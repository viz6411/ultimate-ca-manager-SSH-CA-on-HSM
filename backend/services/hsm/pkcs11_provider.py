"""
PKCS#11 HSM Provider
Supports SoftHSM, Thales, nCipher, AWS CloudHSM (via PKCS#11 library)

Based on python-pkcs11 library and PKCS#11 v3.0 standard (OASIS)
"""

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path

from services.hsm.base_provider import (
    BaseHsmProvider, HsmKeyInfo,
    HsmConnectionError, HsmOperationError, HsmKeyNotFoundError, HsmConfigError
)
from utils import key_algorithms
from utils.key_algorithms import label_for_curve_name
from utils.pkcs11_config import normalize_pkcs11_config
from utils.request_helpers import safe_call

logger = logging.getLogger(__name__)

# Which process initialized each Cryptoki library, and the copies a forked child
# inherited: kept referenced, since releasing one would call C_Finalize in the child
_initialized_by: Dict[str, int] = {}
_inherited: List[Any] = []

# A Cryptoki module caches the token's object list for as long as its initialized
# instance lives, so a card changed outside this process keeps answering with the state
# it had when that instance was first opened. reload_lib() is how a long-lived server
# gets the truth; live sessions are counted so reloading never invalidates one.
_lib_lock = threading.Lock()
_open_sessions = 0


def _count_session(delta: int) -> None:
    global _open_sessions
    with _lib_lock:
        _open_sessions += delta

# Try to import pkcs11 - it's optional
PKCS11_AVAILABLE = False
ALGORITHM_TO_PKCS11 = {}
SIGN_MECHANISMS = {}
ML_DSA_PARAMETER_SETS = {}  # label -> CKP_ML_DSA_* (PKCS#11 3.2), empty on python-pkcs11 < 0.9.5
_ML_DSA_KEY_TYPE = None

try:
    import pkcs11
    from pkcs11 import KeyType, Attribute, CertificateType, Mechanism, MechanismFlag, ObjectClass
    from pkcs11.exceptions import FunctionNotSupported
    from pkcs11.util.rsa import encode_rsa_public_key
    from pkcs11.util.ec import encode_ec_public_key, encode_named_curve_parameters
    PKCS11_AVAILABLE = True
    
    # Algorithm mappings (only defined if pkcs11 is available)
    ALGORITHM_TO_PKCS11 = {
        'RSA-2048': (KeyType.RSA, 2048),
        'RSA-3072': (KeyType.RSA, 3072),
        'RSA-4096': (KeyType.RSA, 4096),
        'EC-P256': (KeyType.EC, 'secp256r1'),
        'EC-P384': (KeyType.EC, 'secp384r1'),
        'EC-P521': (KeyType.EC, 'secp521r1'),
        'EC-BP256': (KeyType.EC, 'brainpoolP256r1'),
        'EC-BP384': (KeyType.EC, 'brainpoolP384r1'),
        'EC-BP512': (KeyType.EC, 'brainpoolP512r1'),
        'AES-128': (KeyType.AES, 128),
        'AES-256': (KeyType.AES, 256),
    }
    
    # Signature mechanisms
    SIGN_MECHANISMS = {
        'RSA-2048': Mechanism.SHA256_RSA_PKCS,
        'RSA-3072': Mechanism.SHA384_RSA_PKCS,
        'RSA-4096': Mechanism.SHA512_RSA_PKCS,
        'EC-P256': Mechanism.ECDSA_SHA256,
        'EC-P384': Mechanism.ECDSA_SHA384,
        'EC-P521': Mechanism.ECDSA_SHA512,
        'EC-BP256': Mechanism.ECDSA_SHA256,
        'EC-BP384': Mechanism.ECDSA_SHA384,
        'EC-BP512': Mechanism.ECDSA_SHA512,
    }

    # Digest to apply locally when a token lacks the hashed ECDSA mechanism
    _ECDSA_DIGEST = {
        Mechanism.ECDSA_SHA256: 'sha256',
        Mechanism.ECDSA_SHA384: 'sha384',
        Mechanism.ECDSA_SHA512: 'sha512',
    }

    try:
        from pkcs11.mechanisms import MLDSAParameterSet
        _ML_DSA_KEY_TYPE = KeyType.ML_DSA
        ML_DSA_PARAMETER_SETS = {
            'ML-DSA-44': MLDSAParameterSet.ML_DSA_44,
            'ML-DSA-65': MLDSAParameterSet.ML_DSA_65,
            'ML-DSA-87': MLDSAParameterSet.ML_DSA_87,
        }
    except (ImportError, AttributeError):
        pass
    for _label, _parameter_set in ML_DSA_PARAMETER_SETS.items():
        ALGORITHM_TO_PKCS11[_label] = (_ML_DSA_KEY_TYPE, _parameter_set)
        SIGN_MECHANISMS[_label] = Mechanism.ML_DSA

    # RSASSA-PSS: (mechanism, hash, MGF1 hash, salt = digest length)
    from pkcs11 import MGF
    _PSS_MECHANISMS = {
        'sha256': (Mechanism.SHA256_RSA_PKCS_PSS, Mechanism.SHA256, MGF.SHA256, 32),
        'sha384': (Mechanism.SHA384_RSA_PKCS_PSS, Mechanism.SHA384, MGF.SHA384, 48),
        'sha512': (Mechanism.SHA512_RSA_PKCS_PSS, Mechanism.SHA512, MGF.SHA512, 64),
    }
except ImportError:
    pkcs11 = None


def cryptoki_library(module_path: str, refresh: bool = False):
    """The PKCS#11 library as initialized by this process.

    Cryptoki leaves an initialized library undefined in a forked child, which must
    call C_Initialize itself; one that refuses (no fork detection) keeps its own state.

    refresh: finalize the library this process initialized and initialize it again.
    A module only reads the token's objects when its instance is created, so this is
    the only way a server process sees a token that changed outside it. Skipped while
    any session is open here, because dropping the module would invalidate it -- the
    stale view is then better than breaking a call in flight.
    """
    pid = os.getpid()
    owner = _initialized_by.get(module_path)
    if refresh and owner == pid:
        with _lib_lock:
            # Re-checked under the lock: a session another thread opened in between must not be
            # invalidated by an unload, so the stale view stays for that call.
            if _open_sessions == 0:
                pkcs11.unload(module_path)
                _initialized_by.pop(module_path, None)
                owner = None
    if owner is None or owner == pid:
        lib = pkcs11.lib(module_path)
    else:
        inherited = pkcs11._loaded.pop(module_path, None)
        if inherited is not None:
            _inherited.append(inherited)
        try:
            lib = pkcs11.lib(module_path)
        except pkcs11.PKCS11Error as e:
            if inherited is None:
                raise
            logger.warning("PKCS#11 module %s not initialized again after fork (%s): "
                           "using the state it kept", module_path, e)
            lib = pkcs11._loaded[module_path] = inherited
    _initialized_by[module_path] = pid
    return lib


# What a caller is told when the token refuses to open, named by the PKCS#11 return code:
# the library's own text (module path, vendor detail) stays in the log.
_CONNECT_MESSAGES = {
    'TokenNotPresent': 'No token in the reader',
    'TokenNotRecognised': 'The token in the reader was not recognised',
    'DeviceRemoved': 'The reader or the token was removed',
    'DeviceError': 'The reader reported an error',
    'SlotIDInvalid': 'The configured PKCS#11 slot does not exist',
    'PinIncorrect': 'The token rejected its PIN',
    'PinInvalid': 'The token rejected its PIN',
    'PinLenRange': 'The token PIN has the wrong length',
    'PinLocked': 'The token PIN is locked',
    'UserPinNotInitialized': 'The token has no user PIN set',
    'TokenWriteProtected': 'The token is write protected',
    'SessionCount': 'Another process already holds the token',
    'SessionReadOnlyExists': 'Another process already holds the token',
    'SessionReadWriteSOExists': 'Another process already holds the token',
}


class Pkcs11Provider(BaseHsmProvider):
    """
    PKCS#11 HSM Provider
    
    Config:
        module_path: Path to PKCS#11 library (.so/.dll)
        token_label: Token label to use
        user_pin: User PIN for authentication
        slot_index: Slot index (optional, default: auto-detect)
    """

    ECDSA_SIGNATURE_FORMAT = 'raw'
    SIGNS_PSS = True
    SIGNS_BRAINPOOL = True
    SIGNS_ML_DSA = bool(ML_DSA_PARAMETER_SETS)
    ML_DSA_LIBRARY = 'python-pkcs11 0.9.5'

    # PIV Applet's certificate containers, keyed by the PKCS#15 id OpenSC gives each
    # slot's key (CKA_ID 01..04 == slots 9A/9C/9D/9E).
    PIV_SLOTS = {'01': '9A', '02': '9C', '03': '9D', '04': '9E'}
    
    def __init__(self, config: Dict[str, Any]):
        if not PKCS11_AVAILABLE:
            raise HsmConfigError(
                "python-pkcs11 library not installed. "
                "Install with: pip install python-pkcs11"
            )
        
        config = normalize_pkcs11_config(config)
        if not config.get('user_pin') and config.get('hsm_user') and config.get('hsm_password'):
            # AWS CloudHSM logs a crypto user in with the PIN "<user>:<password>".
            config['user_pin'] = f"{config['hsm_user']}:{config['hsm_password']}"
        super().__init__(config)

        # Validate config
        self.module_path = config.get('module_path')
        self.token_label = config.get('token_label')
        self.user_pin = config.get('user_pin')
        self.slot_index = config.get('slot_index')
        
        if not self.module_path:
            raise HsmConfigError("module_path is required")
        if not self.token_label:
            raise HsmConfigError("token_label is required")
        if not self.user_pin:
            raise HsmConfigError("user_pin is required")
        
        # Check module exists
        if not Path(self.module_path).exists():
            # The path is the operator's own configuration: it goes to the log, not into a response
            logger.warning("PKCS#11 module not found: %s", self.module_path)
            raise HsmConfigError("PKCS#11 module not found")
        
        self._lib = None
        self._token = None
        self._session = None
        self.list_errors: List[str] = []
        # Set by HsmService when the caller must decide from the token's current objects.
        self.fresh_view = False
    
    def connect(self) -> bool:
        """Connect to HSM and open session"""
        try:
            # Load PKCS#11 library
            self._lib = cryptoki_library(self.module_path, refresh=self.fresh_view)
            
            # Find token
            if self.slot_index is not None:
                slots = self._lib.get_slots()
                if self.slot_index >= len(slots):
                    raise HsmConnectionError(f"Slot {self.slot_index} not found")
                self._token = slots[self.slot_index].get_token()
            else:
                self._token = self._lib.get_token(token_label=self.token_label)
            
            # Open session
            self._session = self._token.open(rw=True, user_pin=self.user_pin)
            _count_session(1)
            self._connected = True
            
            logger.info(f"Connected to PKCS#11 token: {self.token_label}")
            return True
            
        except HsmConnectionError:
            raise  # our own wording ("Slot 5 not found") is already what the operator needs
        except pkcs11.PKCS11Error as e:
            # The library's text carries the module path and vendor detail: it belongs in the log,
            # not in a response body. The caller gets the reason the return code names.
            self._connected = False
            logger.warning("PKCS#11 connection to %s failed: %s", self.module_path, e)
            raise HsmConnectionError(
                _CONNECT_MESSAGES.get(type(e).__name__, 'PKCS#11 connection failed')) from e
        except Exception as e:  # noqa: BLE001 - same rule for anything else the module raises
            self._connected = False
            logger.warning("PKCS#11 connection to %s failed: %s", self.module_path, e)
            raise HsmConnectionError('PKCS#11 connection failed') from e
    
    def disconnect(self) -> None:
        """Close session"""
        if self._session:
            safe_call(self._session.close)
            _count_session(-1)
        self._session = None
        self._token = None
        self._lib = None
        self._connected = False
        logger.debug(f"Disconnected from PKCS#11 token: {self.token_label}")
    
    def test_connection(self) -> Dict[str, Any]:
        """Test connection and return token info"""
        try:
            self.connect()
            
            # Get token info
            info = {
                'success': True,
                'message': 'Connection successful',
                'details': {
                    'token_label': str(self._token.label).strip(),
                    'manufacturer': str(self._token.manufacturer_id).strip(),
                    'model': str(self._token.model).strip(),
                    'serial': self._token.serial.hex() if isinstance(self._token.serial, bytes) else str(self._token.serial),
                },
                'module': self._module_info(),
            }
            return info
            
        except HsmConnectionError as e:
            return {
                'success': False,
                'message': str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'message': f"Test failed: {str(e)}"
            }
        finally:
            self.disconnect()
    
    def _module_info(self) -> Dict[str, str]:
        """What the PKCS#11 library and the token's slot say they are."""
        def version(value):
            return '.'.join(str(part) for part in value) if isinstance(value, (tuple, list)) else str(value)
        # Informative only: a module that cannot describe itself does not fail the test
        try:
            lib, slot = self._lib, self._token.slot
            return {
                'library': str(lib.library_description).strip(),
                'manufacturer': str(lib.manufacturer_id).strip(),
                'library_version': version(lib.library_version),
                'cryptoki_version': version(lib.cryptoki_version),
                'slot': str(slot.slot_description).strip(),
                'hardware_version': version(slot.hardware_version),
                'firmware_version': version(slot.firmware_version),
            }
        except Exception as e:
            logger.warning("PKCS#11 module did not describe itself: %s", e)
            return {}

    def list_keys(self) -> List[HsmKeyInfo]:
        """List all keys in the token; keys that could not be read land in ``list_errors``."""
        if not self._session:
            raise HsmOperationError("Not connected")

        keys = []
        self.list_errors = []

        try:
            # Finish C_FindObjects before looking up public halves in the same session.
            for obj in list(self._session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY
            })):
                key_info = self._object_to_key_info(obj, 'asymmetric')
                if key_info:
                    keys.append(key_info)

            # Find all secret keys
            for obj in list(self._session.get_objects({
                Attribute.CLASS: ObjectClass.SECRET_KEY
            })):
                key_info = self._object_to_key_info(obj, 'symmetric')
                if key_info:
                    keys.append(key_info)

            return keys

        except pkcs11.PKCS11Error as e:
            raise HsmOperationError(f"Failed to list keys: {str(e)}")

    @staticmethod
    def _attr(obj, attribute, default=None):
        """Attribute value, or *default* when the token does not expose it."""
        try:
            return obj[attribute]
        except pkcs11.PKCS11Error:
            return default

    def _ec_algorithm(self, obj, key_id: Optional[bytes]) -> str:
        """Label of the key's curve, read from EC_PARAMS on the key or its public half."""
        params = self._attr(obj, Attribute.EC_PARAMS)
        if not params and key_id:
            for pub in self._session.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.ID: key_id
            }):
                params = self._attr(pub, Attribute.EC_PARAMS)
                break
        if not params:
            return 'UNKNOWN'
        try:
            from asn1crypto.keys import ECDomainParameters
            domain = ECDomainParameters.load(bytes(params))
            if domain.name != 'named':
                return 'UNKNOWN'
            return label_for_curve_name(domain.chosen.native) or 'UNKNOWN'
        except Exception:
            return 'UNKNOWN'

    def _public_half(self, key_id: Optional[bytes]):
        if not key_id:
            return None
        for pub in self._session.get_objects({
            Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.ID: key_id
        }):
            return pub
        return None

    def _mldsa_algorithm(self, obj, key_id: Optional[bytes]) -> str:
        """Label of the key's CKA_PARAMETER_SET, read on the key or its public half;
        a missing or unknown set raises, so the key lands in list_errors."""
        by_value = {int(v): label for label, v in ML_DSA_PARAMETER_SETS.items()}
        value = self._attr(obj, Attribute.PARAMETER_SET)
        if value is None:
            pub = self._public_half(key_id)
            value = self._attr(pub, Attribute.PARAMETER_SET) if pub is not None else None
        label = by_value.get(int(value)) if value is not None else None
        if label is None:
            raise ValueError(f'ML-DSA key with unknown parameter set {value!r}')
        return label

    def _object_to_key_info(self, obj, key_type: str) -> Optional[HsmKeyInfo]:
        """Convert PKCS#11 object to HsmKeyInfo"""
        try:
            raw_id = self._attr(obj, Attribute.ID)
            label = self._attr(obj, Attribute.LABEL) or ''
            key_id = raw_id.hex() if raw_id else label
            if not key_id:
                raise ValueError('key has neither ID nor LABEL')

            pkcs11_key_type = self._attr(obj, Attribute.KEY_TYPE)

            if pkcs11_key_type == KeyType.RSA:
                # Private keys carry MODULUS; MODULUS_BITS is a public-key attribute.
                modulus = self._attr(obj, Attribute.MODULUS)
                bits = int.from_bytes(modulus, 'big').bit_length() if modulus else \
                    self._attr(obj, Attribute.MODULUS_BITS)
                algorithm = f'RSA-{bits}' if bits else 'UNKNOWN'
            elif pkcs11_key_type == KeyType.EC:
                algorithm = self._ec_algorithm(obj, raw_id)
            elif _ML_DSA_KEY_TYPE is not None and pkcs11_key_type == _ML_DSA_KEY_TYPE:
                algorithm = self._mldsa_algorithm(obj, raw_id)
            elif pkcs11_key_type == KeyType.AES:
                value_len = self._attr(obj, Attribute.VALUE_LEN)
                algorithm = f'AES-{value_len * 8}' if value_len else 'UNKNOWN'
            else:
                algorithm = 'UNKNOWN'

            # Determine purpose (private keys expose DECRYPT/UNWRAP, secret keys ENCRYPT/WRAP)
            can_sign = bool(self._attr(obj, Attribute.SIGN, False))
            can_encrypt = any(self._attr(obj, a, False) for a in (
                Attribute.ENCRYPT, Attribute.DECRYPT, Attribute.WRAP, Attribute.UNWRAP))

            if can_sign and can_encrypt:
                purpose = 'all'
            elif can_sign:
                purpose = 'signing'
            elif can_encrypt:
                purpose = 'encryption'
            else:
                purpose = 'all'

            is_extractable = bool(self._attr(obj, Attribute.EXTRACTABLE, False))
            public_key_pem = None
            if key_type == 'asymmetric':
                try:
                    pub = self._public_half(raw_id)
                    if pub is not None:
                        if pkcs11_key_type == KeyType.RSA:
                            public_key_pem = self._export_rsa_public_key(pub)
                        elif pkcs11_key_type == KeyType.EC:
                            public_key_pem = self._export_ec_public_key(pub)
                        elif _ML_DSA_KEY_TYPE is not None and pkcs11_key_type == _ML_DSA_KEY_TYPE:
                            public_key_pem = self._export_mldsa_public_key(pub)
                    if public_key_pem:
                        from cryptography.hazmat.primitives.serialization import load_pem_public_key
                        public = load_pem_public_key(public_key_pem.encode())
                        algorithm = key_algorithms.label_for_public_key(public) or algorithm
                except Exception as e:
                    # Only a parsed SPKI is ever reported; the private key stays listed.
                    public_key_pem = None
                    logger.warning("Public half of PKCS#11 key %s could not be read: %s", key_id, e)

            return HsmKeyInfo(
                key_identifier=key_id,
                label=label or key_id,
                algorithm=algorithm,
                key_type=key_type,
                purpose=purpose,
                public_key_pem=public_key_pem,
                is_extractable=is_extractable
            )

        except Exception as e:
            logger.warning(f"Failed to parse key object: {e}")
            self.list_errors.append(str(e) or type(e).__name__)
            return None
    def generate_key(
        self,
        label: str,
        algorithm: str,
        purpose: str = 'signing',
        extractable: bool = False
    ) -> HsmKeyInfo:
        """Generate a new key in the HSM"""
        self.refuse_unsupported_algorithm(algorithm)
        if not self._session:
            raise HsmOperationError("Not connected")
        
        if algorithm not in ALGORITHM_TO_PKCS11:
            raise HsmOperationError(f"Unsupported algorithm: {algorithm}")
        
        key_type_enum, param = ALGORITHM_TO_PKCS11[algorithm]
        
        try:
            # Generate unique ID
            import secrets
            key_id = secrets.token_bytes(16)
            
            if key_type_enum == KeyType.RSA:
                # Build MechanismFlag capabilities
                caps = MechanismFlag(0)
                if purpose in ('signing', 'all'):
                    caps |= MechanismFlag.SIGN | MechanismFlag.VERIFY
                if purpose in ('encryption', 'all'):
                    caps |= MechanismFlag.ENCRYPT | MechanismFlag.DECRYPT

                pub, priv = self._session.generate_keypair(
                    KeyType.RSA,
                    param,
                    store=True,
                    label=label,
                    id=key_id,
                    capabilities=caps,
                    private_template={Attribute.EXTRACTABLE: extractable}
                )
                
                public_key_pem = self._export_rsa_public_key(pub)
                
            elif key_type_enum == KeyType.EC:
                # asn1crypto names the Brainpool curves in lower case
                ecparams = self._session.create_domain_parameters(
                    KeyType.EC,
                    {Attribute.EC_PARAMS: encode_named_curve_parameters(param.lower())},
                    local=True
                )
                
                caps = MechanismFlag(0)
                if purpose in ('signing', 'all'):
                    caps |= MechanismFlag.SIGN | MechanismFlag.VERIFY

                pub, priv = ecparams.generate_keypair(
                    store=True,
                    label=label,
                    id=key_id,
                    capabilities=caps,
                    private_template={Attribute.EXTRACTABLE: extractable}
                )
                
                public_key_pem = self._export_ec_public_key(pub)

            elif _ML_DSA_KEY_TYPE is not None and key_type_enum == _ML_DSA_KEY_TYPE:
                pub, priv = self._session.generate_keypair(
                    _ML_DSA_KEY_TYPE,
                    store=True,
                    label=label,
                    id=key_id,
                    capabilities=MechanismFlag.SIGN | MechanismFlag.VERIFY,
                    mechanism=Mechanism.ML_DSA_KEY_PAIR_GEN,
                    public_template={Attribute.PARAMETER_SET: param},
                    private_template={Attribute.EXTRACTABLE: extractable}
                )
                public_key_pem = self._export_mldsa_public_key(pub, algorithm)

            elif key_type_enum == KeyType.AES:
                caps = MechanismFlag.ENCRYPT | MechanismFlag.DECRYPT
                if purpose in ('wrapping', 'all'):
                    caps |= MechanismFlag.WRAP | MechanismFlag.UNWRAP

                key = self._session.generate_key(
                    KeyType.AES,
                    param,
                    store=True,
                    label=label,
                    id=key_id,
                    capabilities=caps,
                    template={Attribute.EXTRACTABLE: extractable}
                )
                public_key_pem = None
                
            else:
                raise HsmOperationError(f"Unsupported key type: {key_type_enum}")
            
            key_type = 'symmetric' if key_type_enum == KeyType.AES else 'asymmetric'
            
            logger.info(f"Generated key '{label}' ({algorithm}) in HSM")
            
            return HsmKeyInfo(
                key_identifier=key_id.hex(),
                label=label,
                algorithm=algorithm,
                key_type=key_type,
                purpose=purpose,
                public_key_pem=public_key_pem,
                is_extractable=extractable
            )
            
        except pkcs11.PKCS11Error as e:
            raise HsmOperationError(f"PKCS#11 error: {type(e).__name__}: {str(e) or 'see logs'}")
    
    def _export_rsa_public_key(self, pub_key) -> str:
        """Export RSA public key as PEM"""
        try:
            # python-pkcs11 encodes PKCS#1; "PUBLIC KEY" PEM must hold a SubjectPublicKeyInfo
            from cryptography.hazmat.primitives import serialization
            spki = serialization.load_der_public_key(encode_rsa_public_key(pub_key)).public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            return self._der_to_pem(spki, 'PUBLIC KEY')
        except Exception as e:
            logger.warning(f"Failed to export RSA public key: {e}")
            return None
    
    def _export_ec_public_key(self, pub_key) -> str:
        """Export EC public key as PEM"""
        try:
            der = encode_ec_public_key(pub_key)
            return self._der_to_pem(der, 'PUBLIC KEY')
        except Exception as e:
            logger.warning(f"Failed to export EC public key: {e}")
            return None
    
    def _export_mldsa_public_key(self, pub_key, algorithm: Optional[str] = None) -> str:
        """RFC 9881 SubjectPublicKeyInfo PEM from CKA_VALUE, the raw FIPS 204 public key."""
        try:
            label = self._mldsa_algorithm(pub_key, None)
        except ValueError as e:
            # A freshly generated pair holds the set it was asked for, read back or not
            if not algorithm:
                raise HsmOperationError(str(e)) from e
            label = algorithm
        registered = key_algorithms.get(label) if label else None
        if registered is None or registered.family != 'ML-DSA':
            raise HsmOperationError(f"ML-DSA public key of unknown or unavailable parameter set ({label})")
        from cryptography.hazmat.primitives import serialization
        public_key = registered.public_class.from_public_bytes(bytes(pub_key[Attribute.VALUE]))
        return public_key.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def _der_to_pem(self, der_bytes: bytes, label: str) -> str:
        """Convert DER to PEM format"""
        import base64
        b64 = base64.b64encode(der_bytes).decode('ascii')
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        return f"-----BEGIN {label}-----\n" + '\n'.join(lines) + f"\n-----END {label}-----\n"
    
    def delete_key(self, key_identifier: str) -> bool:
        """Delete a key from the HSM"""
        if not self._session:
            raise HsmOperationError("Not connected")
        
        try:
            key_id = bytes.fromhex(key_identifier)
            
            # Find and delete private key
            for obj in self._session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.ID: key_id
            }):
                obj.destroy()
            
            # Find and delete public key
            for obj in self._session.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.ID: key_id
            }):
                obj.destroy()
            
            # Find and delete secret key
            for obj in self._session.get_objects({
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.ID: key_id
            }):
                obj.destroy()
            
            logger.info(f"Deleted key {key_identifier} from HSM")
            return True
            
        except pkcs11.PKCS11Error as e:
            raise HsmOperationError(f"Failed to delete key: {str(e)}")
    
    def get_public_key(self, key_identifier: str) -> str:
        """Get public key in PEM format"""
        if not self._session:
            raise HsmOperationError("Not connected")
        
        try:
            key_id = bytes.fromhex(key_identifier)
            
            # Find public key
            for pub_key in self._session.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.ID: key_id
            }):
                key_type = pub_key[Attribute.KEY_TYPE]
                
                if key_type == KeyType.RSA:
                    return self._export_rsa_public_key(pub_key)
                elif key_type == KeyType.EC:
                    return self._export_ec_public_key(pub_key)
                elif _ML_DSA_KEY_TYPE is not None and key_type == _ML_DSA_KEY_TYPE:
                    return self._export_mldsa_public_key(pub_key)
                else:
                    raise HsmOperationError(f"Unsupported key type: {key_type}")
            
            raise HsmKeyNotFoundError(f"Public key not found: {key_identifier}")
            
        except pkcs11.PKCS11Error as e:
            raise HsmOperationError(f"Failed to get public key: {str(e)}")

    def get_certificate(self, key_identifier: str) -> Optional[bytes]:
        """DER of the certificate object carrying this key id, or None."""
        if not self._session:
            raise HsmOperationError("Not connected")

        try:
            key_id = bytes.fromhex(key_identifier)
            for obj in self._session.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.ID: key_id
            }):
                value = self._attr(obj, Attribute.VALUE)
                if value:
                    return bytes(value)
            return None

        except pkcs11.PKCS11Error as e:
            raise HsmOperationError(f"Failed to read certificate: {str(e)}")

    def store_certificate(self, key_identifier: str, cert_der: bytes,
                          label: Optional[str] = None) -> None:
        """Store the certificate at the key's id (PKCS#15 maps it to the same PIV slot)."""
        if not self._session:
            raise HsmOperationError("Not connected")

        try:
            attrs = {
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                # CKA_CERTIFICATE_TYPE is required by SoftHSM and harmless elsewhere
                Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
                Attribute.ID: bytes.fromhex(key_identifier),
                Attribute.VALUE: cert_der,
                Attribute.TOKEN: True,
            }
            # CKA_SUBJECT is a required certificate attribute (PKCS#11 spec):
            # SoftHSM refuses the object without it, so it is read out of the DER.
            from asn1crypto.x509 import Certificate as AsnCertificate
            attrs[Attribute.SUBJECT] = AsnCertificate.load(cert_der).subject.dump()
            if label:
                attrs[Attribute.LABEL] = label
            self._session.create_object(attrs)
            logger.info(f"Stored certificate at key id {key_identifier}")

        except FunctionNotSupported:
            self._store_certificate_with_piv_tool(key_identifier, cert_der)
        except pkcs11.PKCS11Error as e:
            raise HsmOperationError(f"Failed to store certificate: {str(e) or type(e).__name__}")

    def _store_certificate_with_piv_tool(self, key_identifier: str, cert_der: bytes) -> None:
        """Write the certificate into the PIV slot that holds this key, with piv-tool.

        OpenSC emulates PKCS#15 on PIV cards and ships no pkcs15init profile for them,
        so creating a token object over PKCS#11 cannot reach the card; the PIV container
        itself is writable. piv-tool exits non-zero even when it did write the object,
        so the write is judged by reading the certificate back after re-initializing the
        module. piv-tool cannot name the object, so the label is not carried over.
        """
        slot = self.PIV_SLOTS.get(key_identifier)
        tool = shutil.which('piv-tool')
        if not slot or not tool:
            raise HsmOperationError(
                "This token cannot store certificates over PKCS#11 and key id "
                f"{key_identifier} has no writable PIV slot")

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        pem = x509.load_der_x509_certificate(cert_der).public_bytes(serialization.Encoding.PEM)
        fd, path = tempfile.mkstemp(prefix='ucm-token-cert-', suffix='.pem')
        try:
            with os.fdopen(fd, 'wb') as handle:
                os.chmod(path, 0o600)
                handle.write(pem)
            run = subprocess.run([tool, '-C', slot, '-i', path], capture_output=True,
                                 text=True, timeout=120)
            logger.info("piv-tool wrote slot %s: rc=%s %s", slot, run.returncode,
                        (run.stderr or run.stdout).strip()[-200:])
        except subprocess.TimeoutExpired:
            raise HsmOperationError("Timed out writing the certificate to the token")
        finally:
            Path(path).unlink(missing_ok=True)

        # The session this provider already holds carries the token's earlier object
        # list, so verify through a session opened on a re-initialized module.
        self.disconnect()
        self.fresh_view = True
        try:
            self.connect()
            stored = self.get_certificate(key_identifier)
        finally:
            self.fresh_view = False
        if stored != cert_der:
            raise HsmOperationError(
                f"piv-tool wrote slot {slot} but the token reads back "
                + ('a different certificate' if stored else 'no certificate'))
        logger.info("Stored certificate in PIV slot %s (key id %s)", slot, key_identifier)

    def delete_certificate(self, key_identifier: str) -> int:
        """Remove certificate objects at this key id; returns how many were removed."""
        if not self._session:
            raise HsmOperationError("Not connected")

        try:
            key_id = bytes.fromhex(key_identifier)
            removed = 0
            for obj in self._session.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.ID: key_id
            }):
                obj.destroy()
                removed += 1
            return removed

        except FunctionNotSupported:
            # PIV containers cannot be emptied over PKCS#11; the overwrite path writes
            # the replacement certificate over the existing one instead.
            logger.info("Token cannot remove objects over PKCS#11: leaving the certificate in place")
            return 0
        except pkcs11.PKCS11Error as e:
            raise HsmOperationError(f"Failed to delete certificate: {str(e) or type(e).__name__}")

    def sign(
        self,
        key_identifier: str,
        data: bytes,
        algorithm: Optional[str] = None,
        hash_algorithm: Optional[str] = None,
        padding: Optional[str] = None
    ) -> bytes:
        """Sign data using HSM key"""
        if not self._session:
            raise HsmOperationError("Not connected")
        
        try:
            key_id = bytes.fromhex(key_identifier)
            
            # Find private key
            priv_key = None
            for obj in self._session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.ID: key_id
            }):
                priv_key = obj
                break
            
            if not priv_key:
                raise HsmKeyNotFoundError(f"Private key not found: {key_identifier}")
            
            # Determine mechanism: the digest the caller declares in the
            # signature first, the key-size default otherwise
            key_type = priv_key[Attribute.KEY_TYPE]
            by_digest = {
                KeyType.RSA: {'sha256': Mechanism.SHA256_RSA_PKCS, 'sha384': Mechanism.SHA384_RSA_PKCS,
                              'sha512': Mechanism.SHA512_RSA_PKCS},
                KeyType.EC: {'sha256': Mechanism.ECDSA_SHA256, 'sha384': Mechanism.ECDSA_SHA384,
                             'sha512': Mechanism.ECDSA_SHA512},
            }
            mechanism_param = None
            if _ML_DSA_KEY_TYPE is not None and key_type == _ML_DSA_KEY_TYPE:
                # Pure ML-DSA, empty context: the token hashes nothing on our behalf
                if hash_algorithm or padding:
                    raise HsmOperationError("ML-DSA signs the data itself: no digest or padding applies")
                mechanism = Mechanism.ML_DSA
            elif padding == 'pss':
                if key_type != KeyType.RSA or hash_algorithm not in _PSS_MECHANISMS:
                    raise HsmOperationError(f"RSA-PSS needs an RSA key and SHA-2, not {hash_algorithm}")
                mechanism, hash_mech, mgf, salt = _PSS_MECHANISMS[hash_algorithm]
                mechanism_param = (hash_mech, mgf, salt)
            elif hash_algorithm and key_type in by_digest and hash_algorithm in by_digest[key_type]:
                mechanism = by_digest[key_type][hash_algorithm]
            elif algorithm:
                mechanism = SIGN_MECHANISMS.get(algorithm)
            else:
                # Default mechanism based on key type
                if key_type == KeyType.RSA:
                    mechanism = Mechanism.SHA256_RSA_PKCS
                elif key_type == KeyType.EC:
                    mechanism = Mechanism.ECDSA_SHA256
                else:
                    raise HsmOperationError(f"Unsupported key type for signing: {key_type}")
            
            # Sign
            try:
                signature = priv_key.sign(data, mechanism=mechanism, mechanism_param=mechanism_param)
            except pkcs11.exceptions.MechanismInvalid:
                # SoftHSM and some tokens offer only raw ECDSA: hash here and
                # sign the digest, which is the same signature.
                digest_name = _ECDSA_DIGEST.get(mechanism)
                if digest_name is None:
                    raise
                signature = priv_key.sign(getattr(hashlib, digest_name)(data).digest(),
                                          mechanism=Mechanism.ECDSA)

            logger.debug(f"Signed {len(data)} bytes with key {key_identifier}")
            return signature
            
        except pkcs11.PKCS11Error as e:
            raise HsmOperationError(f"Signing failed: {str(e)}")


class AwsCloudHsmProvider(Pkcs11Provider):
    """AWS CloudHSM through its PKCS#11 library, which has no Brainpool curve and no ML-DSA."""

    SIGNS_BRAINPOOL = False
    SIGNS_ML_DSA = False
    ML_DSA_LIBRARY = None


# Export availability flag
def is_available() -> bool:
    """Check if PKCS#11 provider is available"""
    return PKCS11_AVAILABLE
