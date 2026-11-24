"""Public KRL auto-sync setup script generator (PR 1: User CA KRL pull).

Generates standalone, tokenless scripts that configure TrustedUserCAKeys +
RevokedKeys on a server and schedule a 15-minute pull from /ssh/krl/<refid>
using ETag / If-None-Match. No host enrollment, no tokens, no UCM state.
"""


def _unix_krl_sync_script(ucm_url, ca_refid, ca_public_key):
    krl_url = f"{ucm_url}/ssh/krl/{ca_refid}"
    pub_key = (ca_public_key or "").strip()
    return f'''#!/bin/sh
# UCM SSH User CA KRL Auto-Sync installer — tokenless public pull (15-min interval).
set -eu
umask 077

command -v curl >/dev/null 2>&1 || {{ echo "curl is required"; exit 1; }}
[ "$(id -u)" -eq 0 ] || {{ echo "run as root (sudo)"; exit 1; }}

SSHD_CONFIG="${{SSHD_CONFIG:-/etc/ssh/sshd_config}}"
CA_PUB_FILE="/etc/ssh/ucm_user_ca.pub"
KRL_FILE="/etc/ssh/ucm_user_krl"
STATE_DIR="/etc/ucm"
ETAG_FILE="$STATE_DIR/krl_{ca_refid}.etag"
SYNC_BIN="/usr/local/bin/ucm-krl-sync"
UNIT="ucm-krl-sync"

case "{ucm_url}" in
    http://*) echo "WARN: UCM_URL is plain HTTP; KRL is pulled over cleartext." ;;
esac

mkdir -p "$STATE_DIR" /etc/ssh

directive_value() {{
    if command -v sshd >/dev/null 2>&1 && [ -f "$SSHD_CONFIG" ]; then
        eff=$(sshd -T -f "$SSHD_CONFIG" 2>/dev/null | grep -i "^$1[[:space:]]" | head -n 1 | sed 's/^[^[:space:]]*[[:space:]]*//' || true)
        if [ -n "$eff" ] && [ "$eff" != "none" ]; then
            printf '%s' "$eff"
            return 0
        fi
    fi
    [ -f "$SSHD_CONFIG" ] || return 0
    grep -i "^$1[[:space:]]" "$SSHD_CONFIG" 2>/dev/null | head -n 1 | sed 's/^[^[:space:]]*[[:space:]]*//' || true
}}

directive_target() {{
    current=$(directive_value "$1")
    case "$current" in
        "") printf '%s' "$2" ;;
        *)  printf '%s' "$current" ;;
    esac
}}

SSHD_CONFIG_CHANGED=0
ensure_directive() {{
    current=$(directive_value "$1")
    [ "$current" = "$2" ] && return 0
    if [ -n "$current" ]; then
        echo "WARN: $1 already set to $current — writing UCM content there"
        return 0
    fi
    [ -f "$SSHD_CONFIG" ] && cp -a "$SSHD_CONFIG" "$SSHD_CONFIG.ucmbak.$(date +%s)"
    printf '%s %s\\n' "$1" "$2" >> "$SSHD_CONFIG"
    SSHD_CONFIG_CHANGED=1
}}

atomic_write() {{
    target="$1"
    mode="$2"
    tmp="$target.tmp.$$"
    cat > "$tmp"
    chmod "$mode" "$tmp"
    if mv -f "$tmp" "$target"; then
        return 0
    fi
    rm -f "$tmp"
    return 1
}}

ensure_directive TrustedUserCAKeys "$CA_PUB_FILE"
ensure_directive RevokedKeys "$KRL_FILE"

CA_TARGET=$(directive_target TrustedUserCAKeys "$CA_PUB_FILE")
KRL_TARGET=$(directive_target RevokedKeys "$KRL_FILE")

printf '%s\\n' '{pub_key}' | atomic_write "$CA_TARGET" 644
[ -f "$KRL_TARGET" ] || atomic_write "$KRL_TARGET" 644 < /dev/null

if [ "$SSHD_CONFIG_CHANGED" -eq 1 ] && command -v sshd >/dev/null 2>&1; then
    if ! sshd -t -f "$SSHD_CONFIG" 2>/dev/null; then
        latest_bak=$(ls -1t "$SSHD_CONFIG".ucmbak.* 2>/dev/null | head -n 1 || true)
        [ -n "$latest_bak" ] && cp -a "$latest_bak" "$SSHD_CONFIG"
        echo "ERROR: sshd -t failed; reverted $SSHD_CONFIG"
        exit 1
    fi
fi

cat > "$SYNC_BIN" << 'SYNC_EOF'
#!/bin/sh
set -eu
KRL_URL="{krl_url}"
KRL_TARGET="__KRL_TARGET__"
ETAG_FILE="__ETAG_FILE__"

mkdir -p "$(dirname "$ETAG_FILE")"
etag=""
[ -f "$ETAG_FILE" ] && etag=$(cat "$ETAG_FILE")

tmp="$KRL_TARGET.tmp.$$"
hdr="$ETAG_FILE.hdr.$$"
trap 'rm -f "$tmp" "$hdr"' EXIT

code=$(curl -sSL --fail -o "$tmp" -D "$hdr" \\
    ${{etag:+-H "If-None-Match: \\"$etag\\""}} \\
    -w "%{{http_code}}" "$KRL_URL" || true)

if [ "$code" = "304" ]; then
    exit 0
fi
if [ "$code" = "200" ] && [ -s "$tmp" ]; then
    chmod 644 "$tmp"
    mv -f "$tmp" "$KRL_TARGET"
    new_etag=$(grep -i '^etag:' "$hdr" 2>/dev/null | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '"\\r\\n' || true)
    [ -n "$new_etag" ] && printf '%s' "$new_etag" > "$ETAG_FILE"
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload 2>/dev/null || true
    echo "ucm-krl-sync: updated $KRL_TARGET (etag=$new_etag)"
else
    echo "ucm-krl-sync: WARN fetch returned HTTP $code" >&2
fi
SYNC_EOF

# Substitute runtime paths into the sync runner
sed -i "s|__KRL_TARGET__|$KRL_TARGET|g; s|__ETAG_FILE__|$ETAG_FILE|g" "$SYNC_BIN"
chmod 755 "$SYNC_BIN"

# Initial sync + reload sshd if needed
"$SYNC_BIN" || true
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    cat > "/etc/systemd/system/${{UNIT}}.service" << EOF
[Unit]
Description=UCM SSH User CA KRL Sync
After=network-online.target

[Service]
Type=oneshot
ExecStart=$SYNC_BIN
EOF
    cat > "/etc/systemd/system/${{UNIT}}.timer" << EOF
[Unit]
Description=Pull UCM SSH KRL every 15 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=15min
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now "${{UNIT}}.timer"
    echo "ucm-krl-sync installed: systemd timer every 15 minutes."
elif command -v crontab >/dev/null 2>&1; then
    ( crontab -l 2>/dev/null | grep -vF "*/15 * * * * $SYNC_BIN" || true; echo "*/15 * * * * $SYNC_BIN" ) | crontab -
    echo "ucm-krl-sync installed: crontab entry added (every 15 minutes)."
else
    echo "WARN: No systemd or crontab found."
fi
'''


def _windows_krl_sync_script(ucm_url, ca_refid, ca_public_key):
    krl_url = f"{ucm_url}/ssh/krl/{ca_refid}"
    pub_key = (ca_public_key or "").strip()
    return f'''# UCM SSH User CA KRL Auto-Sync installer (Windows, elevated PowerShell)
$ErrorActionPreference = "Stop"
$ucm = "{ucm_url}"
$krlUrl = "{krl_url}"
$sshDir = "C:\\ProgramData\\ssh"
$cfgFile = "$sshDir\\sshd_config"
$caPubFile = "$sshDir\\ucm_user_ca.pub"
$krlFile = "$sshDir\\ucm_user_krl"
$dir = "C:\\ProgramData\\ucm"
$etagFile = "$dir\\krl_{ca_refid}.etag"
$syncScript = "$dir\\ucm-krl-sync.ps1"

New-Item -ItemType Directory -Force -Path $dir | Out-Null
New-Item -ItemType Directory -Force -Path $sshDir | Out-Null

function Current-Value([string]$name) {{
    if (-not (Test-Path $cfgFile)) {{ return $null }}
    $m = Select-String -Path $cfgFile -Pattern "^\\s*$name\\s+(\\S+)" | Select-Object -First 1
    if ($m) {{ return $m.Matches[0].Groups[1].Value }}
    return $null
}}

function Ensure-Directive([string]$name, [string]$path) {{
    $cur = Current-Value $name
    if ($cur -eq $path) {{ return $cur }}
    if ($cur) {{
        Write-Output "WARN: $name already set to $cur — writing UCM content there"
        return $cur
    }}
    if (Test-Path $cfgFile) {{
        Copy-Item $cfgFile "$cfgFile.ucmbak" -Force
        @(Get-Content $cfgFile) + "$name $path" | Set-Content $cfgFile
    }} else {{
        "$name $path" | Set-Content $cfgFile
    }}
    return $path
}}

$caTarget = Ensure-Directive "TrustedUserCAKeys" $caPubFile
$krlTarget = Ensure-Directive "RevokedKeys" $krlFile

Set-Content $caTarget "{pub_key}"
if (-not (Test-Path $krlTarget)) {{ [IO.File]::WriteAllBytes($krlTarget, [byte[]]::new(0)) }}

if (Test-Path $cfgFile) {{
    try {{
        & sshd.exe -t -f $cfgFile 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {{
            if (Test-Path "$cfgFile.ucmbak") {{ Copy-Item "$cfgFile.ucmbak" $cfgFile -Force }}
            throw "sshd.exe -t validation failed; reverted sshd_config"
        }}
    }} catch {{}}
}}

@"
`$ErrorActionPreference = "Stop"
`$headers = @{{}}
if (Test-Path "$etagFile") {{ `$headers['If-None-Match'] = (Get-Content "$etagFile") -join '' }}
try {{
    `$resp = Invoke-WebRequest -Uri "$krlUrl" -Headers `$headers -UseBasicParsing
}} catch [Microsoft.PowerShell.Commands.HttpResponseException] {{
    if (`$_.Exception.Response.StatusCode.Value__ -eq 304) {{ exit 0 }}
    throw
}}
`$tmp = "$krlTarget.tmp"
[IO.File]::WriteAllBytes(`$tmp, `$resp.RawContentStream.ToArray())
Move-Item -Force `$tmp "$krlTarget"
if (`$resp.Headers.ETag) {{ Set-Content "$etagFile" ((`$resp.Headers.ETag | Select-Object -First 1) -replace '"', '') }}
Restart-Service sshd -ErrorAction SilentlyContinue
"@ | Set-Content $syncScript

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $syncScript

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$syncScript`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "UCM-SSH-KRL-Sync" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Output "ucm-krl-sync installed: scheduled task every 15 minutes."
'''


def build_krl_sync_setup_script(ucm_url, ca_refid, ca_public_key, platform='unix'):
    """Build the tokenless KRL auto-sync setup script for Unix or Windows."""
    ucm_url = (ucm_url or '').rstrip('/')
    if (platform or 'unix').lower() == 'windows':
        return _windows_krl_sync_script(ucm_url, ca_refid, ca_public_key)
    return _unix_krl_sync_script(ucm_url, ca_refid, ca_public_key)
