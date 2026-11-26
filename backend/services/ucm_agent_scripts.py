"""
ucm-ssh-agent script builders (SPEC_SSH_HOSTS_AND_KRL_AUTOMATION).

Pull-only per issue #451: UCM never reaches out to servers. A POSIX sh agent
installed at /usr/local/bin/ucm-ssh-agent is driven by a systemd.timer every
15 minutes (PowerShell runner + scheduled task on Windows OpenSSH). The agent
calls UCM over HTTPS: public KRL download with ETag (no secret), check-in and
renewal with its host token, enrollment once with a one-time bootstrap token.

The runner owns the sshd_config directives: HostCertificate, TrustedUserCAKeys
and RevokedKeys are ensured; an existing directive pointing at another path is
kept as the write target (OpenSSH honours only the first value, so appending a
second line would do nothing), with a warning and a backup of the replaced
file. After any config change the runner validates with `sshd -t` and only
then reloads sshd, restoring the backup on failure.
"""

RUNNER_PATH = '/usr/local/bin/ucm-ssh-agent'
CONF_PATH = '/etc/ucm/agent.conf'


def _unix_runner_script():
    return r'''#!/bin/sh
# ucm-ssh-agent — pull-only: KRL of the user CA + host certificate.
# Modes: enroll | run. The timer calls `run` every 15 minutes.
set -eu
# The timer/cron/sched environment is not the login shell's: cron ships
# PATH=/usr/bin:/bin on Debian/Ubuntu, where /usr/sbin and /sbin are absent —
# and then `sshd`, `systemctl` and `service` are simply not found, so the config
# is never validated and sshd is never reloaded. Canonical system PATH first.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export PATH
# The conf holds the long-lived host token and it is rewritten through a
# scratch file: 077 keeps that file (and /etc/ucm) unreadable between write
# and chmod. Files sshd must read get an explicit mode from atomic_file.
umask 077

CONF="${UCM_AGENT_CONF:-/etc/ucm/agent.conf}"
STATE_DIR="${UCM_AGENT_STATE:-/etc/ucm}"
ETAG_FILE="$STATE_DIR/krl.etag"
KRL_FILE="${KRL_FILE:-/etc/ssh/ucm_user_krl}"
USER_CA_PUB_FILE="${USER_CA_PUB_FILE:-/etc/ssh/ucm_user_ca.pub}"
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"

log()  { printf '[ucm-ssh-agent] %s\n' "$1"; }
die()  { printf '[ucm-ssh-agent] ERROR: %s\n' "$1" >&2; exit 1; }
# A refusal body goes into one log line: a 5xx from a proxy is a multi-line HTML page,
# and dumping it raw floods the cron/syslog stream with lines that carry no prefix.
brief() { printf '%s' "$1" | tr '\n\t' '  ' | cut -c1-160; }

[ -f "$CONF" ] || die "config not found: $CONF"
. "$CONF"
[ -n "${UCM_URL:-}" ] || die "UCM_URL missing in $CONF"

SSHD_CONFIG_CHANGED=0
CONTENT_CHANGED=0

# --fail-with-body (curl >= 7.76) fails on a 4xx/5xx *and* keeps the answer body,
# which is the only way the operator learns WHY enroll/renew/check-in was refused
# (for example "This SSH CA lists no allowed principals"). Older curl falls back
# to plain --fail and the agent reports the refusal without its reason.
CURL_FAIL='--fail'
if curl --help all 2>/dev/null | grep -q -- '--fail-with-body'; then CURL_FAIL='--fail-with-body'; fi
curl_get() { curl -sS $CURL_FAIL --connect-timeout 10 --max-time 60 "$@"; }
json_str() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n 1; }
json_yes() { grep -c "\"$1\"[[:space:]]*:[[:space:]]*true" || true; }

reload_sshd() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    elif command -v service >/dev/null 2>&1; then
        service ssh reload >/dev/null 2>&1 || service sshd reload >/dev/null 2>&1 || true
    fi
}

# Validate the config sshd will actually load. Plain -t reads the default
# path; a custom SSHD_CONFIG is injected as an include override.
validate_sshd() {
    command -v sshd >/dev/null 2>&1 || return 0
    if [ "$SSHD_CONFIG" = "/etc/ssh/sshd_config" ]; then
        sshd -t
    else
        sshd -t -C "include $SSHD_CONFIG"
    fi
}

atomic_file() { # path mode ; content on stdin
    tmp="$1.tmp.$$"
    if cat > "$tmp" && chmod "$2" "$tmp" && mv -f "$tmp" "$1"; then
        return 0
    fi
    # A failed mv used to leave $target.tmp.<pid> in the directory sshd reads
    # (and the next call would not clean it: the pid differs every tick).
    rm -f "$tmp"
    return 1
}

directive_value() { # directive ; prints the value sshd would honour (first line wins)
    # Check effective configuration via sshd -T first to respect Include directives
    if command -v sshd >/dev/null 2>&1 && [ -f "$SSHD_CONFIG" ]; then
        eff=$(sshd -T -f "$SSHD_CONFIG" 2>/dev/null | grep -i "^$1[[:space:]]" | head -n 1 | sed 's/^[^[:space:]]*[[:space:]]*//' || true)
        if [ -n "$eff" ] && [ "$eff" != "none" ]; then
            printf '%s' "$eff"
            return 0
        fi
    fi
    [ -f "$SSHD_CONFIG" ] || return 0
    # [[:space:]] and not a literal space: sshd accepts "RevokedKeys\t/path",
    # and missing that form means appending a second line the host ignores.
    grep -i "^$1[[:space:]]" "$SSHD_CONFIG" 2>/dev/null | head -n 1 | sed 's/^[^[:space:]]*[[:space:]]*//' || true
}

# directive_target <Directive> <desired-path> ; where the agent must write.
# Never edits the config: when the host already runs the directive with a
# foreign path (a pre-UCM setup), that path becomes the write target —
# OpenSSH honours only the FIRST value, a second line would win nothing.
directive_target() {
    current=$(directive_value "$1")
    case "$current" in
        "") printf '%s' "$2" ;;
        *)  printf '%s' "$current" ;;
    esac
}

# ensure_directive <Directive> <path> ; append the line when missing (enroll
# mode only — the timer run mode never edits sshd_config).
ensure_directive() {
    current=$(directive_value "$1")
    [ "$current" = "$2" ] && return 0
    if [ -n "$current" ]; then
        log "WARN: $1 already set to $current — writing UCM content there"
        return 0
    fi
    [ -f "$SSHD_CONFIG" ] && cp -a "$SSHD_CONFIG" "$SSHD_CONFIG.ucmbak.$(date +%s)"
    printf '%s %s\n' "$1" "$2" >> "$SSHD_CONFIG"
    SSHD_CONFIG_CHANGED=1
}

remove_directive() {
    [ -f "$SSHD_CONFIG" ] || return 0
    if grep -qi "^$1[[:space:]]" "$SSHD_CONFIG" 2>/dev/null; then
        cp -a "$SSHD_CONFIG" "$SSHD_CONFIG.ucmbak.$(date +%s)"
        tmp_cfg="$SSHD_CONFIG.tmp.$$"
        grep -iv "^$1[[:space:]]" "$SSHD_CONFIG" > "$tmp_cfg" || true
        mv -f "$tmp_cfg" "$SSHD_CONFIG"
        SSHD_CONFIG_CHANGED=1
    fi
}

# sshd reads <hostkey>-cert.pub: the PRIVATE key path with .pub stripped
# (ssh_host_ed25519_key.pub -> ssh_host_ed25519_key-cert.pub). CERT_FILE
# overrides; SSH_HOST_KEY_DIR relocates the scan (tests).
host_pubkey_file() {
    dir="${SSH_HOST_KEY_DIR:-/etc/ssh}"

    # 1. Check HostKey directives in sshd_config
    if [ -f "$SSHD_CONFIG" ]; then
        for hk in $(grep -i '^[[:space:]]*HostKey[[:space:]]' "$SSHD_CONFIG" 2>/dev/null | sed 's/^[[:space:]]*[^[:space:]]*[[:space:]]*//' | tr -d '"'); do
            case "$hk" in
                *.pub) pub="$hk" ;;
                *)     pub="$hk.pub" ;;
            esac
            if [ -f "$pub" ]; then
                printf '%s' "$pub"
                return 0
            fi
            priv="${pub%.pub}"
            if [ -f "$priv" ] && command -v ssh-keygen >/dev/null 2>&1; then
                if ssh-keygen -y -f "$priv" > "$pub" 2>/dev/null && chmod 644 "$pub"; then
                    printf '%s' "$pub"
                    return 0
                fi
            fi
        done
    fi

    # 2. Priority fallback search: ed25519 -> ecdsa -> rsa
    for kt in ed25519 ecdsa rsa; do
        f="$dir/ssh_host_${kt}_key.pub"
        [ -f "$f" ] && { printf '%s' "$f"; return 0; }
        priv="$dir/ssh_host_${kt}_key"
        if [ -f "$priv" ] && command -v ssh-keygen >/dev/null 2>&1; then
            if ssh-keygen -y -f "$priv" > "$f" 2>/dev/null && chmod 644 "$f"; then
                printf '%s' "$f"
                return 0
            fi
        fi
    done

    # 3. If no keys exist on the host at all: generate ed25519 key
    if command -v ssh-keygen >/dev/null 2>&1; then
        mkdir -p "$dir"
        new_priv="$dir/ssh_host_ed25519_key"
        new_pub="$dir/ssh_host_ed25519_key.pub"
        if ssh-keygen -t ed25519 -f "$new_priv" -N "" -C "" >/dev/null 2>&1; then
            chmod 600 "$new_priv"
            chmod 644 "$new_pub"
            log "generated new host key: $new_pub" >&2
            printf '%s' "$new_pub"
            return 0
        fi
    fi

    return 1
}

cert_target_default() {
    if [ -n "${CERT_FILE:-}" ]; then printf '%s' "$CERT_FILE"; return 0; fi
    f=$(host_pubkey_file) || return 1
    printf '%s' "${f%.pub}-cert.pub"
}

backup_file() { [ -f "$1" ] && cp -a "$1" "$1.ucmbak.$(date +%s)" 2>/dev/null || true; }

write_content() { # target desired content — back up a foreign file first
    if [ "$1" != "$2" ] && [ -f "$1" ]; then backup_file "$1"; fi
    printf '%s\n' "$3" | atomic_file "$1" 644
}

apply_sshd_guard() {
    changed=${SSHD_CONFIG_CHANGED:-0} content=${CONTENT_CHANGED:-0}
    SSHD_CONFIG_CHANGED=0 CONTENT_CHANGED=0
    [ "$changed" -eq 1 ] || [ "$content" -eq 1 ] || return 0
    if [ "$changed" -eq 1 ] && ! validate_sshd; then
        latest=$(ls -t "$SSHD_CONFIG".ucmbak.* 2>/dev/null | head -n 1)
        if [ -n "$latest" ]; then
            mv -f "$latest" "$SSHD_CONFIG"
            log "WARN: sshd_config failed sshd -t; restored it, no reload"
        fi
        return 0
    fi
    reload_sshd
}

fetch_krl() {
    [ -n "${USER_CA_REFID:-}" ] && [ -n "${KRL_PATH:-}" ] || return 1
    target=$(directive_target RevokedKeys "$KRL_FILE")
    etag=""
    [ -f "$ETAG_FILE" ] && etag=$(cat "$ETAG_FILE")
    hdr=$(mktemp); out=$(mktemp)
    # --fail: without it a 429/500 error page becomes the RevokedKeys file and
    # the host silently stops enforcing revocations while logging "KRL synced".
    if curl -sS --fail --connect-timeout 10 --max-time 60 -o "$out" -D "$hdr" \
        ${etag:+-H "If-None-Match: \"$etag\""} "$UCM_URL$KRL_PATH"; then
        case "$(head -n 1 "$hdr")" in
            *" 304 "*) rm -f "$hdr" "$out"; return 1 ;;
        esac
        # Stream the body straight into the file: a KRL is binary, command
        # substitution would eat its NUL bytes.
        if [ "$target" != "$KRL_FILE" ] && [ -f "$target" ]; then backup_file "$target"; fi
        if ! atomic_file "$target" 644 < "$out"; then
            # Same class as the placeholder fix: a target directory that cannot be
            # written must not report "KRL synced". The ETag stays as it was, so the
            # next poll fetches the KRL again instead of being answered with 304.
            log "WARN: could not write the KRL to $target (not applied, will retry)"
            rm -f "$hdr" "$out"
            return 1
        fi
        CONTENT_CHANGED=1
        newetag=$(grep -i '^etag:' "$hdr" | head -n 1 | sed 's/^[^:]*:[[:space:]]*//; s/\r//g; s/^"\|"$//g')
        printf '%s' "$newetag" > "$ETAG_FILE"
        log "KRL synced to $target"
        rm -f "$hdr" "$out"
        return 0
    fi
    log "WARN: KRL fetch failed: $(head -n 1 "$hdr" 2>/dev/null || echo 'no response from UCM')"
    rm -f "$hdr" "$out"
    return 1
}

renew_cert() {
    [ -n "${HOST_TOKEN:-}" ] || return 1
    resp=$(curl_get -X POST "$UCM_URL/api/v2/ssh/hosts/renew" -H "X-Host-Token: $HOST_TOKEN") \
        || { [ -n "$resp" ] && log "renew refused: $(brief "$resp")"; return 1; }
    cert=$(printf '%s' "$resp" | json_str certificate)
    [ -n "$cert" ] || { log "renew refused: $(brief "$resp")"; return 1; }
    default_cert=$(cert_target_default) || { log "WARN: no ssh host key found and CERT_FILE unset; certificate not installed"; return 1; }
    target=$(directive_target HostCertificate "$default_cert")
    write_content "$target" "$default_cert" "$cert"
    CONTENT_CHANGED=1
    log "host certificate renewed: $target"
}

enroll() {
    [ -n "${BOOTSTRAP_TOKEN:-}" ] || return 0
    pk=$(host_pubkey_file) || die "no ssh_host_*_key.pub found under ${SSH_HOST_KEY_DIR:-/etc/ssh}"
    body=$(printf '{"bootstrap_token":"%s","hostname":"%s","public_key":"%s"}' \
        "$BOOTSTRAP_TOKEN" "$(hostname -f 2>/dev/null || hostname)" "$(cat "$pk")")
    resp=$(curl_get -X POST "$UCM_URL/api/v2/ssh/hosts/enroll" \
        -H 'Content-Type: application/json' -d "$body") || :
    token=$(printf '%s' "$resp" | json_str host_token)
    case "$token" in
        ucm_sh_*) ;;
        *)
            # Expired/used bootstrap token: drop it and continue with the
            # existing host token when there is one (a re-install after the
            # TTL must not break KRL sync).
            if [ -n "${HOST_TOKEN:-}" ]; then
                # Same reason visibility as the die branch below: a re-install onto a
                # host that already has a token must not hide why UCM said no.
                log "WARN: enrollment failed ($(brief "${resp:-no response}")); continuing as enrolled host"
                conf_tmp="$CONF.tmp.$$"
                sed '/^BOOTSTRAP_TOKEN=/d' "$CONF" > "$conf_tmp" && mv -f "$conf_tmp" "$CONF" && chmod 600 "$CONF"
                return 0
            fi
            die "enroll refused: $(brief "${resp:-no response}")"
            ;;
    esac
    conf_tmp="$CONF.tmp.$$"
    sed -e '/^BOOTSTRAP_TOKEN=/d' -e '/^HOST_TOKEN=/d' \
        -e '/^USER_CA_REFID=/d' -e '/^KRL_PATH=/d' "$CONF" > "$conf_tmp"
    printf 'HOST_TOKEN="%s"\n' "$token" >> "$conf_tmp"
    refid=$(printf '%s' "$resp" | json_str refid)
    krlpath=$(printf '%s' "$resp" | json_str krl_path)
    capub=$(printf '%s' "$resp" | json_str public_key)
    if [ -n "$refid" ]; then printf 'USER_CA_REFID="%s"\nKRL_PATH="%s"\n' "$refid" "$krlpath" >> "$conf_tmp"; fi
    mv -f "$conf_tmp" "$CONF"; chmod 600 "$CONF"
    USER_CA_REFID="$refid"; KRL_PATH="$krlpath"

    cert=$(printf '%s' "$resp" | json_str certificate)
    if [ -n "$cert" ]; then
        default_cert=$(cert_target_default)
        ensure_directive HostCertificate "$default_cert"
        target=$(directive_target HostCertificate "$default_cert")
        write_content "$target" "$default_cert" "$cert"
        log "host certificate installed: $target"
    fi
    if [ -n "$refid" ] && [ -n "$capub" ]; then
        ensure_directive TrustedUserCAKeys "$USER_CA_PUB_FILE"
        ensure_directive RevokedKeys "$KRL_FILE"
        ca_target=$(directive_target TrustedUserCAKeys "$USER_CA_PUB_FILE")
        write_content "$ca_target" "$USER_CA_PUB_FILE" "$capub"
        log "user CA installed: $ca_target"
        fetch_krl || log "WARN: initial KRL fetch failed (check-in will retry)"
        krl_target=$(directive_target RevokedKeys "$KRL_FILE")
        # A placeholder so the RevokedKeys line points at a file that exists:
        # sshd refuses to load a missing one. Through atomic_file, not `: >`,
        # because under umask 077 a bare redirect creates it 0600.
        [ -f "$krl_target" ] || atomic_file "$krl_target" 644 < /dev/null \
            || log "WARN: could not create the placeholder for $krl_target (check-in will retry)"
    fi
    apply_sshd_guard
    log "enrolled"
}

apply_config_update() {
    resp="$1"
    has_user=$(printf '%s' "$resp" | json_yes has_user_ca)
    has_host=$(printf '%s' "$resp" | json_yes has_host_ca)

    if [ "${has_user:-0}" -ge 1 ]; then
        new_refid=$(printf '%s' "$resp" | json_str refid)
        new_krl=$(printf '%s' "$resp" | json_str krl_path)
        new_capub=$(printf '%s' "$resp" | json_str public_key)
        conf_tmp="$CONF.tmp.$$"
        grep -vE '^(USER_CA_REFID|KRL_PATH)=' "$CONF" > "$conf_tmp" || true
        [ -n "$new_refid" ] && printf 'USER_CA_REFID=%s\n' "$new_refid" >> "$conf_tmp"
        [ -n "$new_krl" ] && printf 'KRL_PATH=%s\n' "$new_krl" >> "$conf_tmp"
        chmod 600 "$conf_tmp"
        mv -f "$conf_tmp" "$CONF"
        USER_CA_REFID="$new_refid"
        KRL_PATH="$new_krl"
        rm -f "$ETAG_FILE"
        ensure_directive TrustedUserCAKeys "$USER_CA_PUB_FILE"
        ensure_directive RevokedKeys "$KRL_FILE"
        ca_target=$(directive_target TrustedUserCAKeys "$USER_CA_PUB_FILE")
        [ -n "$new_capub" ] && write_content "$ca_target" "$USER_CA_PUB_FILE" "$new_capub"
        krl_target=$(directive_target RevokedKeys "$KRL_FILE")
        [ -f "$krl_target" ] || atomic_file "$krl_target" 644 < /dev/null || true
        fetch_krl || true
    else
        conf_tmp="$CONF.tmp.$$"
        grep -vE '^(USER_CA_REFID|KRL_PATH)=' "$CONF" > "$conf_tmp" || true
        chmod 600 "$conf_tmp"
        mv -f "$conf_tmp" "$CONF"
        USER_CA_REFID=""
        KRL_PATH=""
        remove_directive TrustedUserCAKeys
        remove_directive RevokedKeys
        rm -f "$USER_CA_PUB_FILE" "$KRL_FILE" "$ETAG_FILE"
    fi

    if [ "${has_host:-0}" -eq 0 ]; then
        remove_directive HostCertificate
        rm -f "$CERT_FILE"
    else
        ensure_directive HostCertificate "$CERT_FILE"
    fi
}

check_in() {
    [ -n "${HOST_TOKEN:-}" ] || return 1
    etag=""
    [ -f "$ETAG_FILE" ] && etag=$(cat "$ETAG_FILE")
    krl_ok="true"
    [ -n "${KRL_LAST_ERROR:-}" ] && krl_ok="false"
    resp=$(curl_get -X POST "$UCM_URL/api/v2/ssh/hosts/check-in" \
        -H "X-Host-Token: $HOST_TOKEN" -H 'Content-Type: application/json' \
        -d "{\"krl_etag\":\"$etag\",\"krl_written\":$krl_ok}") || { [ -n "$resp" ] && log "check-in refused: $(brief "$resp")"; return 1; }
    cfg_changed=$(printf '%s' "$resp" | json_yes config_changed)
    renew=$(printf '%s' "$resp" | json_yes renew_required)
    changed=$(printf '%s' "$resp" | json_yes krl_changed)
    if [ "${cfg_changed:-0}" -ge 1 ]; then
        apply_config_update "$resp"
    fi
    [ "${renew:-0}" -ge 1 ] && renew_cert || true
    # The direct fetch already ran this cycle; only re-fetch when the server
    # reports a version newer than the etag we sent (change raced the fetch).
    if [ "${changed:-0}" -ge 1 ]; then fetch_krl || true; fi
    if [ "${cfg_changed:-0}" -ge 1 ]; then
        apply_sshd_guard
        curl_get -X POST "$UCM_URL/api/v2/ssh/hosts/check-in" \
            -H "X-Host-Token: $HOST_TOKEN" -H 'Content-Type: application/json' \
            -d '{"config_applied":true}' >/dev/null || true
    fi
    return 0
}

run() {
    KRL_LAST_ERROR=""
    if [ -n "${BOOTSTRAP_TOKEN:-}" ]; then enroll; fi
    fetch_krl || KRL_LAST_ERROR="1"
    check_in || log "WARN: check-in failed (will retry on the next timer tick)"
    apply_sshd_guard
}

case "${1:-run}" in
    enroll) enroll ;;
    run)    run ;;
    noop)   return 0 2>/dev/null || exit 0 ;;
    *)      die "unknown mode: $1" ;;
esac
'''


def _unix_installer(ucm_url, bootstrap_token):
    return f'''#!/bin/sh
# UCM SSH managed-host agent installer — generated by UCM, one-time token inside.
set -eu
# agent.conf is rewritten through a scratch file and ends up holding the
# long-lived host token; /etc/ucm is root-only (sshd never reads it).
umask 077

command -v curl >/dev/null 2>&1 || {{ echo "curl is required"; exit 1; }}
[ "$(id -u)" -eq 0 ] || {{ echo "run as root (sudo)"; exit 1; }}

mkdir -p /etc/ucm

curl -sS --fail --connect-timeout 10 -o {RUNNER_PATH} "{ucm_url}/ssh/agent-runner"
chmod 700 {RUNNER_PATH}

# Re-install keeps the host token but always refreshes the bootstrap token,
# so a re-run re-enrolls (also after a host key rotation on the server).
if [ ! -f {CONF_PATH} ]; then
cat > {CONF_PATH} <<'EOF'
UCM_URL="{ucm_url}"
EOF
fi
conf_tmp={CONF_PATH}.tmp.$$
sed '/^BOOTSTRAP_TOKEN=/d' {CONF_PATH} > "$conf_tmp"
if ! grep -q '^UCM_URL=' "$conf_tmp"; then printf 'UCM_URL="%s"\\n' "{ucm_url}" >> "$conf_tmp"; fi
printf 'BOOTSTRAP_TOKEN="%s"\\n' "{bootstrap_token}" >> "$conf_tmp"
mv -f "$conf_tmp" {CONF_PATH}
chmod 600 {CONF_PATH}

# systemd's *binary* being present is not the same as systemd running: in a
# container or on OpenRC/sysvinit it is installed, /etc/systemd/system need not
# exist, and `systemctl daemon-reload` answers "System has not been booted with
# systemd". Every step can fail, so none of them may abort the install under
# set -eu — the fallback schedule has to be printed instead, otherwise the host
# is left half-installed: runner downloaded, no enrollment, no schedule.
install_systemd_timer() {{
    mkdir -p /etc/systemd/system || return 1
    cat > /etc/systemd/system/ucm-ssh-agent.service <<'EOF' || return 1
[Unit]
Description=UCM SSH agent sync (KRL + host certificate)
After=network-online.target

[Service]
Type=oneshot
ExecStart={RUNNER_PATH} run
EOF
    cat > /etc/systemd/system/ucm-ssh-agent.timer <<'EOF' || return 1
[Unit]
Description=UCM SSH agent sync every 15 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=15min
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload || return 1
    systemctl enable --now ucm-ssh-agent.timer || return 1
}}

scheduled=0
if command -v systemctl >/dev/null 2>&1 && install_systemd_timer; then
    scheduled=1
    echo "ucm-ssh-agent installed: timer every 15 minutes."
fi

if [ "$scheduled" -ne 1 ]; then
if command -v crontab >/dev/null 2>&1; then
    ( crontab -l 2>/dev/null | grep -vF '*/15 * * * * {RUNNER_PATH} run'; echo '*/15 * * * * {RUNNER_PATH} run' ) | crontab - 2>/dev/null || true
    scheduled=1
    echo "ucm-ssh-agent installed: crontab entry added (every 15 minutes)."
else
    echo "WARN: No systemd or crontab found."
fi
fi

case "{ucm_url}" in
    http://*) echo "WARN: this agent will reach UCM over {ucm_url} IN THE CLEAR: the host token,"
              echo "      every certificate and the KRL cross the network unencrypted. If UCM serves"
              echo "      https, re-run the install command from that address instead." ;;
esac

{RUNNER_PATH} enroll
'''


def _ps1_runner():
    return r'''# ucm-ssh-agent.ps1 — pull-only agent for Windows OpenSSH. Modes: run|enroll
param([string]$Mode = "run")
$ErrorActionPreference = "Stop"
$confPath = "C:\ProgramData\ucm\agent.conf"
$etagFile = "C:\ProgramData\ucm\krl.etag"
if (-not (Test-Path $confPath)) { Write-Error "config not found: $confPath" }
$conf = @{}
Get-Content $confPath | ForEach-Object {
    if ($_ -match '^\s*(\w+)\s*=\s*"?([^"]*)"?\s*$') { $conf[$matches[1]] = $matches[2] }
}
$ucm = $conf['UCM_URL']
$sshDir = "C:\ProgramData\ssh"
$cfgFile = "$sshDir\sshd_config"
$certFile = if ($conf['CERT_FILE']) { $conf['CERT_FILE'] } else { "$sshDir\ssh_host_ed25519_key-cert.pub" }
$krlFile = if ($conf['KRL_FILE']) { $conf['KRL_FILE'] } else { "$sshDir\ucm_user_krl" }
$caPubFile = if ($conf['USER_CA_PUB_FILE']) { $conf['USER_CA_PUB_FILE'] } else { "$sshDir\ucm_user_ca.pub" }

function Reload-SSH {
    if (Test-Path $cfgFile) {
        $sshdExe = "sshd.exe"
        try {
            & $sshdExe -t -f $cfgFile 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Output "ucm-ssh-agent: sshd_config validation failed, reverting backup"
                if (Test-Path "$cfgFile.ucmbak") { Copy-Item "$cfgFile.ucmbak" $cfgFile -Force }
                return
            }
        } catch {}
    }
    Restart-Service sshd -ErrorAction SilentlyContinue
}

function Current-Value([string]$name) {
    $m = Select-String -Path $cfgFile -Pattern "^\s*$name\s+(\S+)" | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value }
    return $null
}

# Where the agent must write: OpenSSH honours only the FIRST directive value,
# so a foreign pre-UCM path becomes the write target. Run mode never edits the
# config; only Enroll appends missing lines (with a backup).
function Resolve-Target([string]$name, [string]$default) {
    $v = Current-Value $name
    if ($v) { $v } else { $default }
}

function Ensure-Directive([string]$name, [string]$path) {
    $cur = Current-Value $name
    if ($cur -eq $path) { return }
    if ($cur) { Write-Output "ucm-ssh-agent: WARN $name already set to $cur - writing UCM content there"; return }
    if (Test-Path $cfgFile) {
        Copy-Item $cfgFile "$cfgFile.ucmbak" -Force
        @(Get-Content $cfgFile) + "$name $path" | Set-Content $cfgFile
    } else {
        "$name $path" | Set-Content $cfgFile
    }
}

function Write-Content($target, $desired, $content) {
    if ($target -ne $desired -and (Test-Path $target)) { Copy-Item $target "$target.ucmbak" -Force }
    Set-Content $target $content
}

function Fetch-Krl {
    if (-not $conf['KRL_PATH']) { return $false }
    $target = Resolve-Target "RevokedKeys" $krlFile
    $headers = @{}
    if (Test-Path $etagFile) { $headers['If-None-Match'] = (Get-Content $etagFile) -join '' }
    try {
        $resp = Invoke-WebRequest -Uri "$ucm$($conf['KRL_PATH'])" -Headers $headers -UseBasicParsing
    } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        if ($_.Exception.Response.StatusCode.Value__ -eq 304) { return $false }
        throw
    }
    # A KRL is binary: $resp.Content decodes it as text and Set-Content then
    # re-encodes with the default codepage and CRLF, which corrupts the file
    # sshd is about to read. Write the raw bytes, atomically.
    if ($target -ne $krlFile -and (Test-Path $target)) { Copy-Item $target "$target.ucmbak" -Force }
    $tmp = "$target.tmp"
    [IO.File]::WriteAllBytes($tmp, $resp.RawContentStream.ToArray())
    Move-Item -Force $tmp $target
    if ($resp.Headers.ETag) { Set-Content $etagFile (($resp.Headers.ETag | Select-Object -First 1) -replace '"', '') }
    Write-Output "ucm-ssh-agent: KRL synced to $target"
    return $true
}

function Renew {
    if (-not $conf['HOST_TOKEN']) { return }
    $resp = Invoke-RestMethod -Method Post -Uri "$ucm/api/v2/ssh/hosts/renew" -Headers @{ "X-Host-Token" = $conf['HOST_TOKEN'] }
    if ($resp.data.certificate) {
        $target = Resolve-Target "HostCertificate" $certFile
        Write-Content $target $certFile $resp.data.certificate
        Reload-SSH
    } else { Write-Output "ucm-ssh-agent: renew refused: $($resp.message)" }
}

function Get-HostPubKey {
    if (Test-Path $cfgFile) {
        $m = Select-String -Path $cfgFile -Pattern "^\s*HostKey\s+(\S+)"
        foreach ($match in $m) {
            $hk = $match.Matches[0].Groups[1].Value.Trim('"')
            $pub = if ($hk.EndsWith(".pub")) { $hk } else { "$hk.pub" }
            if (Test-Path $pub) { return $pub }
        }
    }
    foreach ($kt in @("ed25519", "ecdsa", "rsa")) {
        $f = "$sshDir\ssh_host_${kt}_key.pub"
        if (Test-Path $f) { return $f }
    }
    $gen = "$sshDir\ssh_host_ed25519_key"
    try {
        & ssh-keygen -t ed25519 -f $gen -N ""
        if (Test-Path "$gen.pub") { return "$gen.pub" }
    } catch {}
    $any = Get-ChildItem "$sshDir\ssh_host_*_key.pub" | Select-Object -First 1
    if ($any) { return $any.FullName }
    Write-Error "no host public key found or generated in $sshDir"
}

function Enroll {
    if (-not $conf['BOOTSTRAP_TOKEN']) { return }
    $pubFile = Get-HostPubKey
    $body = @{ bootstrap_token = $conf['BOOTSTRAP_TOKEN']; hostname = hostname; public_key = (Get-Content $pubFile -Raw).Trim() } | ConvertTo-Json
    try {
        $data = (Invoke-RestMethod -Method Post -Uri "$ucm/api/v2/ssh/hosts/enroll" -ContentType "application/json" -Body $body).data
    } catch {
        if ($conf['HOST_TOKEN']) {
            # The same reason visibility as the POSIX runner: ErrorDetails.Message carries
            # UCM's answer (present in Windows PowerShell 5.1 and in pwsh 7).
            Write-Output "ucm-ssh-agent: WARN enrollment failed ($($_.ErrorDetails.Message)); continuing as enrolled host"
            # @() : Get-Content hands back a scalar String when one line survives, and
            # then += concatenates instead of appending an element.
            $kept = @(Get-Content $confPath | Where-Object { $_ -notmatch '^\s*BOOTSTRAP_TOKEN=' })
            Set-Content $confPath $kept
            return
        }
        throw
    }
    if (-not $data.host_token) { Write-Error "enroll refused" }
    # @() for the same reason as $kept: a fresh conf leaves one line, and a scalar
    # String += "HOST_TOKEN=…" would glue the token onto UCM_URL.
    $lines = @(Get-Content $confPath | Where-Object { $_ -notmatch '^\s*BOOTSTRAP_TOKEN=' -and $_ -notmatch '^\s*HOST_TOKEN=' -and $_ -notmatch '^\s*USER_CA_REFID=' -and $_ -notmatch '^\s*KRL_PATH=' })
    $lines += "HOST_TOKEN=$($data.host_token)"
    if ($data.user_ca) {
        # Written with the token, before anything below can throw: without KRL_PATH the
        # agent would silently never pull a KRL again, and check-in does not repair it.
        $lines += "USER_CA_REFID=$($data.user_ca.refid)"
        $lines += "KRL_PATH=$($data.user_ca.krl_path)"
    }
    # Save the host token before anything that can throw: the bootstrap token is
    # already spent at this point, and a host whose token was not written has to
    # be reinstalled from the UI.
    Set-Content $confPath $lines
    # Fetch-Krl and Renew read the parsed conf, not the file, and it was parsed
    # before enrollment existed: without this, KRL_PATH only appears on the next
    # tick and the initial fetch below silently does nothing.
    $conf['HOST_TOKEN'] = $data.host_token
    if ($data.user_ca) {
        $conf['USER_CA_REFID'] = $data.user_ca.refid
        $conf['KRL_PATH'] = $data.user_ca.krl_path
    }
    if ($data.certificate) {
        Ensure-Directive "HostCertificate" $certFile
        $target = Resolve-Target "HostCertificate" $certFile
        Write-Content $target $certFile $data.certificate
    }
    if ($data.user_ca) {
        Ensure-Directive "TrustedUserCAKeys" $caPubFile
        Ensure-Directive "RevokedKeys" $krlFile
        $caTarget = Resolve-Target "TrustedUserCAKeys" $caPubFile
        Write-Content $caTarget $caPubFile $data.user_ca.public_key
        # RevokedKeys must point at a file that exists, or sshd will not load the config.
        $krlTarget = Resolve-Target "RevokedKeys" $krlFile
        if (-not (Test-Path $krlTarget)) { [IO.File]::WriteAllBytes($krlTarget, [byte[]]::new(0)) }
        try { Fetch-Krl | Out-Null } catch { Write-Output "ucm-ssh-agent: WARN initial KRL fetch failed (check-in will retry)" }
    }
    Reload-SSH
    Write-Output "ucm-ssh-agent: enrolled"
}

if ($Mode -eq "enroll") { Enroll; exit 0 }
if ($conf['BOOTSTRAP_TOKEN']) { Enroll }
# A failed KRL fetch must not end the tick: check-in and renewal still have to run.
$krlChanged = $false
try { $krlChanged = Fetch-Krl } catch { Write-Output "ucm-ssh-agent: KRL fetch failed (will retry on next run)" }
if ($conf['HOST_TOKEN']) {
    try {
        $etag = if (Test-Path $etagFile) { (Get-Content $etagFile) -join '' } else { "" }
        $d = (Invoke-RestMethod -Method Post -Uri "$ucm/api/v2/ssh/hosts/check-in" -Headers @{ "X-Host-Token" = $conf['HOST_TOKEN'] } -ContentType "application/json" -Body (@{ krl_etag = $etag } | ConvertTo-Json)).data
        if ($d.config_changed -and $d.config_update) {
            $cu = $d.config_update
            $lines = @(Get-Content $confPath | Where-Object { $_ -notmatch '^\s*USER_CA_REFID=' -and $_ -notmatch '^\s*KRL_PATH=' })
            if ($cu.has_user_ca -and $cu.user_ca) {
                $lines += "USER_CA_REFID=$($cu.user_ca.refid)"
                $lines += "KRL_PATH=$($cu.user_ca.krl_path)"
                Set-Content $confPath $lines
                $conf['USER_CA_REFID'] = $cu.user_ca.refid
                $conf['KRL_PATH'] = $cu.user_ca.krl_path
                Remove-Item -Force -ErrorAction SilentlyContinue $etagFile
                Ensure-Directive "TrustedUserCAKeys" $caPubFile
                Ensure-Directive "RevokedKeys" $krlFile
                $caTarget = Resolve-Target "TrustedUserCAKeys" $caPubFile
                Write-Content $caTarget $caPubFile $cu.user_ca.public_key
                $krlTarget = Resolve-Target "RevokedKeys" $krlFile
                if (-not (Test-Path $krlTarget)) { [IO.File]::WriteAllBytes($krlTarget, [byte[]]::new(0)) }
                try { $krlChanged = Fetch-Krl } catch {}
            } else {
                Set-Content $confPath $lines
                $conf.Remove('USER_CA_REFID')
                $conf.Remove('KRL_PATH')
                if (Test-Path $cfgFile) {
                    Copy-Item $cfgFile "$cfgFile.ucmbak" -Force
                    @(Get-Content $cfgFile | Where-Object { $_ -notmatch '^\s*(TrustedUserCAKeys|RevokedKeys)\s' }) | Set-Content $cfgFile
                }
                Remove-Item -Force -ErrorAction SilentlyContinue $caPubFile, $krlFile, $etagFile
            }
            if (-not $cu.has_host_ca) {
                if (Test-Path $cfgFile) {
                    Copy-Item $cfgFile "$cfgFile.ucmbak" -Force
                    @(Get-Content $cfgFile | Where-Object { $_ -notmatch '^\s*HostCertificate\s' }) | Set-Content $cfgFile
                }
                Remove-Item -Force -ErrorAction SilentlyContinue $certFile
            } else {
                Ensure-Directive "HostCertificate" $certFile
            }
            $krlChanged = $true
        }
        if ($d.renew_required) { Renew }
        if ($d.krl_changed) { $krlChanged = Fetch-Krl }
        if ($d.config_changed) {
            Reload-SSH
            try { Invoke-RestMethod -Method Post -Uri "$ucm/api/v2/ssh/hosts/check-in" -Headers @{ "X-Host-Token" = $conf['HOST_TOKEN'] } -ContentType "application/json" -Body (@{ config_applied = $true } | ConvertTo-Json) | Out-Null } catch {}
        }
    } catch { Write-Output "ucm-ssh-agent: check-in failed (will retry on next run)" }
}
if ($krlChanged) { Reload-SSH }
'''


def _ps1_installer(ucm_url, bootstrap_token):
    return f'''# UCM SSH managed-host agent installer (Windows, elevated PowerShell)
$ErrorActionPreference = "Stop"
$ucm = "{ucm_url}"
$dir = "C:\\ProgramData\\ucm"
New-Item -ItemType Directory -Force -path $dir | Out-Null
Invoke-WebRequest -Uri "$ucm/ssh/agent-runner?platform=windows" -OutFile "$dir\\ucm-ssh-agent.ps1"
$conf = "$dir\\agent.conf"
if (-not (Test-Path $conf)) {{ "UCM_URL=$ucm" | Set-Content $conf }}
# @(Get-Content) read fully into memory first: piping Get-Content straight into
# Set-Content of the same file is the classic "file is being used by another process".
$confLines = @(Get-Content $conf) | Where-Object {{ $_ -notmatch '^\\s*BOOTSTRAP_TOKEN=' }}
Set-Content $conf $confLines
"BOOTSTRAP_TOKEN={bootstrap_token}" | Add-Content $conf
schtasks /Create /TN "ucm-ssh-agent" /SC MINUTE /MO 15 /F /RU SYSTEM /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dir\\ucm-ssh-agent.ps1" | Out-Null
& "$dir\\ucm-ssh-agent.ps1" -Mode enroll
Write-Output "ucm-ssh-agent installed: scheduled task every 15 minutes."
'''


def build_agent_setup_script(ucm_url, bootstrap_token, platform='unix'):
    if platform == 'windows':
        return _ps1_installer(ucm_url, bootstrap_token)
    return _unix_installer(ucm_url, bootstrap_token)


def build_agent_runner(platform='unix'):
    if platform == 'windows':
        return _ps1_runner()
    return _unix_runner_script()
