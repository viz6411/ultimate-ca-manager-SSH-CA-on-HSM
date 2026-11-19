# Pre-release checklist — SSH CA deploy automation

Scope: the SSH CA feature that binds an SSH certificate authority to an existing
deploy target, lays its artefacts (CA public key, KRL) in the canonical directory
on that target and signs the target's own host key. It sits beside the X.509 deploy
hooks (`docs/API_REFERENCE.md`, Deploy Hooks), so this checklist runs next to
[RELEASE_TESTING.md](../RELEASE_TESTING.md), not instead of it.

Route and field names are the ones the branch ships. Read them from
`docs/API_REFERENCE.md` at run time — this file names behaviour and expected
results, not endpoints that may not exist yet.

Reference topology (lab example — adapt hostnames, as in
[docs/testing/PUBLIC-ENDPOINTS-TEST-PLAN.md](testing/PUBLIC-ENDPOINTS-TEST-PLAN.md)):

| Role | Example |
|------|---------|
| UCM | `https://ucm.example.net:8443` |
| Target, full sshd | `ssh1.example.net` (Ubuntu 24.04 or RHEL 9) |
| Target, exec refused | `sftp1.example.net` (`internal-sftp`, chroot) |
| Test client | `client.example.net` |

## How to use this checklist

- Run the whole checklist on every release candidate and on the stable tag, before
  the release is published. Run it on SQLite and on PostgreSQL, and on the
  deliverables [RELEASE_TESTING.md](../RELEASE_TESTING.md) lists.
- Tick a box only when you saw the expected result. Record for every item: version
  (`cat /opt/ucm/VERSION`), backend, deliverable, and for a Failed item the exact
  error text and the audit entry.
- A Failed item sends the candidate back to development. After the fix, re-run the
  whole checklist: an SSH CA change reaches the deploy queue, the deletion blockers
  and the backup manifest, so a partial re-run does not show what moved.
- Items marked `[LAB]` can only be settled against a live sshd server. No CI job
  answers them. Mark them Failed when the observed behaviour differs, not "untested".
- Write "N/A" nowhere. If an item does not apply to a deliverable, write why.

## 1. Stand preparation

Prepare the target once, as root, before UCM touches it:

```bash
# On the sshd target. TARGET_USER is the deploy service user UCM connects as.
TARGET_USER=ucm-deploy
id "$TARGET_USER" 2>/dev/null || useradd -r -m -s /usr/sbin/nologin "$TARGET_USER"
install -d -m 755 -o "$TARGET_USER" -g "$TARGET_USER" /etc/ssh/ssh_ca_keys
install -d -m 700 -o "$TARGET_USER" -g "$TARGET_USER" "/home/$TARGET_USER/.ssh"
# The public key UCM shows on the target (Settings > Deployment > Show public key)
printf '%s\n' '<ssh-ed25519 AAAA... ucm-deploy>' > "/home/$TARGET_USER/.ssh/authorized_keys"
chmod 600 "/home/$TARGET_USER/.ssh/authorized_keys"
chown -R "$TARGET_USER:$TARGET_USER" "/home/$TARGET_USER"
# One NOPASSWD line, nothing else
printf '%s\n' "$TARGET_USER ALL=(root) NOPASSWD: /usr/bin/systemctl reload sshd" \
  > /etc/sudoers.d/ucm-ssh-ca && chmod 440 /etc/sudoers.d/ucm-ssh-ca && visudo -c
# Clock and host keys
timedatectl set-ntp true && timedatectl status
ls -l /etc/ssh/ssh_host_*_key.pub
```

The sshd directives live in a drop-in the setup script or the administrator writes —
UCM never edits `sshd_config`:

```bash
# /etc/ssh/sshd_config.d/50-ucm-ssh-ca.conf
TrustedUserCAKeys /etc/ssh/ssh_ca_keys/<the file the binding names>
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
HostCertificate <the host-certificate path the binding names>
RevokedKeys <the KRL path the binding names>
# then: sshd -t && systemctl reload sshd
```

On the client, trust the host CA for the names the host certificate will carry:

```bash
printf '@cert-authority ssh1.example.net ssh1 %s\n' '<host CA public key>' >> ~/.ssh/known_hosts
```

- [ ] **PREP-01 — Target runs a real sshd with host keys**
  - Check: `ssh -p 22 <user>@ssh1.example.net exit`, `ls -l /etc/ssh/ssh_host_*_key.pub`.
  - Expected: sshd answers; at least one host public key exists, and its type is
    recorded in the checklist (Ed25519, ECDSA or RSA).

- [ ] **PREP-02 — NTP is on, on UCM and on the target**
  - Check: `timedatectl status` on both, `date -u` on both.
  - Expected: both are synchronised and differ by less than a few seconds. An
    unsynchronised clock makes a freshly signed host certificate outside its
    validity window; a failure here invalidates every item in sections 4 and 5.

- [ ] **PREP-03 — Both names of the target resolve**
  - Check: `getent hosts ssh1.example.net ssh1`, `getent hosts sftp1.example.net`.
  - Expected: the FQDN and the short name both resolve to the target. The client
    host must resolve too, and one name must resolve to an address that is *not*
    in the principals list (an IP-only alias) for HOST-04.

- [ ] **PREP-04 — Both SSH CAs exist in UCM**
  - Check: Modules > Administration > SSH CAs: create one host CA and one user CA,
    each with `allowed_principals` set to the target's FQDN, its short name and its
    aliases, `max_ttl` set to a short value (for example 7 days),
    `allow_any_principal` off.
  - Expected: both CAs are listed with their fingerprints and key types; the host CA
    reports `ca_type: host`, the user CA `ca_type: user`.

- [ ] **PREP-05 — Deploy target exists with its service user**
  - Check: Settings > Deployment > Add target (SSH), username `ucm-deploy`, key
    generated by UCM; then `POST /api/v2/deploy/targets/<id>/test` (Test connection).
  - Expected: the test answers `Connection and SFTP OK`, the host key is pinned on
    first connect (`host_key_pinned: true`, fingerprint shown), and the target's
    public key is the one installed in `authorized_keys`.

- [ ] **PREP-06 — Canonical directory is owned by the deploy service user**
  - Check: `ls -ld /etc/ssh/ssh_ca_keys`, `sudo -u ucm-deploy test -w /etc/ssh/ssh_ca_keys && echo writable`.
  - Expected: the directory exists, mode 0755, owned by the deploy service user, and
    that account can write in it. UCM created nothing: the stand created it.

- [ ] **PREP-07 — The sudoers grant is exactly one NOPASSWD line**
  - Check: `sudo -l -U ucm-deploy`, `cat /etc/sudoers.d/ucm-ssh-ca`.
  - Expected: one line, `systemctl reload sshd`, NOPASSWD. No wildcard, no `ALL`, no
    second grant. `visudo -c` says `parsed correctly`.

- [ ] **PREP-08 — Drop-in carries the directives, UCM wrote none of them**
  - Check: `cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf`,
    `stat -c '%y %U %n' /etc/ssh/sshd_config`.
  - Expected: `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `HostCertificate` and
    `RevokedKeys` point at the paths the bindings will name, all of them under
    `/etc/ssh/ssh_ca_keys` — the host certificate's default is
    `/etc/ssh/ssh_ca_keys/<CA slug>_host_key-cert.pub`, not the file next to the host
    key, because two host CAs on one host must not write one file, and `/etc/ssh`
    itself stays owned by root; `sshd -t` exits 0; `sshd_config` is unchanged since the
    stand was prepared and owned by root.

- [ ] **PREP-09 — Restricted target exists (exec refused)**
  - Check: a second target whose account is confined to `internal-sftp` in a chroot,
    `POST /api/v2/deploy/targets/<id>/test`, then `ssh sftp1.example.net -l ucm-ro exit`.
  - Expected: SFTP works over that target and `exec` is refused by sshd
    (`Subsystem request failed` or the shell never starts). This target is used by
    PROBE-04 and LIM-04.

- [ ] **PREP-10 — Stand snapshot taken before the run**
  - Check: copy `/opt/ucm/data/ucm.db` (or `pg_dump`) and `/etc/ucm/master.key` to a
    location outside the data directory, mode 0600.
  - Expected: a copy exists that a later item can restore. UCM never deletes it.

- [ ] **PREP-11 — What UCM does not do on the server is stated, not assumed**
  - Check: after the first successful attach and delivery, run
    `stat -c '%y %U %n' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*`,
    `find /etc/ssh -newer /etc/passwd -name 'sshd_config*'`, and on the UCM side read
    the delivery detail of that push.
  - Expected: no directory was created by UCM over SFTP, `sshd_config` and its
    drop-ins were not touched, and the delivery detail lists only the artefact paths.
    Any config edit UCM made is a defect.

## 2. Attaching a target to an SSH CA

- [ ] **ATT-01 — Attach the target to the host CA**
  - Check: SSH CAs > the host CA > its deployment section > attach the lab target;
    leave the default artefact paths under `/etc/ssh/ssh_ca_keys`.
  - Expected: the binding is created, listed on the CA card and on the target, and
    the initial artefact push is queued without a manual Deploy now.

- [ ] **ATT-02 — Attach the same target to the user CA**
  - Check: same attach flow on the user CA.
  - Expected: the binding is created; the user CA's public key is pushed; **no** host
    certificate is created for a user CA binding.

- [ ] **ATT-03 — Two CAs, one target: separate bindings**
  - Check: list the target's bindings.
  - Expected: one row per CA, each with its own paths and status. Attaching the same
    CA to the same target a second time answers 409.

- [ ] **ATT-04 — Principals outside `allowed_principals` are refused**
  - Check: set the CA's allowed principals to `ssh1.example.net`, `ssh1`; attach with
    a principal `other.example.net`.
  - Expected: the attach is refused with a message naming the principal and the CA's
    allowed principals. No binding row appears.

- [ ] **ATT-05 — Wildcard is allowed only on the CA**
  - Check: set `allowed_principals` to `ssh1.*`, attach the target, read the issued
    host certificate's principals.
  - Expected: the attach is accepted; the certificate's principals are exact names
    (`ssh1.example.net`, `ssh1`, the aliases), never `ssh1.*`. A wildcard written in
    the binding's principals is refused at save.

- [ ] **ATT-06 — Validity above the CA's `max_ttl` is refused at attach**
  - Check: CA `max_ttl` = 604800 (7 days); attach with a validity of 30 days.
  - Expected: the attach is refused, naming the CA's `max_ttl`, and
    `details.fields.validity.values` carries the durations the form spoke, not seconds
    (`validity` as `30d`, `max_ttl` as `7d`); the refusal's own text reads as the same
    durations. [LAB] Note separately what an over-long value does if it reaches the
    signing path today: `backend/services/ssh_cert/signing.py` clamps to `max_ttl`
    silently instead of refusing, so the refusal must come from the attach validation. A
    silent clamp of a value the form accepted is a defect to record, not a pass, and so is
    an answer that quotes `2592000` where the form said `30d`.

- [ ] **ATT-07 — A `ca_type` mismatch is refused**
  - Check: ask the host CA to serve user artefacts, and the user CA to serve a host
    certificate, through the attach form and through the API.
  - Expected: both refused. The signing rule already says an SSH user CA cannot sign
    host certificates and the other way round; the attach must refuse earlier, before
    a serial number is spent.

- [ ] **ATT-08 — No key-ID field when `allow_custom_key_id` is off**
  - Check: CA with `allow_custom_key_id: false`; open the attach form.
  - Expected: the key-ID field is not shown at all, and an API request that sends a
    key ID anyway is refused. The certificate carries the CA's own
    `<principals>@<CA name>` key ID, which is what sshd logs.

- [ ] **ATT-09 — Key-ID template accepted when `allow_custom_key_id` is on**
  - Check: set `allow_custom_key_id: true` on the CA, reopen the attach form, enter a
    template in the `{{name}}` syntax the HTTP targets use (`backend/services/deploy/http.py`),
    for example `{{name}}` or `host-{{name}}`, save.
  - Expected: the field is shown, the template saves, and the issued host
    certificate's `key_id` is the rendered name of the target/CA, not the literal
    `{{name}}`.

- [ ] **ATT-10 — A typo in the placeholder is refused at save**
  - Check: with `allow_custom_key_id: true`, save `{{nam}}`, `{{ name | jsonn }}`,
    and `{{name`.
  - Expected: each is refused at save with the reason (`Unknown template variable`,
    `Unknown template filter`, `Malformed template placeholder`). No binding is
    created, and no certificate is ever issued with a literal `{{` in its key ID.

- [ ] **ATT-11 — No reload command by default, and a restart only when the admin wrote it**
  - Check: read the binding's reload command after a default attach. Then write
    `sudo systemctl restart sshd` in it deliberately, save, and deliver.
  - Expected: the default binding carries no reload command and a KRL push runs
    nothing; a `restart sshd` happens only for the binding whose own command says so,
    and the delivery detail records its exit status. If the sudoers grant of PREP-07
    names only `systemctl reload sshd`, the `restart` is refused by sudo and the
    delivery fails with that text: record it under LIM-07, not as a defect here.

- [ ] **ATT-12 — Disabled binding and disabled target deliver nothing**
  - Check: disable the binding, revoke a certificate; then disable the target and
    re-enable the binding.
  - Expected: no delivery is queued while either is disabled; re-enabling the binding
    queues the current artefacts again (saving it does that itself). Re-enabling the
    target only lets rows that are already pending run on the next pass: a target
    re-enable, on its own, queues nothing — record that as the behaviour the release
    ships, and that a re-enabled target with no pending row needs a Deploy now.

- [ ] **ATT-13 — The reload command is one command, never a chained one**
  - Check: save a binding whose reload command is two commands joined by `&&`, then each
    of `;`, `||`, a single `|`, a trailing `&`, a command inside backticks, a command
    inside `$( )`, and a command split by a newline. Then put a chained command into an
    existing binding and save it.
  - Expected: each is refused with `422`, `details.fields.reload_command` and the key
    `sshDeploy.errors.reloadChained`, and the dialog puts that sentence on the reload
    field itself rather than only on a toast. No binding is created, and the refused edit
    leaves the stored command exactly as it was. A single command, with its own arguments
    and its own `sudo` prefix, is accepted: this rule is about chaining, not about
    shell-quoting a path. Automated: `TestReloadCommandIsOneCommand` in
    `backend/tests/test_ssh_ca_deploy.py` and
    `frontend/src/components/__tests__/SSHCaDeploySection.refusal.test.jsx`.

## 3. Permission probe at attach

- [ ] **PROBE-01 — Unwritable artefact directory refuses the attach**
  - Check: `chmod 755 /etc/ssh/ssh_ca_keys && chown root:root /etc/ssh/ssh_ca_keys`,
    attach the target, read the answer; restore the ownership.
  - Expected: the attach is refused with `422`, **no binding row is created**, and one
    `details.fields` entry per path that failed, each naming the target's username
    (`ucm-deploy`), the path, its directory and the right it needs (write access to that
    directory, and owning the files UCM places there). A generic `SFTP write failed`
    without the account and the right is a defect.

- [ ] **PROBE-02 — A missing sudo grant refuses the attach that names a reload command**
  - Check: `rm /etc/sudoers.d/ucm-ssh-ca`; attach the target **with** a reload command
    (`sudo systemctl reload sshd`), read the answer; attach again with the command left
    empty; restore the file and attach once more.
  - Expected: the attach that names a command is refused (`422`,
    `details.fields.reload_command`), naming the account and the command it needs through
    NOPASSWD sudo, and it created no binding row; the attach with no command is accepted,
    because a binding that names no command needs no grant. Nothing is left
    half-configured on the target.
  - Record the command the probe ran (it is `sudo -k -n -v`) and whether the one-line
    grant of PREP-07 was enough for it: a probe that needs a second grant contradicts the
    agreed sudoers shape (ATT-11) and must be reported, not worked around.

- [ ] **PROBE-03 — UCM checks no `sshd_config` of its own, at attach or afterwards** [LAB]
  - Check: break the drop-in (`RevokedKeys /nonexistent/revoked_keys`), run `sshd -t` by
    hand to see it fail, then attach with a reload command set and deliver. Restore the
    drop-in.
  - Expected: the attach is accepted while the account can write the paths and its sudo
    grant exists: the probe answers those two questions only and never runs `sshd -t`. The
    broken configuration surfaces as the delivery's `reload_exit` and its stderr, and sshd
    goes on running its old configuration. An attach that claims to have validated sshd's
    configuration is a defect, and so is a delivery that reports success while its reload
    command failed.

- [ ] **PROBE-04 — No exec on the target: host key read fails, manual pubkey works**
  - Check: attach `sftp1.example.net` (PREP-09) to the host CA. Then use the manual
    fallback and paste the output of `cat /etc/ssh/ssh_host_ed25519_key.pub` from that
    host into the fallback field.
  - Expected: UCM reports that it cannot read the host key because exec is refused —
    with that stated reason, not a transport error — and the manual public key is
    accepted so the binding can be created and the host certificate signed. Nothing
    is signed from a key UCM invented.

- [ ] **PROBE-05 — The probe leaves no files on the target**
  - Check: before the attach `find /etc/ssh/ssh_ca_keys -mindepth 1 | wc -l`; attach with
    all three artefact paths named; `ls -l /etc/ssh/ssh_ca_keys` for `*.ucm-probe` and for
    `*.ucm-tmp`; repeat the attach against an unwritable directory (PROBE-01).
  - Expected: the probe writes an empty `<path>.ucm-probe` in every non-empty path and
    removes it again — it never writes a real artefact path, so a probe cannot blank what
    sshd is reading. A refused attach leaves nothing behind, and neither a successful nor
    a refused save leaves a `.ucm-probe` or a `.ucm-tmp` remnant behind (`.ucm-tmp` is the
    delivery's temp name — FILE-04). The one case that can leave one is a host that
    refuses the removal itself: PROBE-07.

- [ ] **PROBE-06 — The host key is read from the target, not from UCM's memory**
  - Check: `ssh ucm-deploy@ssh1.example.net 'cat /etc/ssh/ssh_host_ed25519_key.pub'`
    and compare it, byte for byte, with the subject key of the certificate UCM signed.
  - Expected: the same key. The target's pinned host key of the deploy target
    (`host_key`, TOFU) is not modified by the host-key read, and `HostKey` in
    `sshd_config` is not touched.

- [ ] **PROBE-07 — A probe file the host will not give back stays there, and the save
  still succeeds** [LAB]
  - Check: make the removal fail on a stand where it can: hold `<path>.ucm-probe` open
    from a second session, or make the artefact directory append-only (`chattr +a`) after
    the write probe passes. Attach with all three artefact paths named, then `ls -l
    /etc/ssh/ssh_ca_keys` and read the binding.
  - Expected: the attach is accepted — the write that succeeded is what the probe was
    answering — and the leftover `<path>.ucm-probe` is still on the host, with the owner
    and mode the write gave it. UCM reports no failed save for a removal it could not do,
    and does not retry the attach forever over it. Record the leftover path: it is not an
    artefact, FILE-07 still has to hold for it, and a later delivery must not read it as
    one. Nothing here is settled by CI: the refusal is the host's own.

## 4. Automatic host certificate

- [ ] **HOST-01 — The host certificate appears in the list, linked to the target**
  - Check: Modules > Administration > SSH Certificates; filter by the host CA.
  - Expected: one certificate of type `host` with `source` marking it as UCM's own
    issue (`deploy`), and a visible reference to the deploy target (`deploy_target_id`
    and `deploy_target_name` on the record). Opening it names the target and adds
    `deploy_target_path`: the file the binding writes this certificate to. The list
    names the target, not the path — the path is on the binding and in the detail only.

- [ ] **HOST-02 — Principals are exact names**
  - Check: read the certificate's principals in UCM, and on the client run
    `ssh-keygen -L -f <the certificate UCM exported>`.
  - Expected: the FQDN, the short name and the configured aliases, each an exact
    string. No wildcard, no IP address, no empty principal.

- [ ] **HOST-03 — sshd is trusted by both names** [LAB]
  - Check: on the client, with the `@cert-authority` line from the stand block:
    `ssh -o CertificateFile=~/.ssh/id_ed25519-cert.pub user@ssh1.example.net exit`
    and the same against `ssh1`.
  - Expected: both connect, and `ssh -v` shows the server offering a certificate
    (`Server host key: ... certificate`). No "unknown host key" prompt, no
    `known_hosts` entry written for the plain key.

- [ ] **HOST-04 — A name outside the principals is refused — expected behaviour**
  - Check: connect by the alias PREP-03 left out of the principals (for example the
    bare IP or `ssh1.lan`).
  - Expected: the **client** refuses the server's host certificate
    (`Server host key ... is not in ...` / principal mismatch) and the connection
    fails. This is correct OpenSSH behaviour, not a UCM defect: it means the principals
    were chosen deliberately. The fix for the operator is to add that name to the
    binding, not to relax the check.

- [ ] **HOST-05 — Validity is what the binding said**
  - Check: compare `valid_from`/`valid_to` in UCM with the binding's validity, and
    `ssh-keygen -L` on the exported certificate.
  - Expected: the window equals the binding's validity (bounded by the CA's
    `max_ttl`), valid from is backdated a few minutes so a lagging server accepts it
    at once, and no re-sign happened outside that window.

- [ ] **HOST-06 — The certificate is in place where sshd reads it**
  - Check: `ls -l <HostCertificate path from PREP-08>`, `sshd -t`,
    `systemctl reload sshd`, then reconnect.
  - Expected: sshd presents the certificate. UCM wrote the certificate file, not
    `sshd_config`; the reload ran only because the binding's command asked for it
    (ATT-11).

- [ ] **HOST-07 — Re-attach and re-issue do not orphan the old certificate**
  - Check: detach the target, attach it again, and read the SSH certificate list.
  - Expected: the current certificate is the one sshd presents; the previous one is
    still listed under its CA with its serial, and deleting it follows section 9.
    Record the expiry behaviour of the host certificate as the release ships it: the
    old certificate must never silently disappear while the target still presents it.

## 5. Revocation and KRL delivery

- [ ] **KRL-01 — Revoking a host certificate queues the KRL to every binding of that CA**
  - Check: revoke the host certificate (SSH Certificates > Revoke Certificate, with a reason);
    read the CA card and `GET /api/v2/deploy/deliveries`.
  - Expected: one pending or delivered row per binding of that CA, event naming the
    KRL update; each target receives the regenerated KRL.

- [ ] **KRL-02 — Delivery runs no reload** [LAB]
  - Check: `systemctl show -p ActiveEnterTimestamp,ExecMainStartTimestamp sshd`
    before and after the delivery; read the delivery detail (no `reload_exit`), and
    `journalctl -u sshd --since -5min`.
  - Expected: the KRL file is replaced on the target, sshd's start timestamp is
    unchanged, no reload command ran, and the delivery reports success. This is the
    agreed behaviour and it must be **observed here**, not assumed.

- [ ] **KRL-03 — The next login with the revoked certificate is refused** [LAB]
  - Check: on the client, immediately after the delivery,
    `ssh -o CertificateFile=~/.ssh/id-cert.pub user@ssh1.example.net exit`;
    on the server read `journalctl -u sshd`.
  - Expected: the connection is refused at that attempt (`user ... not in
    revocation list` or the equivalent), with no reload, no cache wait and no second
    attempt succeeding. If the revoked key is accepted once more, that is a release
    blocker: the KRL is not effective without a reload.

- [ ] **KRL-04 — Several revocations of one CA do not multiply deliveries**
  - Check: revoke three certificates of one CA in a row, faster than the 30-second
    drain, then read the CA's delivery list.
  - Expected: one pending row per binding, reused (its event updated, attempts reset),
    not three. Each target ends up holding one KRL file containing all three
    certificates.

- [ ] **KRL-05 — The KRL on the target contains every revoked serial**
  - Check: `ssh-keygen -Q -l <the KRL path>` on the target, and
  `GET /api/v2/ssh/cas/<id>/krl` from UCM; compare the two.
  - Expected: the file on the target is byte-identical to what UCM serves, its version
    number is higher than the previous one, and it lists every revoked serial (and,
    for a serial 0 certificate, the key ID entry `ssh-keygen -k` produces).

- [ ] **KRL-06 — One KRL per CA, no per-host variant**
  - Check: attach the same CA to two targets, revoke a certificate, compare the files.
  - Expected: identical bytes on both targets. No per-binding KRL content, no CA KRL
    split by target.

- [ ] **KRL-07 — Status of each delivery is visible on the CA card**
  - Check: read the CA card after a revoke: last delivery per target, status, error
    text when one failed.
  - Expected: per-target status (pending / delivered / failed), attempts, the error of
    a failed one, and the timestamp of the last success.

- [ ] **KRL-08 — Deploy now works on an SSH CA binding**
  - Check: Deploy now on a binding; `ls -l` the artefacts and the KRL on the target.
  - Expected: 200, and a delivery row that completes in this request rather than
    waiting for the next scheduler pass.

- [ ] **KRL-09 — Retry works on a failed delivery**
  - Check: `POST /api/v2/deploy/deliveries/<id>/retry` on an exhausted (failed)
    delivery, with the target fixed.
  - Expected: the delivery goes back to pending, runs with attempts restarted, and
    ends delivered. A retry on a row that is not `failed` answers `400` and changes
    nothing.

- [ ] **KRL-10 — Revoking a user CA certificate updates the user bindings only**
  - Check: revoke a user certificate of the user CA.
  - Expected: the user CA's bindings get the KRL; the host CA's bindings get nothing.

- [ ] **KRL-11 — A CA with no bindings revokes without a delivery**
  - Check: revoke a certificate of an SSH CA that is attached to no target.
  - Expected: the revocation succeeds, the KRL is downloadable from the CA, and no
    delivery row is created.

- [ ] **KRL-12 — A revoke that beats the first delivery does not swallow the initial push**
  - Check: attach a target to a CA, and before the queue drains (within 30 seconds of the
    save) revoke a certificate of that CA; then read the delivery list and `ls -l
    /etc/ssh/ssh_ca_keys` on the target.
  - Expected: exactly one pending delivery for that binding, reused as KRL-04 describes it,
    `attempts` back to zero and no `last_error`, and it still writes the whole set the save
    queued: the CA public key is on the target, and for a host binding its host certificate is
    signed and written under the path the drop-in's `HostCertificate` names, after which the
    binding's reload command has run once. Coalescing a revoke into a pending *initial* push
    must not narrow the file set to the KRL alone — a target left with only a KRL, no
    `TrustedUserCAKeys` file and an empty `HostCertificate` path is a Failed item. A revoke
    that arrives after a delivered push queues a KRL-only delivery instead: it writes only
    `krl_path` and runs no command. The same shape holds for a revoke landing on a push that
    failed and waits to be retried: it keeps the full job, so Retry has nothing to restore.
    Automated: `TestRevokeBeatsTheFirstDelivery` in `backend/tests/test_ssh_ca_deploy.py`.

- [ ] **KRL-13 — A revoke that lands while a push is already running re-queues that push**
  - Check: press Deploy now on a bound target and, while that delivery is still running —
    after its KRL was generated, before the row is recorded as delivered — revoke a
    certificate of that CA. Then read the delivery list, the CA card and `ls -l
    /etc/ssh/ssh_ca_keys` on the target.
  - Expected: the running delivery ends `delivered`, and exactly one further pending
    `ssh.cert.revoked` row exists for that binding, with the normal retry budget: the push
    that finished cannot have carried a serial revoked after its KRL was generated, so the
    host is owed one more KRL write. Until that row drains, the CA card counts this target
    under "KRL missing on N targets" again — a card that stayed quiet here is a defect. An
    already pending row is refreshed, never duplicated (KRL-04). After the drain the KRL on
    the target carries every revoked serial (KRL-05). Automated:
    `TestRevocationDuringADelivery` in `backend/tests/test_ssh_ca_deploy.py`.

## 6. CA update and rotation

- [ ] **ROT-01 — A changed CA public key is rewritten on every bound target**
  - Check: publish the new key through the path the release ships (CA re-key or, if
    none exists, import a second host CA and move the bindings to it); read
    `/etc/ssh/ssh_ca_keys/*` on each target and compare with `GET /api/v2/ssh/cas/<id>/public-key`.
  - Expected: each target's CA public key file matches the CA's current published
    key. [LAB] Record which path the release actually ships: `update_ca` in
    `backend/services/ssh_ca_service.py` refuses to change key material today, so a
    rotation observed only through a second imported CA is the behaviour to write down.

- [ ] **ROT-02 — Dual trust during rotation** [LAB]
  - Check: with both keys in play, connect a client that trusts the old key and a
    client that trusts the new one; host certificates issued before and after the
    rotation.
  - Expected: nothing breaks at the moment of rotation: the old public key is not
    removed from a target while certificates signed by it are still valid and still
    used. The old key goes only after the administrator removes it, or after the
    binding moves.

- [ ] **ROT-03 — Editing CA policy does not re-push artefacts for no reason**
  - Check: change `max_ttl`, `allowed_principals` or a default extension on an attached
    CA; read the delivery list.
  - Expected: either nothing is queued, or one deliberate delivery per binding — not a
    push per edited field. A policy edit that changes nothing for the target must not
    rewrite its files.

- [ ] **ROT-04 — A host certificate re-signed under the new key works under the old clients**
  - Check: after ROT-01, issue a host certificate and connect with a client that trusts
    only the new key, and with one that trusts only the old key.
  - Expected: the new-key client connects; the old-key client is refused — which is the
    point of a rotation, and the operator must move clients before removing the old key.

## 7. Artefacts on the target host

- [ ] **FILE-01 — Owners and modes**
  - Check: `ls -l /etc/ssh/ssh_ca_keys`, `stat -c '%a %U:%G %n' /etc/ssh/ssh_ca_keys/*`.
  - Expected: the directory is 0755 and owned by the deploy service user; the CA
    public keys and the KRL are 0644 and world-readable; nothing secret (no private
    key of any kind) is present; no file is group- or world-writable.

- [ ] **FILE-02 — sshd can actually read them**
  - Check: as root `sshd -t`, then `journalctl -u sshd -n 40` after a reload.
  - Expected: `sshd -t` exits 0 with no output; no `Could not open ...`, no
    `error loading ...` line for a CA key or the KRL.

- [ ] **FILE-03 — SELinux / AppArmor** [LAB]
  - Check: `ls -Z /etc/ssh/ssh_ca_keys /etc/ssh/ssh_ca_keys/*` on an enforcing host;
    `sudo ausearch -m avc -ts recent` and `aa-status` on an AppArmor host, after a delivery.
  - Expected: the labels match what sshd reads for `/etc/ssh` content (record the
    labels you saw), no AVC denials, and no AppArmor complain/audit entries for sshd
    reading the directory. On a relabelled host the fix is `restorecon`, and the
    checklist records that as an operator step, not a UCM bug — unless UCM wrote the
    file at a path sshd's policy never reads.

- [ ] **FILE-04 — Writes are atomic**
  - Check: during a delivery, `ls -l /etc/ssh/ssh_ca_keys` repeatedly; after it, look
    for `*.ucm-tmp`.
  - Expected: a reader never sees a half-written file: each artefact appears as a
    complete file, renamed into place; no `.ucm-tmp` survives a success or a failure.

- [ ] **FILE-05 — A path whose directory is missing fails readably**
  - Check: attach with a path under a directory that does not exist.
  - Expected: the delivery fails naming the path, no directory appears on the target,
    and the failure is recorded as permanent or retried as the release defines it.
    UCM does not create directories over SFTP.

- [ ] **FILE-06 — Nothing UCM writes is world-writable or executable**
  - Check: `find /etc/ssh/ssh_ca_keys -perm /g+w,o+w -o -perm /u+x`.
  - Expected: empty output.

- [ ] **FILE-07 — Only public material reaches the target**
  - Check: `grep -l 'PRIVATE KEY' -r /etc/ssh/ssh_ca_keys`; `sudo -u ucm-deploy cat`
    each file.
  - Expected: no private key anywhere on the target. The CA's private key stays in
    UCM (or on its HSM token); the target holds only public keys, the host
    certificate and the KRL.

## 8. Delivery failures

- [ ] **FAIL-01 — Target unreachable: pending with the error text**
  - Check: `systemctl stop sshd` on the target (or drop the firewall), revoke a
    certificate, read the delivery list.
  - Expected: status `pending`, `last_error` naming the transport failure
    (`SSH connection failed: ...`), the target showing `last_failure_at` and a
    `failure_count` of 1, and one audit entry per failed attempt.

- [ ] **FAIL-02 — Backoff: 60 s first, capped at 3600 s, five attempts**
  - Check: keep the target down; read `attempts` and `next_attempt_at` after each
    pass (`GET /api/v2/deploy/deliveries`).
  - Expected: the gap grows 60 → 120 → 240 → 480 → 960 seconds and never exceeds
    3600; the delivery stops being retried after 5 attempts and becomes `failed`.
    The drain itself runs every 30 seconds.

- [ ] **FAIL-03 — An exhausted delivery is retryable by hand**
  - Check: after 5 failed attempts, start sshd again and press Retry (KRL-09).
  - Expected: the delivery runs again from attempt 1 and delivers the current
    artefacts; the CA card stops reporting a failure.

- [ ] **FAIL-04 — One dead target does not block the others**
  - Check: revoke a certificate of a CA bound to two targets, one of them down.
  - Expected: the live target is delivered on the next pass while the dead one sits in
    backoff. No queue-wide stall.

- [ ] **FAIL-05 — The queue drains every 30 seconds, on the leader only in HA**
  - Check: single node — time a revoke to a delivery. HA — `GET /api/v2/system/service/status`
    and the nodes' logs while one node is stopped. See [docs/HA.md](HA.md) and
    [ADMIN_GUIDE.md > HA mode](ADMIN_GUIDE.md#ha-mode-scheduler-and-startup).
  - Expected: the pass runs within about 30 seconds of the event; in HA exactly one
    node runs it (the leader) and no artefact is pushed twice.

- [ ] **FAIL-06 — A transport failure never leaves a half-configured target**
  - Check: kill the delivery mid-write (`systemctl stop sshd` during a push), then
    recover and re-deliver; read every artefact's content and mode.
  - Expected: after recovery each file is either the old complete version or the new
    complete version, never a truncated one, and a re-push repairs every path.

- [ ] **FAIL-07 — A removed binding queues nothing further**
  - Check: remove a binding while its target is down; wait past the last backoff.
  - Expected: no new delivery for that binding, no `Binding missing` attempts piling
    up in the history.

## 9. Deletion and blockers

- [ ] **DEL-01 — Deleting an SSH CA that has bindings is refused**
  - Check: `DELETE /api/v2/ssh/cas/<id>` (or the CA card's Delete) on an attached CA.
  - Expected: 409 whose message names the bound targets and says to remove the SSH CA
    deployment bindings first. The CA is still there afterwards.

- [ ] **DEL-02 — Deleting an SSH CA that has certificates is refused**
  - Check: `DELETE /api/v2/ssh/cas/<id>` on a CA with issued certificates and no bindings.
  - Expected: 409 naming the number of certificates issued by it. This already holds
    today; the new binding blocker must not have replaced it.

- [ ] **DEL-03 — A valid, non-revoked SSH certificate cannot be deleted**
  - Check: `DELETE /api/v2/ssh/certificates/<id>` on a valid host certificate; then on
    a revoked-but-unexpired one.
  - Expected: both 409. The valid one says revoke it first; the revoked one names the
    date it may be deleted (`A revoked SSH certificate stays in the KRL until it
    expires`), because dropping the row would take the revocation out of the KRL.

- [ ] **DEL-04 — A binding alone is removable**
  - Check: remove the SSH CA binding (not the target), then revoke a certificate of that CA.
  - Expected: the binding goes, the CA stays, and no delivery is queued for the removed
    binding. Removing the binding is the documented way to free a CA for deletion.

- [ ] **DEL-05 — Deleting the target cascades its bindings and history; files stay**
  - Check: delete the deploy target; then `ls -l /etc/ssh/ssh_ca_keys` on that host,
    and `ssh user@<target> exit`.
  - Expected: the target, its SSH CA bindings, its X.509 bindings, its CRL bindings and
    their delivery history are gone from UCM. **The files on the host stay, and sshd
    keeps trusting the CA: there is no "undeploy".** Record this as expected behaviour
    and state in the release notes that the operator removes the drop-in and the files.

- [ ] **DEL-06 — SSH CA deletion has one route, and the X.509 bulk route is untouched**
  - Check: `grep -rn "bulk" backend/api/v2/ssh/` (empty in this release), then `POST` the
    X.509 bulk delete route (`/api/v2/cas/bulk/delete`) with one CRL-bound CA and one free
    CA in the same id list.
  - Expected: no bulk route exists for SSH CAs, so DEL-01's refusal can only be met through
    `DELETE /api/v2/ssh/cas/<id>`; record that as shipped behaviour. The SSH CA blocker lives
    in `SSHCAService.delete_ca` through `services/deploy/ssh_ca.binding_blocker`, not in
    `backend/services/deletion_blockers.py` (that module carries the X.509 CA blockers only,
    and it cannot see an SSH CA binding). The X.509 bulk route still refuses what its unit
    route refuses — the blocked CA in the per-item `failed` list with its reason, the free one
    deleted, nothing half-deleted.

- [ ] **DEL-07 — No dangling reference is left behind**
  - Check: after DEL-04 and DEL-05, read `GET /api/v2/deploy/deliveries`, the SSH CA
    card and the certificate's deploy section; then restart UCM.
  - Expected: no row names a deleted binding or target, no screen errors, and no
    traceback in `/var/log/ucm/error.log` at the next start.

## 10. Backup and restore

- [ ] **BAK-01 — The archive carries the SSH CA bindings**
  - Check: attach a target to a host CA, issue a host certificate, take a backup
    (Settings > Backup), and list the archive's tables/sections against
    `backend/services/backup/manifest.py`.
  - Expected: the new SSH CA ↔ deploy target binding table is in the archive next to
    `ssh_cas`, `ssh_certificates`, `deploy_targets`, `deploy_bindings` and
    `crl_deploy_bindings`. A section missing from the manifest is a release blocker.

- [ ] **BAK-02 — Restore onto a clean installation keeps the links**
  - Check: restore the archive on an empty UCM of the same version (fresh data
    directory, `master.key` of the same installation), then read the target, the CA
    card and the host certificate.
  - Expected: the binding is there, its target, CA and host certificate references
    resolve, and the host key pin of the target survived. Delivery history may be
    absent (the queue is not an export); the binding itself is.

- [ ] **BAK-03 — After a restore the artefacts re-push without re-entering anything**
  - Check: on the restored instance press Deploy now on the restored binding.
  - Expected: the push succeeds with the credentials restored from the archive — no
    field is empty, no "save the target again" is needed.

- [ ] **BAK-04 — `master.key` is the fixed point**
  - Check: restore the same archive twice: once with the original `master.key` (or
    `KEY_ENCRYPTION_KEY`) present, once on an installation with a different one.
  - Expected: with the right key everything decrypts. With a different key the target's
    private key and every SSH CA private key are unreadable and UCM says so instead of
    silently offering broken targets. See
    [ADMIN_GUIDE.md > Private-Key Encryption](ADMIN_GUIDE.md#private-key-encryption-kek-and-dek):
    the KEK is the secret to back up, and the release notes must not soften that.

- [ ] **BAK-05 — Restore of a 2.254 archive that has no SSH CA bindings**
  - Check: restore a 2.254 archive onto this release.
  - Expected: it restores with no SSH CA bindings and no error; the SSH CAs it carries
    are simply unattached. Nothing in the new tables is invented for rows that never existed.

- [ ] **BAK-06 — A restore that has to revoke certificates queues their KRL pushes**
  - Check: bind a target to an SSH CA. Take a backup that carries two certificates of that
    CA sharing one serial, the older of them revoked, and restore it in merge mode onto an
    installation where the younger holder is still valid — the pair `UPGRADE.md` describes
    for a shared serial. Before the queue drains, read the delivery list and the CA card.
  - Expected: the restore revokes the valid holder with the revoked one (the KRL revokes by
    serial, so it was revoked already in everything but the row), and queues exactly one
    pending `ssh.cert.revoked` delivery per bound target of that CA, `triggered_by` is
    `system` and the retry budget is the normal one. The CA card counts that target under
    "KRL missing on N targets" until the row is delivered. A restore of the same archive
    that revokes nothing queues nothing: revocations queue a KRL push, restoring a bound CA
    does not. A 2.254 archive, and the 2.254 upgrade itself, cannot hit this and queues
    nothing — its SSH serial step runs while the binding table does not exist yet, because
    the migration that creates it (301) comes after the pivot (300). Automated:
    `backend/tests/test_ssh_ca_deploy_restore.py`.

## 11. Regression of what already worked

- [ ] **REG-01 — X.509 deploy bindings behave as before**
  - Check: on the same target that now also carries SSH CA bindings, deploy an X.509
    certificate (cert / key / full chain paths), renew it, read the delivery history.
  - Expected: paths, modes (0644 public, 0600 key), chain variant handling and the
    atomic write are unchanged; the SSH CA artefacts are not disturbed by the push.

- [ ] **REG-02 — CRL delivery is unchanged**
  - Check: renew a CRL of an X.509 CA bound to a target (`crl.updated`), including a
    PEM bundle with parent CRLs, and press Deploy now.
  - Expected: one delivery per binding, coalesced while pending, DER refuses
    `include_parent_crls`, the CA deletion blocker for a CRL-bound CA still answers 409.

- [ ] **REG-03 — Test connection still works on every target kind**
  - Check: Test connection on an SSH target, on the same-host preset, and on an HTTP
    target.
  - Expected: `Connection and SFTP OK` (SSH), the HEAD probe answer (HTTP), a pinned
    host key on first success, and a refusal that fails closed when the presented host
    key differs from the pin.

- [ ] **REG-04 — Host key pinning still fails closed**
  - Check: replace the target's host key, run Test connection.
  - Expected: 409 with `Host key verification failed: ... does not match the pinned
    one`, and the reset path the UI offers. The new host-key read of section 3 must not
    have widened this.

- [ ] **REG-05 — The queue drain interval is unchanged (30 s, leader in HA)**
  - Check: as FAIL-05, for a certificate and a CRL binding.
  - Expected: both drain on the same `deploy_delivery` scheduler task, at 30 seconds,
    one node in HA.

- [ ] **REG-06 — Bindings left behind by a renewal still report and reattach**
  - Check: renew a deployed certificate whose key UCM does not hold, read the
    left-behind state and press reattach.
  - Expected: unchanged from before this feature; the new SSH CA binding type did not
    take the state away from X.509 bindings.

- [ ] **REG-07 — HTTP targets unaffected**
  - Check: push to an HTTP target with a templated body.
  - Expected: template validation, header encryption, `key_pem` opt-in and the SSRF
    rules behave exactly as `docs/API_REFERENCE.md` documents them.

- [ ] **REG-08 — All 10 interface languages carry the new strings**
  - Check: `node scripts/check-i18n-sync.js` at the repository root.
  - Expected: it reports no missing key for `de`, `en`, `es`, `fr`, `it`, `ja`, `pt`,
    `ru`, `uk`, `zh`. A language left untranslated is a Failed item.

- [ ] **REG-09 — Built-in help parity en / fr / ru / zh**
  - Check: `cd frontend && npm test` (it runs the help parity test), and open the
    changed help page in all four languages.
  - Expected: each translated page carries the English structure — same entries per
    section, same item types, same tips and warnings. The other six languages show the
    English text, which is expected.

- [ ] **REG-10 — The existing SSH screens still work**
  - Check: setup script download (`type=user` and `type=host`, unix and windows),
  `GET /api/v2/ssh/cas/<id>/krl`, `.../public-key`, signing a host key by hand,
    `POST /api/v2/ssh/certificates/verify`, the SSH dashboard counts.
  - Expected: unchanged. The setup script still refuses to edit anything UCM is not
    allowed to edit, and the shared-serial handling of 3.0 still marks and revokes as
    `UPGRADE.md` describes.

- [ ] **REG-11 — Permissions are unchanged**
  - Check: with a Viewer, an Operator and an API key that holds `read:deploy` only,
    read and try to change an SSH CA binding.
  - Expected: deploy stays admin-only for writes and deletes, `read:deploy` reads,
    SSH CA reads and writes follow `read:ssh_cas` / `write:ssh_cas` / `delete:ssh_cas`,
    and a missing scope answers 403 naming it.

- [ ] **REG-12 — Audit trail of the new actions**
  - Check: attach, detach, deploy now, retry, host certificate issue, revoke.
  - Expected: each writes one audit entry naming the resource and the actor, and the
    audit chain verification (`GET /api/v2/audit/verify`) still reports the chain intact.

- [ ] **REG-13 — A reader who may not read deployments sees no targets**
  - Check: with a Viewer and an Operator, neither of which holds `read:deploy`, read
    `GET /api/v2/ssh/cas`, the list of SSH certificates and the detail of a host
    certificate UCM signed for a bound target, and open that CA's bindings list.
  - Expected: in the certificate's list entry and detail `deploy_target_id` and
    `deploy_target_name` are `null`, and `deploy_target_path` is not present at all — not
    empty, absent. The CA list carries `deploy_targets_total` 0, `krl_undelivered_targets`
    0 and `deploy_defaults` null, and the KRL badge of the SSH CA page shows nothing rather
    than a number invented for a role that may not read it. The bindings list answers 403
    naming `read:deploy`. The same reads by an account that does hold `read:deploy` are
    unchanged, and the Deployment block of the CA screen is not rendered at all. Automated:
    `TestWhatADeployReaderSees` in `backend/tests/test_ssh_ca_deploy.py`.

## 12. Installation upgrade paths

Run each on a **copy** of a real database, never on the live installation.

- [ ] **UPG-01 — 2.254 → 3.0 on a copy (SQLite)**
  - Check: start 2.254 on the copy once, install the release under test, start it;
    then `sqlite3 <data>/ucm.db "SELECT name FROM _migrations ORDER BY id"`.
  - Expected: migration `300` (the 2.254 upgrade) and `301` (this feature's schema)
    both appear, nothing else is missing, the boot log shows each step with its
    duration and no line starting with `✗`, and the existing certificates, SSH CAs and
    deploy targets are intact. The `ucm.db.2.254-before-3.0` copy exists (see
    `UPGRADE.md`, *A copy of the SQLite database before the upgrade*).

- [ ] **UPG-02 — 3.0 → 3.0 on a copy (only the new migration)**
  - Check: take a 3.0 database that already applied `300`, install the release under
    test, start it, read `_migrations`.
  - Expected: exactly the new migration (301) is added. `300` and the `_from_2_254`
    steps are not replayed. On PostgreSQL the same run applies the same set: the new
    migration carries `pg_compatible = True` and is safe to run twice.

- [ ] **UPG-03 — The new schema only adds**
  - Check: read the migration against
    [CONTRIBUTING.md > Migrations and rolling updates](../CONTRIBUTING.md#migrations-and-rolling-updates),
    and run `cd backend && pytest tests/test_migration_expand_only.py`.
  - Expected: a new table, a nullable `deploy_target_id` column on the SSH certificate,
    and indexes only — no dropped or renamed table or column, no `NOT NULL` without a
    default, no new constraint on columns the previous version writes, no deleted rows.
    If the migration carries `requires_full_stop`, the release notes must say so.

- [ ] **UPG-04 — Rolling HA update from the previous 3.0**
  - Check: two nodes on one PostgreSQL, one still on the previous 3.0, then upgrade the
    first. See [docs/HA.md > Upgrading](HA.md#upgrading).
  - Expected: the un-migrated node keeps working against the new schema; the node on
    the new version serves the SSH CA screens; no node refuses to start.

- [ ] **UPG-05 — Rollback on a copy**
  - Check: stop UCM, put the pre-upgrade `ucm.db` copy back, remove the `-wal` and
    `-shm` files left by the new version, restore `/etc/ucm/master.key` of that point,
    reinstall the previous version and start it. Follow the *Rollback* recipe of
    `UPGRADE.md`.
  - Expected: the previous version starts on that copy, reads every encrypted key with
    that `master.key`, and shows no SSH CA bindings (they did not exist). Everything
    written by the new version is gone, which is what a rollback means: write the date
    of the copy in the record.

- [ ] **UPG-06 — Container upgrade on Unraid**
  - Check: on the Unraid installation, update the image tag, keeping the same
    application data share, the same `/etc/ucm` and `/opt/ucm/data` mappings, the same
    env entries and the same device passthroughs (HSM or TPM device mappings, if the
    installation has any — see `docker-compose.hsm.yml` for what a device mapping is
    for). Start it, then run the smoke of `RELEASE_TESTING.md`.
  - Expected: the same `/etc/ucm` and `/opt/ucm/data` volumes are mounted (without
    them the master key is destroyed and every encrypted key is unrecoverable —
    `RELEASE_TESTING.md`, *Master key persistence*), the env is unchanged, each device
    that was mapped is still mapped and readable inside the container, the upgrade
    needs `UCM_ACCEPT_MAJOR_UPGRADE=3` only when the data last started on 2.254, and
    the SSH CA bindings work after the restart. Record the Unraid template's
    host-path values: an upgrade that re-created the container with a fresh empty
    share is a Failed item, not a UCM bug.

- [ ] **UPG-07 — Fresh install has the schema**
  - Check: install the release on an empty data directory, SQLite and PostgreSQL.
  - Expected: the new tables exist from the first start, the migration registry lists
    the new migration, and `GET /api/v2/health` reports the version exactly.

## 13. Known limitations, verified as behaviour

These are not defects. Each item confirms the limitation is real, is enforced in a way
the operator can see, and is stated in the release notes.

- [ ] **LIM-01 — Windows clients of host certificates** [LAB]
  - Check: distribute the host CA trust to a Windows client through GPO or Intune
    (the only supported way), then connect that client to the target.
  - Expected: the Windows client trusts the host certificate only after the policy
    lands, and UCM ships nothing for it: the Windows setup script
    (`platform=windows`) configures the Windows OpenSSH **server**, not its clients.
    The release notes must say that client-side trust is an administrator's job.

- [ ] **LIM-02 — FIPS mode refuses an Ed25519 deploy key and an Ed25519 pinned host key**
  - Check: on the `-fips` image or a FIPS-mode package, create an SSH target (UCM
    generates ECDSA P-256 where it would have generated Ed25519), import an Ed25519
    target key, and test a target whose pinned host key is Ed25519. Also attach a
    target to an Ed25519 SSH CA.
  - Expected: each refusal is explicit and names the fix (an ECDSA or RSA host key on
    the target, re-pin the host key, or keep the Ed25519 CA outside FIPS mode). The
    FIPS readiness check lists them (`deploy.ssh_eddsa_key`,
    `deploy.ssh_eddsa_host_key`, `ssh_ca.eddsa_key`). Nothing is silently downgraded.

- [ ] **LIM-03 — A host CA's KRL is read by clients, not by the server** [LAB]
  - Check: deliver the host CA's KRL to the target, then check where it is actually
    consulted: `ssh-keygen -Q -f <KRL on the client> <host certificate>` and, on the
    target, `ssh -v user@ssh1.example.net exit`.
  - Expected: revoking a host certificate takes effect for a **client** that holds the
    KRL and the `RevokedKeys` (or client-side equivalent) the release documents. A
    server-side `RevokedKeys` entry for a host CA is not what makes the revocation
    bite. Record the exact client-side step an administrator must take; if the release
    ships no client-side KRL path at all, say so in the release notes.

- [ ] **LIM-04 — `internal-sftp` and chroot targets get the fallback only**
  - Check: run the full attach against `sftp1.example.net` (PREP-09): artefact push,
    host-key read, reload attempt.
  - Expected: the artefacts arrive; the host key is not read (exec refused) and the
    manual public-key fallback is the way to complete it; the reload command is refused
    or not offered, and the answer says which. Nothing pretends the target was
    reconfigured.

- [ ] **LIM-05 — UCM never edits `sshd_config`, including on failure**
  - Check: after every failure path above (PROBE-01, PROBE-02, FAIL-01, FAIL-06),
    `stat -c '%y %U %n' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*` and
    `diff` against the copy taken at PREP-08.
  - Expected: identical, byte for byte, root-owned. Directive changes belong to the
    setup script and the drop-in (PREP-08) only.

- [ ] **LIM-06 — The target account is a real privilege boundary**
  - Check: read the deployment help text and the release notes' wording about the
    target account; then check what that account can actually do on the target
    (`sudo -l -U ucm-deploy`, `ls -ld /etc/ssh/ssh_ca_keys`).
  - Expected: the account writes only the canonical directory and reloads sshd —
    nothing else. The documentation must not describe it as a read-only account, and
    the release notes must state what the account can do, because UCM holds its key.
    `deploy.helpDescription` and the binding's own hint (`sshDeploy.reloadCommandPerms`)
    both say write access to the deployment paths **and** password-less sudo for the one
    reload command the binding names: text that promises write access only, or calls the
    account read-only, is a Failed item.

- [ ] **LIM-07 — The save proves the account has a password-less grant, not that this
  command is the granted one** [LAB]
  - Check: bind with a reload command the sudoers file does not name
    (`sudo systemctl restart sshd` while the grant of PREP-07 names only
    `systemctl reload sshd`), save, then deliver.
  - Expected: the save is accepted — the probe runs `sudo -k -n -v`, which answers
    whether the account has a password-less grant at all, not whether this command
    string is the granted one. The delivery then fails with sudo's refusal, its
    `reload_exit` and stderr in the delivery detail, and the binding reports a failed
    delivery. The operator's fix is to grant the command the binding names. Nothing may
    claim the command itself was verified at save.

## Automated gate before the manual run

Run these at the repository root first. A red gate stops the manual run: fix it, then
start this checklist from section 1.

```bash
ruff check backend/ --select F --ignore F401,F541,F811,F841
bandit -r backend/ -lll
cd backend && pytest --tb=short --durations=30 -m "not ha and not slow"
cd frontend && npm test
node scripts/check-i18n-sync.js
# The PostgreSQL halves, on a real server, as the CI jobs run them. The two URLs are
# separate on purpose: the marked tests build their own engines, the application runs on
# the third (docs/testing/postgres-harness.md).
cd backend && UCM_TEST_POSTGRES_URL=... UCM_TEST_PG_URL=... \
  pytest --tb=short -m postgres tests/
cd backend && UCM_TEST_POSTGRES_URL=... UCM_TEST_PG_URL=... pytest --tb=short \
  tests/test_backup_cross_installation.py tests/test_restore_reference_resolution_pg.py \
  tests/test_database_migration_matrix.py tests/test_database_migration_scale.py \
  tests/test_database_admin.py tests/test_migration_runner_pg.py \
  tests/test_scep_intune_ca_lock_pg.py
cd backend && for s in 1 2 3; do UCM_TEST_APP_PG_URL=... \
  pytest --tb=short $(../scripts/ci/shard-tests.sh $s 3 ../scripts/ci/pg-app-tests.txt); done
```

- [ ] **GATE-01 — Backend lint and high-severity bandit findings**
  - Expected: both exit 0. Any bandit finding at `-lll` is read before it is dismissed,
    and this feature moves credentials and executes remote commands: a dismissed
    finding needs its reason written here.

- [ ] **GATE-02 — Backend suite, HA and slow tests deselected**
  - Expected: green, no failure, no new skip that hides a feature gap (`-rs` shows the
    skip reasons when you want them). Read every failure against the same command run on
    the previous release's tag: only a failure the old tag does not have belongs to this
    feature.

- [ ] **GATE-03 — PostgreSQL matrix, all three halves**
  - Expected: green with the URLs of the block above on a real PostgreSQL. The new tables
    and the migration exist on both backends, or this gate is where it shows. Three halves
    must be green, not the marked one alone: `pytest -m postgres tests/`, the opt-in files,
    and the three application shards of `scripts/ci/pg-app-tests.txt` with
    `UCM_TEST_APP_PG_URL` set — those shards are where a fresh `SERIAL` id column and an
    upgraded one are told apart. A stand whose interpreter lacks `gevent`, `sqlalchemy` or
    `jks` for the isolated children (`tests/test_background_jobs_process.py`,
    `tests/test_mtls_trust_anchor.py`, `docker/ha-database.sh`) is not this feature's
    failure: record which half of CI the stand cannot run and say so in the release record.

- [ ] **GATE-04 — Frontend suite (includes help parity)**
  - Expected: green.

- [ ] **GATE-05 — i18n sync across all 10 locales**
  - Expected: no missing key.

## Recording the run

Copy this table into the release record; one row per item ID.

| Item | Passed / Failed | Version | Backend | Deliverable | Note (exact error text on a failure) |
|------|-----------------|---------|---------|-------------|--------------------------------------|
| PREP-01 | | | | | |

A release candidate is not fit for the stable tag while any item above is Failed, and
the release record must carry, besides the table: the version of UCM, the version of
the target's sshd, the target's operating system, and whether SELinux or AppArmor was
enforcing during the run.
