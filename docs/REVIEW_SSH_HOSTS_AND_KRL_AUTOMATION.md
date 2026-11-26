# Review: SSH Managed Hosts / KRL Automation (`feat/ssh-managed-hosts`)

**Дата:** 2026-11-21
**Проверяемая версия:** `143b1f9f0..1dacc1d9c` (upstream/dev + 5 коммитов: `fa5c39af5`, `54fc42c5f`, `b6140155c`, `aa90c1737`, `1dacc1d9c`), 46 файлов, +4407/−32
**ТЗ:** `docs/SPEC_SSH_HOSTS_AND_KRL_AUTOMATION.md`

## Статус стадий pipeline

| Стадия | Вердикт |
|---|---|
| Tester (2 цикла) | **ок** — 69 backend + 12 frontend новых тестов зелёные; полный pytest = baseline (13 pre-existing JKS/DNS-провалов); vitest 2543 passed; lint 0 errors; i18n sync. Дефекты D1 (payload `auto_renew`) и D2 (events при revoke-cert) закрыты коммитом `b6140155c`, подтверждено независимыми тестами. D3 (loopback `callback_url`) — принятое ограничение (SSRF-политика как у webhook endpoints), D4/D5 — NOTE. |
| Reviewer | **REJECT** — 2 BLOCKER, 9 IMPORTANT. После закрытия B1+B2 заявлено готовность к APPROVE WITH NOTES. |

## BLOCKER (обязательны до релиза)

### B1. Агент никогда не прописывает `HostCertificate` и пишет сертификат не туда
`backend/services/ucm_agent_scripts.py` (`CERT_FILE="$(find_host_pubkey)-cert.pub"` → `ssh_host_ed25519_key.pub-cert.pub`; в sshd_config агент гарантирует только `TrustedUserCAKeys`/`RevokedKeys`).
- Чистый сервер: сертификат подписан и лежит в файле, который sshd не читает → хост не предъявляет сертификат клиентам; эффект §3.1/§5 отсутствует при «Valid» в UI.
- Сервер, ранее настроенный Host CA setup-скриптом (`HostCertificate .../ssh_host_ed25519_key-cert.pub`): агент пишет в другой файл → sshd отдаёт старый сертификат → через TTL хост перестанет доверяться, хотя UI «продлил успешно».
- PowerShell-версия агента использует правильный путь — два агента противоречат друг другу.

**Минимальная правка:** `CERT_FILE="${CERT_FILE:-${pubkey%.pub}-cert.pub}"`; в `enroll()` — `sshd_ensure_line HostCertificate "$CERT_FILE"`; расширить smoke-тест (прогон без override + проверка трёх директив).

### B2. `sshd_ensure_line` молча не работает при уже существующей директиве
`grep -qi "^RevokedKeys "` на строку другой политики → агент не добавляет и не предупреждает; KRL пишется в файл, который sshd не читает (OpenSSH берёт первое значение директивы) → мгновенный отзыв не применяется, UI показывает «KRL Synced». То же для `TrustedUserCAKeys`. Нет бэкапа sshd_config и проверки `sshd -t` с откатом (домашние setup-скрипты репо делают и то, и другое).

**Минимальная правка:** читать существующее значение директив; при чужом пути — писать в существующий путь (агент поддерживает `KRL_FILE`) с явным предупреждением, иначе `die`; `cp -a sshd_config{,.bak}` + `sshd -t || restore`.

## IMPORTANT

1. **I1. «Reinstall» не работает:** installer пишет конф только если файла нет → новый bootstrap-токен игнорируется, enroll ничего не делает, UI показывает «New install token issued». Также при неудачном первом enroll таймеры не устанавливаются.
2. **I2. Mode A (callback wake-up) не реализован на агенте:** UCM шлёт HMAC-POST, но агент не поднимает слушателя; HMAC-ключ агенту недоступен. Либо добавить listener, либо убрать `callback_url` из мастера и зафиксировать Mode B (long-poll) как единственный путь.
3. **I3. `revoke_cert` отправляет в KRL только текущий сертификат:** старые host-сертификаты хоста (до TTL) остаются валидными → клиенты, кешировавшие старый сертификат, продолжают принимать скомпрометированный хост. Нужно отзывов всех невзятых сертификатов публичного ключа хоста.
4. **I4. Fan-out усиление из `/renew`:** одна агентская продлевка порождает wake-POST всем хостам CA; LAN-байпас flask-limiter (`RATE_LIMIT_TRUST_LAN` по умолчанию) снимает лимиты с агентских вызовов; вместо `utils.ssrf_protection.safe_request_post` (DNS-rebind pinning) — голый `requests.post` с валидацией URL только при создании. Wake — только целевому хосту + `safe_request_post`.
5. **I5. Новые публичные пути не зарегистрированы:** `utils/public_endpoints.py` не знает `/ssh/krl/`, `/ssh/agent-setup`, `/ssh/agent-runner` → при включённом admin-allowlist они (и агентские `/api/v2/ssh/hosts/*`) получают 403 для хостов вне админ-подсетей; rate-limiter бакет `_default` вместо протокольного.
6. **I6. Удаление Host CA оставляет осиротевшие managed hosts → 500:** `delete_ca` блокирует только по сертификатам; `host_ca=None` даёт `AttributeError` в `cert_status`/`_sign_host_cert`. Одна проверка в `delete_ca`.
7. **I7. Частичный отказ enroll:** `get_next_serial()` коммитит до подписи; падение подписи оставляет `active`-хост со spent-токеном и без сертификата. Подписывать до записи хост-полей либо rollback в except.
8. **I8. Ре-enroll молча подписывает старый публичный ключ:** после переустановки с новыми host-ключами хост получит сертификат на старый ключ → клиенты отклонят хост. Заменять ключ или 409.
9. **I9. `wait`: давление на пул соединений + busy-loop агента:** 15 одновременных long-poll'ов (пул 5+10) вызывают QueuePool-таймауты UI; `expire_all()` на удалённом хосте → `ObjectDeletedError` 500; агент без `--fail`/sleep крутит бессрочный цикл при 401/429. Точечный refresh/SELECT + `sleep`/`curl --fail` на агенте.

## MINOR (сводка)

- `current_cert_id` без `ondelete` → висячий FK / IntegrityError после удаления истёкшего сертификата.
- Фронт видит только первые 25 хостов (без серверной пагинации/поиска).
- `renew` не проверяет порог `renew_threshold_percent` на сервере (бесконечные перевыпуски живым токеном).
- `rotate_token` разрешён на `pending`-хосте.
- `last_krl_sync_at` фиксирует «UCM сказал синхронизироваться», а не факт загрузки KRL агентом.
- `sshHosts.subtitle` без `_one/_other` (конвенция i18n репо).
- Иконочные кнопки: `title` вместо `aria-label` (доступность).
- Избыточный `CREATE UNIQUE INDEX` на `token_hash` в миграции (дублирует UNIQUE в CREATE TABLE; расхождение create_all vs upgrade).
- `enqueue_deliveries`: `ca_refid=None` проходит через CA-фильтрованный endpoint (существующее поведение, заметно для `ssh_host.*`).

## NOTE / принятые ограничения (без правок)

- D3: loopback `callback_url` запрещён SSRF-политикой (как webhook endpoints) — агент регистрировать по LAN-адресу.
- Токены: 192 бита энтропии, поиск по SHA-256 через уникальный индекс — timing-оракула нет; salt не нужен.
- ETag/кэш KRL корректны между воркерами (ETag = `krl_version` из БД, единый коммит с отзывом).
- Guard rails сквозные подтверждены (force-renew не обходит revoked, delete заблокирован, pending с живым bootstrap удаляем).
- Миграция 138 идемпотентна на обоих диалектах; PG-DDL коммитит раннер.
- Конфиг агента `KEY=value` вместо INI-секций ТЗ §5 — функционально эквивалентно; однострочник `/ssh/agent-setup?token=…` вместо формы ТЗ §6.2 — лучше ТЗ.
- Эксплуатационные предупреждения для checklist: при `mTLS REQUIRED` на 8443 агентский pull работать не будет; агент не поддерживает CA-pinning (`--cacert`) → self-signed HTTPS UCM требует установки CA-сертификата на хосте; агентские `enroll/check-in/renew` входят в протокольное исключение, поэтому в safe-mode они отвечают 200, а не 503 (продление не останавливается во время инцидента — принято осознанно, см. §10 чек-листа).
- Windows-агент: wake-стрима нет (timer 15 мин, `shortcut:` в коде); PowerShell не линтился (нет pwsh) — ручной пункт в checklist.
- Фронт-тест гейта описывает роль `write:ssh`, которой бэкенд всё равно выдаёт `ssh_cas`-права — тест уточнить.

## Что проверялось и чем

- Tester: `backend/tests/test_ssh_managed_hosts.py`, `test_ssh_krl_public.py`, `test_migration_138_ssh_managed_hosts.py` (+PG-маркер), `test_ucm_agent_scripts.py` (sh -n/bash -n + offline smoke POSIX-агента на mock http.server), `SSHHostsPage.lifecycle.test.jsx`, `AppRoutes.sshHostsGate.test.jsx`, `ssh-hosts.service.payload.test.js`; полный гейт CI (`pytest -n 4 --dist loadfile`, `vitest --run`, lint, `check-i18n-sync.js`) = baseline.
- Reviewer: статический ревью diff + семантика sshd_config («первое значение директивы»), сравнение с `api/v2/ssh/setup_scripts.py`, `utils/public_endpoints.py`, `security/rate_limiter.py`, `config/settings.py` (пул), `gunicorn_config.py` (gevent/mtls). Реальные прогоны — по отчёту Tester; поведение живого sshd не проверялось.

## Обязательное условие мержа

Закрыть B1 и B2 (плюс I1–I9 желательны в этом же цикле, I5/I6 — фактически обязательны для публичных сценариев), затем повторные гейты Tester + вердикт Reviewer (APPROVE / APPROVE WITH NOTES). До закрытия B1 фича в релизе выглядит рабочей в UI, не меняя ни один сервер.

---

## Follow-up 2026-11-22: ответ мейнтейнера (#451) и закрытие B/I/M-пунктов

Ответ мейнтейнера (issue #451): PR на `dev`, KRL-часть отдельным PR, enrollment вторым,
**push wake-up запрещён** («UCM reaching out to hosts goes against the pull-only,
agentless model. A short polling interval against the cached KRL is enough»).

Вырезано из реализации (commit of this cycle): `callback_url` (колонка, API-валидация,
SSRF-проверка, поле мастера в UI, i18n-ключи), `wake_callback_hosts` (HMAC-POST Mode A)
и все его вызовы, long-poll `GET /api/v2/ssh/hosts/wait` (Mode B) — агент живёт только
на таймере 15 минут. Тесты удалённых механик удалены; SPEC дополнен разделом 0.

Статус пунктов ревью:

| Пункт | Статус | Как закрыт |
|---|---|---|
| B1 | закрыт | `ucm-ssh-agent`: сертификат пишется в `<hostkey>-cert.pub` (путь приватного ключа без `.pub`), директивы `HostCertificate`/`TrustedUserCAKeys`/`RevokedKeys` прописываются при enroll; новый smoke-тест `test_runner_derives_cert_path_from_host_key` без `CERT_FILE` |
| B2 | закрыт | `ensure_directive` (только enroll) дописывает директиву с backup'ом; чужое значение директивы = цель записи (агент пишет туда, backup чужого файла); config-правка валидируется `sshd -t` с откатом на backup и без reload; run-режим sshd_config не трогает вообще (тот же тест) |
| I1 | закрыт | installer всегда обновляет `BOOTSTRAP_TOKEN` в существующем конф; повторный enroll перезакрывает хост-токен; при expired bootstrap + живом host-токене агент продолжает pull (WARN, токен вычист из конф) |
| I2 | закрыт вырезанием | Mode A удалён entirely; Mode B (`wait`) удалён entirely (решение мейнтейнера) |
| I3 | закрыт | `_revoke_host_certs`: отзыв всех невзятых невнесрочных host-сертификатов публичного ключа хоста (revoke + re-enroll со сменой ключа) |
| I4 | закрыт вырезанием | fan-out wake-POST больше не существует; LAN-bypass/ssrf-замечания к нему не применимы |
| I5 | закрыт | `/ssh/krl/` в `PROTOCOL_PREFIXES`, `/ssh/agent-setup`+`/ssh/agent-runner` в `PROTOCOL_EXACT_PATHS` (bare-префиксы запрещены тестом `test_shared_prefixes_are_slash_terminated_or_unambiguous`), отдельные бакеты rate-limiter; тест-гейты `test_rate_limiter_protocol_coverage.py`/`test_protocol_prefix_single_source.py` зелёные. Агентские `/api/v2/ssh/hosts/*` остаются за flask-limiter `_limit` декораторами (10/60/10 в минуту) |
| I6 | закрыт | `delete_ca` блокируется при живых managed hosts (host_ca или user_ca ссылка) |
| I7 | закрыт | enroll: ValueError (политический отказ CA) → rollback всего enroll; операционный сбой подписи → хост остаётся active без сертификата, retry через check-in→renew (тест policy-refusal зелёный) |
| I8 | закрыт | re-enroll с новым публичным ключом: отзыв старых сертификатов, замена ключа |
| I9 | закрыт вырезанием | `wait` удалён; agent loop: `curl --fail`, одна проверка за тик, следующий тик таймера |
| M1 | закрыт | `delete_certificate` обнуляет `current_cert_id` ссылающихся хостов перед удалением строки |
| M2 | уже было | серверная пагинация/поиск `/api/v2/ssh/hosts` (parse_request_pagination + meta) |
| M3 | снят, формулировка исправлена | порога на /renew нет осознанно: очерёдность диктует check-in (`renew_required`), а тест `test_agent_renew_signs_a_fresh_certificate` закрепляет контракт «/renew всегда подписывает новый сертификат» (early-return его ломает). Прежняя формулировка «спам держит per-route rate limit» неверна для LAN-агентов: `RATE_LIMIT_TRUST_LAN` по умолчанию true и `@limiter.request_filter` в `app.py` снимает flask-limiter с приватных адресов — см. NOTE-3 в follow-up-разделе ниже |
| M4 | закрыт | `rotate_token` только для active-хостов |
| M5 | NOTE | last_krl_sync_at = сигнал UCM — оставлено (факт загрузки виден по ETag-запросу в KRL-логе) |
| M6 | закрыт | `sshHosts.subtitle_one/_other` (+ `_few/_many` для uk), sync-скрипт зелёный |
| M7 | закрыт | `aria-label` на всех иконочных row-actions |
| M8 | закрыт | дублирующий `CREATE UNIQUE INDEX token_hash` убран из миграции |
| M9 | NOTE | `enqueue_deliveries` ca_refid — существующее поведение ядра, вне скоупа |

Гейты цикла (2026-11-22, локально поднят PostgreSQL 18 без root — рецепт в
`docs/PRE_RELEASE_CHECKLIST.md`, §0): полный `pytest -v --tb=short -n 4 --dist loadfile`
→ **17017 passed, 1 failed** (только pre-existing `test_udp_oversize_datagram…`; 12 JKS-тестов
зелёные после `pip install --no-deps pyjks`, как в CI); PG-матрица `-m postgres` → 313 passed;
PG opt-in migration/restore-файлы → 112 passed; SSH-наборы на PostgreSQL-бэкенде
(`UCM_TEST_APP_PG_URL`) → 240 passed (найден и исправлен **D6**: `valid_from/valid_to`
писались tz-aware в `timestamp without time zone` → сдвиг на смещение TimeZone сервера;
SSH-файлы зарегистрированы в `scripts/ci/pg-app-tests.txt`, guard-тест зелёный);
vitest 2543 passed; ESLint 0 errors; i18n sync зелёный. Вердикты Tester/Reviewer по итогам
этого цикла — следующими стадиями pipeline.

---

## Tester-цикл 2026-11-22 (pull-only после #451): вердикт **ок**

Гейты, измеренные Tester'ом независимо: полный SQLite-гейт
`pytest -q --tb=line -n 4 --dist loadfile` → **17095 passed / 1 failed / 442 skipped**
(единственное падение — предсуществующий baseline
`test_dns_update_server.py::test_udp_oversize_datagram_reaches_the_handler_in_full_neg`);
SSH-набор на PostgreSQL-бэкенде → 141 passed / 1 skipped; PG-матрица `-m postgres`
→ 312 passed (после укрепления `test_migration_138_ssh_managed_hosts.py`: оно теперь
сначала `DROP SCHEMA IF EXISTS … CASCADE`, иначе остаток схемы от прерванного прогона
убивает `CREATE TABLE`); vitest 322 файла / 2548 тестов; ESLint 0 ошибок; i18n sync зелёный.

Новые тесты цикла (Tester, 6 файлов): `test_ssh_pull_only_contract.py` (удалённые
эндпоинты отвечают 404 для всех методов, агентская поверхность = enroll/check-in/renew,
ни один HTTP-клиент процесса не делает исходящих вызовов на всём жизненном цикле хоста,
в POSIX- и PowerShell-скриптах нет wake/wait/callback кода), `test_ssh_agent_protocol_surface.py`,
`test_ssh_cert_validity_utc.py` (D6: окно валидности хранится naive UTC на обеих СУБД),
`test_ssh_host_lifecycle_guards.py` (revocation-каскад, guard'ы удаления/ротации,
delete_ca, SET NULL при delete_certificate), `test_migration_138_pull_model_schema.py`,
`SSHHostsPage.pull-only.test.jsx` (UI-вызовы не выходят за UCM; у сервиса нет ни одного
wake/wait/callback метода).

Открытые наблюдения (не блокируют релиз, закрыты как принято ниже):

| ID | Уровень | Суть | Решение |
|---|---|---|---|
| MINOR-1 | MINOR | `/renew` не отзывает вытесненный сертификат: старый остаётся принятым до своего TTL | Принято как часть дизайна. Отзыв вытесненного сертификата того же хост-ключа добавил бы в KRL запись по ключу, которым хост пользуется прямо сейчас (KRL собирается `ssh-keygen -k -s <ca.pub>` по `serial:` невзятых сертификатов CA), то есть риск отказа живого хоста. Компропрометация ключа покрывается каскадом I3 (отзыв всех невзятых сертификатов ключа). Требует подтверждения на реальном sshd — пункт 6 чек-листа. |
| MINOR-2 | MINOR | нет retention/cleanup вытесненных host-сертификатов | Отложено как наблюдаемый рост: при дефолтах (`host_cert_ttl` 30 дней, `renew_threshold_percent` 30) на хост приходится ≈1 новая строка в ~21 день, старые строки сами истекают; `retention_service` чистит только аудит-лог. Завести отдельную задачу, если наблюдение в booted-инсталляции покажет рост. |
| NOTE-3 | NOTE | утверждение «спам держит per-route rate limit» неверно для LAN-агентов | Исправлено в таблице M3 выше: `RATE_LIMIT_TRUST_LAN` (default true) + `@limiter.request_filter` в `app.py` снимают flask-limiter с приватных/loopback адресов, т.е. `10 per minute` на enroll/renew действует только для не-LAN источников. Реальная защита от шторма подписей — очерёдность агента (15-минутный таймер + `renew_required` из check-in). Явный per-host порог на `/renew` нельзя вводить как time-floor: тест `test_agent_renew_signs_a_fresh_certificate` закрепляет «/renew сразу после enroll подписывает новый сертификат». |
| NOTE-6 | NOTE | ESLint-warning `no-unused-vars` в `SSHHostsPage.pull-only.test.jsx:136` | Исправлено в этом цикле (`calls.find(([m]) => …)`), warning снят. |

Ручная стадия (нужен реальный целевой хост): §1–§2 (миграция на реальных пакетах,
enroll одной командой, systemd-таймер), §4 (ssh-keygen стоимость), §6 (renew/guard'ы на живом
агенте + новый пункт про вытесненный сертификат), §7–§8 (webhooks, UI), §10 (allowlist/
cleartext/публичный KRL caveats).

---

## Reviewer раунд 1 (2026-11-22): APPROVE WITH NOTES — закрытиеIMPORTANT / MINOR

| № | Уровень | Находка | Статус |
|---|---|---|---|
| 1 | IMPORTANT | `fetch_krl` curl без `--fail`: страница ошибки 429/500/502 записывалась в файл `RevokedKeys`, лог при этом «KRL synced» — отзыв на хосте молча исчезал | Закрыто: `--fail` + `WARN: KRL fetch failed: <status line>` в ветке отказа (`ucm_agent_scripts.py`, fetch_krl) |
| 2 | IMPORTANT | PowerShell-половина писала бинарный KRL через `$resp.Content` + `Set-Content` (декодирование в строку, кодовая страница по умолчанию, CRLF) → `RevokedKeys` на Windows повреждался при каждом синке | Закрыто: `[IO.File]::WriteAllBytes($tmp, $resp.RawContentStream.ToArray())` + `Move-Item -Force`, backup чужого файла как в POSIX. Живого `pwsh` в CI нет — проверяется текстом скрипта, фактическая запись на Windows — ручной пункт чек-листа |
| 3 | IMPORTANT | `/api/v2/ssh/hosts/{enroll,check-in,renew}` не были в протокольном исключении: при включённом `admin_allowed_networks` хост вне админ-подсетей получал 403, KRL приходил, а host-сертификаты молча истекали по `host_cert_ttl` | Закрыто: три маршрута добавлены в `PROTOCOL_EXACT_PATHS` (токен-аутентификация, публичны по дизайну как OCSP) и получили собственные бакеты rate-limiter вместо общего `_default` с админ-UI |
| 4 | IMPORTANT | `base_url` из `request.url_root` попадает в `UCM_URL` конф агента навсегда: при http-UI или TLS-терминации без `X-Forwarded-Proto` long-lived host-токен идёт в клиртеке | Принято с видимостью: URL остаётся(origin админ-запроса) — это же значение закреплено тестом `TestInstallCommandOrigin` и является конвенцией `/ssh/setup`; добавлен явный `WARN` инсталлера при `UCM_URL=http://…` («host token, сертификаты и KRL идут в открытом виде — переустановите по https») и расширение §10 чек-листа. Полностью закрыто бы только каноническим `get_admin_canonical_origin()`, что меняет контракт install_command — отдельная задача |
| 5 | MINOR | `directive_value` искал `^$1 ` и не видел директиву с табом → агент дописывал вторую строку, OpenSSH брал первую (B2 возвращалась для tab-конфигов) | Закрыто: `^$1[[:space:]]` + `sed 's/^[^[:space:]]*[[:space:]]*//'` |
| 6 | MINOR | `conf_tmp` создавался под umask 0644, в него дописывался токен, `chmod 600` уже после `mv`; `/etc/ucm` был 0755 | Закрыто: `umask 077` в начале и runner'а, и инсталлера; файлы, которые читает sshd, по-прежнему получают явный 644 из `atomic_file` |
| 7 | MINOR | Без systemd инсталлер только печатал совет про cron — на sysvinit/OpenRC/контейнере планирование отсутствовало вовсе | Закрыто: печатается готовая строка `( crontab -l 2>/dev/null; echo '*/15 * * * * …/ucm-ssh-agent run' ) | crontab -`; пункт добавлен в чек-лист §3 |
| 8 | MINOR | Windows-агент правил `sshd_config` и перезапускал `sshd` без аналога `sshd -t`, с одним фиксированным `.ucmbak`, который никогда не восстанавливался | **Осознанный долг (не в этом релизе):** `sshd.exe -t` на Windows OpenSSH не проверен ни локально, ни в CI (pwsh отсутствует), а неверная команда сломала бы установку. B2-валидация живёт только в POSIX-половине; Windows-половина — ручной пункт чек-листа §3 с явным ожиданием |
| 9 | MINOR | `valid_to` в ответах enroll/renew шёл как `isoformat()` без оффсета, вопреки конвенции `utc_isoformat` | Закрыто: `utc_isoformat(...)` в обоих местах |
| 10 | MINOR | Докстринг миграции 138 всё ещё обещал «long-poll wake-up» | Закрыто: текст приведён к pull-only |
| 11 | MINOR | При `auto_renew=off` хост можно удалить с невзятым валидным сертификатом (он остаётся доверенным до TTL) | Принято: поведение guard'а (сначала off → потом delete) и отзыв возможен из списка сертификатов. Требуется формулировка в UI-подтверждении удаления — отдельная косметическая задача, код не менялся |
| 15 | NOTE | `/renew` перехватывал только `PermissionError`, CA-отказ (`ValueError`) уходил агенту как 500 | **Посылка не подтвердилась:** 500 не происходит — глобальный обработчик `ValueError` в `app.py` отвечает 400 `Invalid parameter value`, и тест Tester'а это закрепляет. Оставлено как есть (агент в обоих случаях повторяет на следующем тике); перевод на 403 с текстом CA — отдельная задача, меняющая контракт |

Проверено гейтами после правок: `test_ucm_agent_scripts.py`, `test_ssh_managed_hosts.py`,
`test_ssh_agent_protocol_surface.py`, `test_ssh_pull_only_contract.py`,
`test_rate_limiter_protocol_coverage.py`, `test_protocol_prefix_single_source.py`,
`test_ssh_krl_public.py`, `test_admin_allowlist*.py` → 223 passed.

---

## Tester раунд 2 (2026-11-22): вердикт **ок**, все 8 фиксов `60dd8c61c` доказаны тестами

Гейты: целевой набор 329 passed / 4 skipped; SSH+агентские файлы на PostgreSQL 315 passed /
2 skipped; полный бэкенд `-n 4 --dist loadfile` → 17110 passed / 1 failed (только разрешённый
baseline `test_udp_oversize_datagram…`) / 442 skipped, 4:55; vitest 322 файла / 2548 тестов;
ESLint 0 errors (467 предсуществующих warning); i18n sync зелёный.

12 новых проверок (правка только тестовых файлов `test_ucm_agent_scripts.py` 8→17,
`test_ssh_agent_protocol_surface.py`, `test_ssh_pull_only_contract.py`): 429/500 mock-UCM не
превращается в `RevokedKeys` (байты старого KRL и `krl.etag` нетронуты, в логе
`WARN: KRL fetch failed <status>`); бинальная запись KRL в PowerShell доказана по тексту
генерируемого скрипта; enroll/check-in/renew отвечают 201/200/200 пиру вне allowlist-подсетей,
а `GET /api/v2/ssh/hosts` тому же пиру остаётся 403, и три маршрута меряются в своих бакетах;
`umask 077` доказан runtime (agent.conf и krl.etag → 0600, файлы sshd → 0644) и статически
(umask раньше первой записи); foreign-путь с табом остаётся целью записи, второй строки
`RevokedKeys`/`TrustedUserCAKeys` в конфиге нет; без systemd инсталлер печатает пригодную для
вставки crontab-строку; `valid_to` в ответах enroll/renew — `…Z` и равен перечитанному из БД
naive UTC; WARN про `http://UCM_URL` печатается для http и молчит для https.

Новый долг этого раунда:

| ID | Уровень | Суть | Статус |
|---|---|---|---|
| T2-1 | MINOR | Windows-половина: `agent.conf` с долгоживущим host-токеном пишется `Set-Content` в `C:\ProgramData\ucm` без явной ACL (POSIX-половина закрыта `umask 077`) | Не исправлено в этом релизе: проверка ACL требует живого Windows-хоста. Требуется явный ACL (`icacls … /inheritance:r /grant:r SYSTEM:(F)`) и ручной пункт чек-листа §3. Заводится отдельной задачей |
| T2-2 | NOTE | umask-тест зависит от umask процесса pytest (при уже 077 он стал бы тривиальным); в этом ране umask 022 — проверка нетривиальна | Принято. При добавлении явного `umask(0o022)` в фикстуре тест станет независимым от окружения |

Открытых BLOCKER/IMPORTANT нет. Ручная стадия чек-листа (§1–§3, §6–§8, §10) требует реального
целевого хоста (sshd + systemd timer), живого Windows с pwsh и реального crontab — это следующий
шаг релизного pipeline, не этот цикл.

---

## Reviewer раунд 2 (2026-11-22): APPROVE WITH NOTES — закрытие

| № | Уровень | Находка | Статус |
|---|---|---|---|
| 1 | IMPORTANT | `[ -f "$krl_target" ] \|\| : > "$krl_target"` под новым `umask 077` создавал пустой `RevokedKeys` с режимом 0600, минуя `atomic_file` и конвенцию 644 | Закрыто: `atomic_file "$krl_target" 644 < /dev/null` |
| 2 | IMPORTANT | crontab-строка без PATH: у cron `PATH=/usr/bin:/bin`, `/usr/sbin` нет → `validate_sshd` и `reload_sshd` ничего не находят; плюс дубль записи при повторном инсталле | Закрыто иначе и шире: сам runner выставляет канонический PATH (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`) сразу после `set -eu` — это покрывает cron, sysvinit и любой другой планировщик, а не только печатаемую строку; строка инсталлера теперь `crontab -l \| grep -v ucm-ssh-agent` (безопасен повторный инсталл) |
| 3 | MINOR | Windows: `Set-Content $confPath` шёл после `Fetch-Krl`, который на 429/500 делает `throw` → host-токен не сохранялся при уже spent bootstrap-токене, хост требовал переустановки | Закрыто: токен пишется до всего, что может бросить исключение; `Fetch-Krl` в enroll обёрнут в try с WARN; refid/KRL_PATH дописываются после |
| 4 | MINOR | Windows run-режим: `Fetch-Krl` без try обрывал весь тик (check-in и renew не выполнялись) | Закрыто: `$krlChanged = $false; try { … } catch { WARN }`; плюс placeholder пустого `RevokedKeys` при enroll, как в POSIX |
| 5 | MINOR | Три агентских пути, попав в `PROTOCOL_EXACT_PATHS`, больше не 404-ятся на ACME-vhost и не защищены guard'ом чужого `X-Forwarded-Host` | Записано как принятое следствие в §10 чек-листа (безвредно при обязательном `X-Host-Token`; добавлена проверка «без токена с ACME-хоста → 401, никогда сертификат») |
| 6 | NOTE | Устаревший пункт ран-1 «в safe-mode агентские эндпоинты дают 503» | Исправлен в разделе «Эксплуатационные предупреждения»: теперь 200, принято осознанно |
| 7 | NOTE | `[IO.File]::WriteAllBytes(…, $resp.RawContentStream.ToArray())` — идиома Windows PowerShell 5.1; в pwsh 7 бинарное тело отдаётся через `Content` (byte[]) | Принято как долг: реальная проверка требует живого хоста и на 5.1, и на 7 — пункт §3 чек-листа. Текст скрипта этого не доказывает |
| 8 | NOTE | `validate_sshd` при отсутствии `sshd` в PATH возвращает успех → битый конфиг может остаться без откатa | Принято: закрывается живым пунктом §3 (канонический PATH теперь выставляется самим агентом, так что `sshd` будет найден там, где он установлен) |

Открытых BLOCKER/IMPORTANT после этого закрытия нет. Долги, принятые для релиза:
Windows `sshd -t` и never-restored `.ucmbak`, ACL на `C:\ProgramData\ucm\agent.conf` (T2-1),
общий 400 на CA-отказ в `/renew`, отсутствие retention вытесненных host-сертификатов,
`base_url` = origin админ-запроса (WARN вместо канонического origin).

---

## Tester раунд 3 (2026-11-22): вердикт **ок** — все 4 фикса `8aec001a7` подтверждены

Гейты: 13 целевых файлов → 327 passed / 4 skipped; PG (`UCM_TEST_APP_PG_URL`) → 315 passed /
2 skipped; полный бэкенд `-n 4 --dist loadfile` → 17117 passed / 1 failed (только разрешённый
`test_udp_oversize_datagram…`) / 442 skipped, 5:02; vitest 322 файла / 2548 тестов; i18n — 9
локалей синхронны. Изменён только `backend/tests/test_ucm_agent_scripts.py` (+149 строк, 6 кейсов).

- Placeholder `RevokedKeys`: рантайм-смоук enroll против mock-UCM с `krl_error=500` в обоих
  вариантах (своя директива и чужой путь) — файл существует с режимом **0644**, пустой, создан по
  цели, на которую смотрит директива, `ucm_user_krl` при этом не создаётся, scratch-файлов нет.
- Канонический `PATH`: раннер запускался в bwrap с окружением ровно `{PATH=/usr/bin:/bin, …}`
  (cron-условия), фейковые `sshd`/`systemctl` лежали только в `/usr/sbin`/`/usr/local/sbin` —
  агент нашёл `sshd` (маркер `sshd -t`), конфиг не откатан. В CI без bubblewrap этот кейс
  подтверждает только текстовая половина — добавление bwrap в CI-образ отдельной задачей.
- crontab: в единственной `*/15`-строке `crontab -l | grep -v ucm-ssh-agent` идёт до добавления
  новой записи (текстовая половина; реальный `crontab` — ручной пункт).
- PowerShell: `Set-Content $confPath $lines` раньше `Fetch-Krl`, placeholder `RevokedKeys`
  раньше `Fetch-Krl`, `Fetch-Krl` обёрнут в try в enroll и в run-теле. Поведение pwsh — ручной
  пункт (pwsh нет ни локально, ни в CI).

MINOR/NOTE этого раунда: runtime-половина crontab-дедупликации не покрыта (в песочнице нет
`crontab`); bwrap-зависимость теста PATH; пред-существующие предупреждения conftest о «changed
shared tables» в `test_public_endpoints.py`, `test_admin_allowlist.py`, `test_ssh.py`,
`test_ssh_ca_permissions.py`, `test_ca_is_active_removed.py` — не нашего скоупа.

---

## Tester раунд 4 (2026-11-22): вердикт **ок** (фиксы `f6fed0ac3` доказаны)

Гейты: 12 целевых файлов → 284 passed / 4 skipped; PG → 321 passed / 2 skipped; полный бэкенд
`-n 4 --dist loadfile` → 17123 passed / 1 failed (разрешённый baseline) / 442 skipped, 5:01;
i18n-синхрон зелёный (vitest пропущен: фронтенд в этом коммите не менялся). Изменён только
`backend/tests/test_ucm_agent_scripts.py` (ре-пин крон-контракта + 6 новых проверок).

Ре-пин обоснован и подтверждён исполнением строки против фейкового `crontab`: две одинаковые
записи схлопываются в одну, рукописные `*/30 … ucm-ssh-agent run`, `0 5 … run --quiet`,
`MAILTO=root` и комментарий выживают; старая форма `grep -v ucm-ssh-agent` убивала чужой
`*/30`-график — это и было причиной смены контракта.

Доказано: все три `@()`-обёртки PowerShell + инвариант «ни одного append к результату
`Get-Content` без `@()`»; порядок Enroll (KRL-поля и `Set-Content` раньше директив и
`Fetch-Krl`, единственный `Set-Content`); POSIX-ветка отказа плейсхолдера рантаймом (exit 0,
два WARN, каталог не создан, `sshd -t` вызван, гард не обойдён) и ветка отказа `sshd -t`
(откат строки `RevokedKeys`, конфиг выгружен, enroll завершён).

Новое наблюдение этого раунда:

| ID | Уровень | Суть | Статус |
|---|---|---|---|
| T4-1 | MINOR | `fetch_krl` не проверяет результат `atomic_file "$target" 644 < "$out"`: при недоступном для записи каталоге `RevokedKeys` curl успешен → агент пишет «KRL synced to <несуществующий путь>», сохраняет ETag и возвращает 0; пока содержимое KRL не изменится, отсутствующий файл не будет восстановлен никогда (все последующие опросы дают 304) | Закрыто в этом же цикле: неуспешная запись = WARN + return 1 без записи ETag и без `CONTENT_CHANGED` (следующий тик повторит загрузку, а не получит 304). Проверено isolated-исполнением ветки: несуществующий каталог → WARN, rc 1, etag-файл не создан; положительный контроль — обычная запись даёт 644 и «KRL synced» |
| T4-2 | NOTE | `apply_sshd_guard` откатывает только самый свежий `sshd_config.ucmbak.*`; ранее добавленные директивы переживают откат | Принято: в проверенном сценарии конфиг остаётся валидным (файлы директив записаны успешно), функциональной дыры нет |
| T4-3 | NOTE | `grep -vF` — подстрочный матчинг: комментарий, дословно содержащий всю запись, тоже удалится | Принято как косметика |
| T4-4 | NOTE | Флейк PG-прогона: `TestWebhookEvents::test_host_revoke_events_route_by_ca_filter` в первом PG-прогоне упал, изолированно и при повторе — зелёный (общие таблицы/порядок) | Следить в CI, не блокирует релиз |

---

## Tester раунд 5 (2026-11-22): вердикт **ок** — T4-1 закреплён тестом

Гейты: точечный набор (12 файлов) → 287 passed / 4 skipped; PG дважды → 324 passed / 2 skipped
оба прогона (флейк `TestWebhookEvents::test_host_revoke_events_route_by_ca_filter` из раунда 4
не воспроизвёл ни разу); полный бэкенд `-n 4 --dist loadfile` → 17126 passed / 1 failed
(разрешённый baseline) / 442 skipped, 5:04. Vitest и lint пропущены: фронтенд с предыдущего
зелёного прогона не менялся.

T4-1 доказан реальным `run`-тиком против mock-UCM: `/ssh/krl` отдаёт 200 + ETag `"1"`, check-in
отвечает `krl_changed: true`, а `KRL_FILE` указывает в несозданный каталог — в логе есть
`WARN: could not write the KRL to …`, нет `KRL synced`, `state/krl.etag` отсутствует, ни один
последующий GET не принёс `If-None-Match` (то есть 304-запирания нет, загрузка повторяется
каждый тик), exit 0 обоих тиков, ровно один renew, scratch- и `.ucmbak`-файлов нет.
Положительный контроль тем же механизмом: записываемая цель даёт `KRL synced`, байты с NUL,
режим 0644, etag `"1"`, а второй тик опрашивает с `If-None-Match: "1"` и уже не перекатывает
файл. Текстовая половина: ровно одно вхождение `atomic_file "$target" 644 < "$out"`, и оно —
`if ! …` с веткой WARN + `rm` + `return 1` без etag и без `CONTENT_CHANGED=1`; `sh -n` и
`bash -n` на обеих POSIX-сборках зелёные.

NOTE этого раунда: guard закреплён в фактической форме `if ! … ; then` (а не `|| log`, как у
плейсхолдера); покрывается отказ ENENT (нет каталога), ветка EACCES/RO-mount/NFS даёт тот же
отказ внутри `atomic_file`, но отдельным тестом не закреплена — она в ручных пунктах чек-листа.

---

## Reviewer раунд 4 (2026-11-22): APPROVE WITH NOTES — закрытие

| № | Уровень | Находка | Статус |
|---|---|---|---|
| 1 | IMPORTANT | Windows: `Fetch-Krl` читает `$conf`, разобранный до enroll, а `KRL_PATH` появлялся только в файле после `Set-Content` → «initial KRL fetch» внутри `Enroll` был мёртвым кодом (`return $false`), первый KRL приходил только на следующем тике (≤15 мин) | Закрыто: сразу после `Set-Content` обновляется и разобранный `$conf` (`HOST_TOKEN`, `USER_CA_REFID`, `KRL_PATH`) — файл и память больше не расходятся; POSIX-половина уже делала это через export |
| 2 | IMPORTANT | `models/ssh.py` всё ещё описывал `krl_version` как «wake-up signal agents long-poll on», вопреки pull-only SPEC/CHANGELOG | Закрыто: комментарий приведён к ETag pull-only `/ssh/krl/<refid>`; то же исправление в `ssh_cert/management.py` («ETag / agent wake-up») и в заголовке Фазы 2 SPEC, где wake-up теперь явно помечен descoped по #451 |
| 3 | MINOR | Windows-установщик: `Get-Content $conf \| Where \| Set-Content $conf` читал и писал один файл в одном пайплайне (на PS 5.1 — «file is being used by another process») | Закрыто: `@(Get-Content $conf)` сначала дочитывается до конца, затем `Set-Content` |
| 4 | MINOR | `atomic_file` при отказе `mv` оставлял `$target.tmp.$$` в каталоге, который читает sshd (в тесте чистился только mktemp в `/tmp`) | Закрыто: ветка отказа удаляет tmp и возвращает 1. Проверено isolated-исполнением: отказ (`chmod` с неверным режимом) → rc 1 и ни одного `.tmp.*`; успех → rc 0, 0644, tmp нет |
| 5 | NOTE | Уточнение: `[byte[]]::new(0)` — массив **нулевой длины**, то есть пустой файл (0 байт), а не «1-байтный плейсхолдер»; поведение совпадает с POSIX-плейсхолдером из `/dev/null` | Расхождение в формулировке раунда, кода не потребовало |
| 6 | NOTE | PowerShell-доказательства остаются текстовыми: pwsh 5.1/7 нет ни локально, ни в CI | Принято как долг: ручные пункты §3 чек-листа, обязателен живой хост и на 5.1, и на 7 |

Открытых BLOCKER/IMPORTANT после этого закрытия нет. Итог релизного решения: pull-контракт
реализован целиком (15-минутный таймер + ETag/304), push-механик в продукте нет, debts
зафиксированы (Windows `sshd -t`/`.ucmbak`, ACL `C:\ProgramData\ucm\agent.conf` = T2-1,
общий 400 на CA-отказ в `/renew`, отсутствие retention вытесненных host-сертификатов,
`base_url` = origin админ-запроса с WARN вместо канонического origin).

---

## Флейк PG-гейта: `test_host_revoke_events_route_by_ca_filter` (2026-11-22)

Симптом: в PG-прогоне `tests/test_ssh*.py tests/test_ucm_agent_scripts.py` тест упал один раз
(прогон 1), следующий прогон той же командой — зелёный. Такой же единственный случай был в
Tester-раунде 4.

Диагностика (один цикл, 12 попыток воспроизвести): 5 × `test_ssh_managed_hosts.py` изолированно,
4 × `test_ssh_managed_hosts.py + test_ucm_agent_scripts.py`, 3 × полный glob — все зелёные,
`--tb=long` не дал ни одного трейсбека, то есть падающий ассерт в этих повторах не зафиксирован.
`pytest-randomly` в окружении отсутствует, порядок тестов детерминирован.

Что проверено чтением: событие `ssh_ca.krl_updated` ставится в durable-очередь синхронно
(`WebhookDelivery.status = 'pending'`, не фоновая отправка), `krl_version` в payload читается из
`cert.ca` — того же объекта, которому `ssh_cert/management.py` увеличил счётчик до эмита;
фикстуры `host_ca`/`user_ca`/`enrolled_host` — function-scoped, то есть CA на тест создаётся
новый и счётчик в нём начинается с 0. Очистка теста удаляет свои delivery-строки и endpoint'ы.

Вывод: признаков продуктового дефекта в этом пути не найдено; устойчивая гипотеза — состояние
общих таблиц PG-базы, пережившее прогон (conftest предупреждает «left the shared tables changed»
в `test_admin_allowlist.py`, `test_public_endpoints.py`, `test_ssh.py`, `test_ssh_ca_permissions.py`,
`test_ca_is_active_removed.py` — не нашего скоупа), при котором выборка `WebhookDelivery` без
`ORDER BY` на PostgreSQL возвращает строку в неопределённом порядке. Это тестовая гигиена, и она
остается открытым наблюдением: PG-гейт при единичном падении этого теста надо повторять, а
разобраться с ним должна тестовая обвязка отдельной задачей (тесты — не зона правки девелопера).

---

## Ручной pre-release прогон 2026-11-22: локальный стенд (UCM + реальный OpenSSH 10.2)

Состав стенда (без root): UCM запущен `python3 app.py` (DATA_DIR=/tmp/opencode/ucm-stand, HTTPS 8443,
self-signed сертификат UCM, SQLite); целевой хост — `openssh-server 10.2p1` из deb (`dpkg-deb -x`,
плюс `libwrap0` для `sshd-session`) внутри bubblewrap: `--ro-bind / /`, bind своего дерева на `/etc`,
`/usr/local/bin`, `/run`, bind `/usr/lib/openssh` и `/usr/sbin` из распакованного пакета, tmpfs нет —
сетевой namespace общий, sshd слушает 127.0.0.1:2222; TLS-доверие: сертификат UCM добавлен в CA-связку,
curl работает **без `-k`**.

### Что подтверждено живьём

| Пункт чек-листа | Результат |
|---|---|
| §2 install одной командой | `curl …/ssh/agent-setup?token=… \| bash` → exit 0; `/usr/local/bin/ucm-ssh-agent` 0700, `/etc/ucm` 0700, `agent.conf` 0600 с `HOST_TOKEN=ucm_sh_…`, `USER_CA_REFID`, без `BOOTSTRAP_TOKEN` |
| §2 директивы sshd | `HostCertificate`, `TrustedUserCAKeys`, `RevokedKeys` дописаны ровно по одной строке; создан `sshd_config.ucmbak.<ts>`; **`sshd -t` реальным OpenSSH 10.2 прошёл**, конфиг выгружен |
| §2 host-сертификат | `ssh-keygen -L`: host certificate, Signing CA = Host CA, principals `stand1.lab.internal`, `Valid: 2026-11-22 → 2026-12-22` (ровно 30 суток) |
| §2 доверие клиента | known_hosts `@cert-authority stand1.lab.internal <Host CA pub>` + `StrictHostKeyChecking=yes` → сессия прошла (`HOSTCERT_TRUST_OK`); тот же узел с **чужой** CA-якорем → `Host key verification failed`. Отдельный факт: клиент отвергает сертификат, если запрошенное имя (`127.0.0.1`) отсутствует в principals — имя в сертификате и имя соединения должны совпадать |
| §2 hostname discipline | enroll с другим hostname → 403 `This enrollment is bound to hostname '…'`; enroll при CA-политике без principals → 403 `This SSH CA lists no allowed principals`; с principals вне списка → 403 `Principal '…' is not in the CA's allowed principals list` |
| §4 ETag / 304 | тик 1: `KRL synced` (44 байта, режим **0644**), etag `0`; тик 2: ни одной строки в логе, файл не тронут → 304 отработал |
| §3 нет systemd | инсталлер на хосте без systemd напечатал готовую crontab-строку (см. D8) |
| §10 cleartext | `UCM_URL="https://127.0.0.1:8443"` в конфe; при `http://` инсталлер печатает WARN (проверено текстом и прогоном) |

### Дефекты, найденные только живым прогоном

| ID | Уровень | Что не так | Что сделано |
|---|---|---|---|
| **D7** | **BLOCKER-класс (найден вручную, тесты его не ловили)** | `POST /hosts/<id>/revoke-cert` вернул 200, хост стал `revoked`, но сертификат остался `revoked=False`, `krl_version` Host CA не изменился, KRL остался 44 байта с ETag `"0"`, а `ssh-keygen -Q` назвал хост-ключ `ok`. Причина: `_revoke_host_certs` фильтровал `SSHCertificate.public_key == host.public_key`, а агент присылает содержимое `.pub`-файла — **с комментарием** (`ssh-ed25519 AAA…dyi viz@VIZ-PC`, 91 символ), тогда как сертификат хранится без комментария (80 символов). Совпадения нет → не отозвано ни одного сертификата. отзыв host-сертификата на реальном хосте не доходил до KRL вообще. Автотесты этого не видели, потому что тестовый enroll шлёт ключ без комментария | `SSHManagedHostService._key_material()` нормализует OpenSSH-ключ (`<type> <base64>`, комментарий отбрасывается) с обеих сторон фильтра; самопроверка: форматированный и чистый ключ равны, два разных ключа не сливаются, пустой комментарий не ломает прежнее поведение. Тот же фильтр используется при re-enroll с новым ключом — исправление закрывает и этот путь |
| **D8** | IMPORTANT | Инсталлер выбирал ветку systemd по признаку `command -v systemctl`, а не по факту systemd: в контейнере/OpenRC бинарник есть, `/etc/systemd/system` отсутствует → `cat > …service: No such file or directory` под `set -eu` → установка обрывалась **посреди**: раннер скачан, конф записан, enroll не выполнен, планирования нет | Ветка вынесена в `install_systemd_timer()`, где каждый шаг (`mkdir -p`, запись unit'ов, `daemon-reload`, `enable --now`) возвращает 1 вместо обрыва; при неудаче печатается резервная crontab-строка. Проверено живьём: тот же контейнер теперь доходит до enroll |
| **D9** | MINOR | `curl_get` с `--fail` терял тело ответа: агент писал `ERROR: enroll refused: no response`, хотя UCM ответил точную причину (политика principals, bound hostname) | `--fail-with-body` (curl ≥ 7.76, определяется через `curl --help all`), тело ошибки логируется в enroll/renew/check-in (`check-in refused: {"detail":"Invalid host token"}`). Живой прогон сразу показал обе причины вместо «no response» |

Открытым осталось: KRL **User CA** (тот, что качает агент в `RevokedKeys`) не меняется при отзыве host-сертификата —
это разные KRL по дизайну (host-сертификат отзывается в KRL своего Host CA); клиенты OpenSSH сами KRL для
host-сертификатов не проверяют, поэтому отзыв живого host-сертификата ограничивается TTL и запретом продления.
Это уже записано в §6 чек-листа как ожидаемое следствие pull-модели.

---

## Tester раунд 6 (2026-11-22): вердикт **ок** — D7/D8/D9 закреплены тестами, флейк PG объяснён и снят

Гейты: целевой набор (13 файлов) → 343 passed / 4 skipped; **пять подряд** PG-прогонов
`tests/test_ssh*.py tests/test_ucm_agent_scripts.py` → 334 passed / 2 skipped каждый, `StopIteration`
непоявлялись; полный бэкенд `-n 4 --dist loadfile` → 17136 passed / 1 failed (разрешённый
baseline) / 442 skipped, 5:06. Изменены только `tests/test_ssh_managed_hosts.py`,
`tests/test_ucm_agent_scripts.py`, `tests/conftest.py`.

- **D7** — `TestRevokeWithRealPubKeyFile`: enroll публичным ключом **с комментарием** (ровно то, что
  агент берёт из `.pub`), затем `revoke-cert` → `revoked=True` + `revoked_at` + причина, `krl_version`
  вырос ровно на число отозванных сертификатов, публичный `/ssh/krl/<refid>` непустой и байты
  изменились, события `ssh_certificate.revoked` и `ssh_ca.krl_updated` в очереди. Второй тест —
  re-enroll после ротации ключа (тоже с комментарием): сертификат старого ключа отозван. На
  дофиксовом коде оба падали бы (91 против 80 символов в фильтре).
- **D8** — инсталлер целиком прогоняется в bubblewrap с подставными `systemctl`/`sshd`/`id`: случай
  «нет systemd» (unit-каталог недоступен) и случай «`daemon-reload` отвечает *System has not been
  booted with systemd as init system (PID 1)*» → exit 0, напечатанная crontab-строка, раннер скачан,
  enroll-POST дошёл до mock UCM, `HOST_TOKEN` появился, `BOOTSTRAP_TOKEN` удалён. Позитивный контроль:
  unit-файлы записаны, `enable --now ucm-ssh-agent.timer` вызван, резервная строка не напечатана.
- **D9** — детекция `--fail-with-body` прогнана вживую против curl, который флаг объявляет, и против
  curl, который его не объявляет (остаётся `--fail`); runtime на настоящем curl: 403 enroll → в логе
  точная причина вместо «no response» (exit 1, конф не испорчен, bootstrap-токен жив), 401 check-in →
  `check-in refused: {"detail":"Invalid host token"}` и **exit 0 тика**, KRL/etag/конф не тронуты,
  403 renew → `renew refused: …` и отказ не засчитан как продление.
- **Флейк PG** — первопричина подтверждена и устранена в слое обвязки: 11 сканов первой страницы
  заменены на `GET /api/v2/ssh/hosts?search=<hostname>&per_page=100` (тот же домашний приём, что уже
  использовали `test_ssh_host_lifecycle_guards.py` и `test_ssh_cert_validity_utc.py`), а SSH-таблицы
  добавлены в `conftest._LEAK_TABLES`, поэтому накопление общей PG-базы теперь видно guard'у
  (17 предупреждений в полном прогоне, режим `warn`, падений нет).

Хвост D8, найденный этим раундом и закрытый сразу: `|| return 1` отсутствовали на двух
`cat > /etc/systemd/system/ucm-ssh-agent.{service,timer}`. `mkdir -p` возвращает 0 и на существующем,
но read-only каталоге, а `set -e` внутри условия `if` подавлен — то есть при read-only unit-каталоге
инсталлер доходил до `enable --now` и полагался только на него; на хосте, где systemd отвечает
успешно, а unit-файлы не записались, он рапортовал бы «installed: timer every 15 minutes» без
всякого планирования. Теперь обе записи возвращают 1, и печатается резервная строка. Проверено:
`sh -n`/`bash -n` на обеих POSIX-сборках, 125 passed в целевых наборах.

Доплата к D7 тем же механизмом (`500ed1616` следом): сравнение «ключ хоста заменён» в enroll
тоже переведено на материал ключа. Раньше `host.public_key != public_key` сравнивало строки
целиком: `.pub`-файл, перегенерированный с другим комментарием (тот же ключ), считался бы
ротацией ключа и отзывал бы сертификаты живого хоста. Проверено целевыми наборами (130 passed);
закрепить это тестом — задача Tester'а, если Reviewer сочтёт обязательным.

---

## Reviewer раунд 5 (2026-11-22): APPROVE WITH NOTES — закрытие

| № | Уровень | Находка | Статус |
|---|---|---|---|
| 1 | IMPORTANT | `_revoke_host_certs` без фильтра по ключу тащит в Python все не отозванные host-сертификаты CA (~1 КБ на строку; 10 000 — десятки мегабайт и секунды на каждый revoke и каждый re-enroll) | Закрыто как предложено: отбор остаётся в SQL — точное совпадение нормализованного ключа ИЛИ `LIKE "<wanted> %"` (в `<type> <base64>` нет `%` и `_`, экранируем на всякий случай). `if not wanted: return []` — пустой ключ хоста больше не матчает пустые ключи сертификатов |
| 2 | IMPORTANT | `public_key` в enroll проверяется только по длине; строка с authorized_keys-опциями (`from="…" ssh-ed25519 …`) нормализуется в `from="…" ssh-ed25519` и снова могла бы молча не совпасть | **Проверено живьём на стенде — additional проверка не нужна:** enroll с `from="10.0.0.1" ssh-ed25519 AAA…` и с `not-a-key-at-all` → 403 `Invalid SSH public key format` (существующий `_parse_public_key` в `ssh_cert/utils.py`), строка хоста осталась `pending` с `public_key IS NULL` и без сертификатов; валидный ключ без комментария → 201 и 1 сертификат. Дублирующая проверка на входе API — избыточный слой |
| 3 | IMPORTANT | Чек-лист не требовал прогона Windows и на 5.1, и на 7 | Закрыто: §3 теперь два обязательных пункта — Windows PowerShell 5.1 (`powershell.exe`, именно её ставит `schtasks`) и PowerShell 7 (`pwsh`), с байтовым сравнением KRL после тика; `[IO.File]::WriteAllBytes(…RawContentStream…)` доказано только для 5.1 |
| 4 | MINOR | Пустой/`None` `host.public_key` давал `wanted == ''` | Закрыто (см. №1) |
| 5 | MINOR | Частичная запись unit-файлов | Подтверждено корректным: `cat > f <<'EOF' || return 1` валидный POSIX/dash/bash; при неудаче второй записи `return 1` → `scheduled = 0` → печатается crontab-строка, «успех без планирования» невозможен. Косметический осадок: сиротский `ucm-ssh-agent.service` без таймера (не загружен, перезапишется следующим инсталлом) — принято |
| 6 | MINOR | `_LEAK_TABLES` + SSH-таблицы: не сломает ли CI | Проверено: `UCM_TEST_LEAK_MODE` по умолчанию `warn`, нигде в workflow/скриптах `fail` не ставится → только предупреждения. При будущем переводе в `fail` SSH-файлам понадобится самоочистка — записано |
| 7 | MINOR | Опечатка `sshkeygen -Q`; устаревший пункт «это половина про `--fail`» | Исправлено в §4; туда же добавлен пункт про curl < 7.76 (Ubuntu 20.04): агент работает, но причину отказа не печатает — это возможность curl, а не гарантия |
| 8 | NOTE | `e671a2a93`: настоящая ротация с прежним комментарием всё ещё детектируется (base64 разный) | Принято ревьюером как не блокирующее релиз; отдельный тест «тот же ключ, другой комментарий → отзыва нет» — по 3 ассертам в существующем тесте, записано как задача |

Вывод ревьюера по релизу: выпуск ветки локально (без push/PR) допустим после ручного прогона чек-листа; обязательные разделы названы, окно обязательных ручных пунктов — §0/§0b/§1 (отзыв ключа из настоящего `.pub` с комментарием + `ssh-keygen -Q` = `REVOKED`), §2 (живой timer и `sshd -T`), §3 (обе POSIX-половины, EACCES-ветка, живой crontab, Windows 5.1 **и** 7), §4 (реальный KRL и цена 304), §5 (негативное доказательство отсутствия push), §6 (гарды продления и замещённый сертификат), §7 (webhooks).

---

## Tester раунд 7 (2026-11-22): вердикт **ок** — закрытие находок Reviewer-раунда 5

Гейты: целевые 13 файлов + новый → 351 passed / 4 skipped; **три** PG-прогона подряд →
339 passed / 2 skipped каждый; полный бэкенд `-n 4 --dist loadfile` → 17142 passed / 1 failed
(разрешённый baseline UDP) / 442 skipped, 5:14. Новый файл `tests/test_ssh_revoke_key_match_v7.py`
(6 тестов), production и git не тронуты, существующие ассерты не ослаблены. `UCM_TEST_LEAK_MODE`
в `.github/` не встречается ни разу → в CI остаётся `warn`.

- **LIKE-половина выборки:** enroll ключом из `.pub`, затем в тестовой БД строка сертификата
  переписывается на `"<type> <base64> old@host"` → `revoke-cert` отзывы именно её (`revoked=True`,
  `revoked_at`, причина), `krl_version` +1, байты публичного KRL изменились. На «точное равенство»
  до правки — красный.
- **Пустой ключ хоста:** хост с `public_key IS NULL` на том же Host CA, что и два живых хоста:
  revoke → отозвано ровно 0 строк, 3 живых сертификата соседей нетронуты, `krl_version` и KRL не
  изменились, в очередях нет `ssh_certificate.revoked`/`ssh_ca.krl_updated` (есть `ssh_host.revoked`);
  re-enroll (rotación) того же хоста — 0 отзованных по всему CA. При «выборке всех host-сертификатов
  CA» сертификаты соседей ушли бы в KRL.
- **Форма ключа при enroll** закреплена как защита от регресса: `from="10.0.0.1" ssh-ed25519 …` и
  `not-a-key-at-all` → non-2xx, хост остаётся `pending` без ключа и без сертификатов, bootstrap-токен
  не сожжён и следующий валидный enroll даёт 201 `active`.
- **Комментарий ≠ ротация:** тот же ключ с другим комментарием → живой сертификат не отозван,
  0 отзованных, 2 живых, `krl_version` и KRL неизменны; настоящая ротация (тот же комментарий,
  другой base64) → старый сертификат отозван, живых ровно 1, `krl_version` +1.

MINORTester'а (принимаем как отдельные решения, не блокирующие релиз): точный HTTP-код отказа по
форме ключа не закреплён (403 против «generic ValueError → 400» — открытый вопрос контракта,
записан в `host_management.py`); для проверки rotate-пути после отзыва тест временно выставляет
хосту `status=ACTIVE` напрямую в тестовой БД.

---

## Ручной прогон после фиксов (2026-11-22, повторный пункт чек-листа про отзыв)

Тот же стенд, хост `stand3.lab.internal`, enroll **ключом из настоящего `.pub`-файла**
(`ssh-ed25519 AAA…dyi viz@VIZ-PC`, 91 символ с комментарием): 201, хост `active`, сертификат выдан.

`POST /hosts/2/revoke-cert {"reason":"live re-walk of defect D7"}`:

| Что смотрели | До фикса (первый прогон) | После фикса |
|---|---|---|
| `cert_status` в ответе | `valid` | `revoked`, `cert_serial` 4 |
| Строки сертификатов CA этого хоста | `revoked=0` (не отозван ни один) | **все 3** `revoked=1` + `revoked_at` + причина |
| `krl_version` Host CA | 0 | **0 → 4** |
| `GET /ssh/krl/<refid>` | 44 байта, ETag `"0"` | **126 байт, ETag `"4"`** |
| `ssh-keygen -Q` | — | старый KRL: `ok`; новый KRL: **`REVOKED`** |
| KRL User CA | 0 | 0 (не тронут — другой CA, по дизайну) |

Отдельный факт, который надо знать при ручном прогоне (и он теперь записан в §1 чек-листа):
host-сертификат отзывается **по serial'у**, а serial существует только у сертификата.
`ssh-keygen -Q -f <krl> ssh_host_ed25519_key` (голый ключ) отвечает `ok` даже при корректном
отзыве — проверять надо файл сертификата (`ssh-ed25519-cert-v01@openssh.com …`), и тогда ответ
`REVOKED`. Это не дефект продукта.

---

## Ручной прогон §5/§6 (2026-11-22, стенд, host `stand4.lab.internal`)

Хост зарегистрирован, инсталл `curl …/ssh/agent-setup?token=… | sh` (exit 0): раннер 0700,
`/etc/ucm` 0700, `agent.conf` 0600 (`HOST_TOKEN`, `USER_CA_REFID`, `KRL_PATH`, без
`BOOTSTRAP_TOKEN`), host-сертификат и User CA установлены, реальный `sshd -t` — OK,
напечатана резервная crontab-строка (systemd в контейнере нет).

| Пункт | Результат |
|---|---|
| §5 pull-путь отзыва user-сертификата | сертификат User CA выдан (serial 1) → `POST /certificates/6/revoke` → `krl_version` User CA 0 → 1 → тик агента: `KRL synced`, `/etc/ssh/ucm_user_krl` **44 → 121 байт**, режим 0644, etag 1 |
| §5 цена «ничего не изменилось» | следующий тик: ни одной строки в логе, mtime файла не изменился → 304 без перезаписи |
| §4 проверка KRL | `ssh-keygen -Q` по **файлу сертификата** = `REVOKED`; по голому ключу = `ok` (UCM отзывает по serial, serial есть только у сертификата) — пункт чек-листа переписан |
| §6 delete-guard | 400 «Cannot delete a managed host while auto-renew is on and its certificate is valid: turn auto-renew off first, or revoke…» |
| §6 force-renew | 200 «Host certificate reissued» и при `auto_renew: true`, и после `PATCH {auto_renew:false}` |
| §6 force-renew отозванного хоста | 400 «Host status is 'revoked': cannot renew» |
| §6 отзыв токена (rotation) | старый токен после ротации → 401 «Invalid host token» |
| §6 агентский renew при выключенном auto-renew | 403 «Auto-renewal is paused» (продление разрешено только явным действием админа) |
| §6 кросс-хостная изоляция | у агентских `/hosts/renew` и `/hosts/check-in` нет идентификатора хоста в пути — хост определяется по токену, поэтому воздействовать на чужой хост адресуемо невозможно; чужой хост после всех операций остался `revoked`, serial 4 |

### D10 (MINOR, найден живым прогоном, закрыт)

Повторный инсталл на хосте, у которого в `agent.conf` уже есть `HOST_TOKEN`, при отказе UCM
печатал `WARN: enrollment failed (token expired?)` — точная причина (403 про principal-политику)
терялась, хотя `curl_get` её уже получал. Ветка «продолжаем как зарегистрированный хост» теперь
печатает ответ UCM. Проверено живьём: `WARN: enrollment failed ({"detail":"Principal
'stand4.lab.internal' is not in the CA's allowed principals list"}); continuing as enrolled host`.

### Долг, найденный прогоном и НЕ исправленный в этом релизе

Регистрация хоста с principal, которого нет в списке Host CA, проходит (`POST /ssh/hosts` — 201),
а падает только позже — на самом хосте, с 403. Причина записана в чек-лист как отдельный пункт:
проверять principals при регистрации — это изменение поведения API, оно не входило в задачу.

---

## Reviewer раунд 6 (2026-11-22): APPROVE WITH NOTES — закрытие

| № | Уровень | Находка | Статус |
|---|---|---|---|
| 1 | IMPORTANT | D10 был закрыт только в POSIX-половине: PowerShell-`Enroll` печатал `WARN enrollment failed (token expired?)`, то есть на Windows-хосте причина отказа UCM терялась, и в чек-листе/долгах про это не было ни строки | Закрыто фиксом, а не долгом: ветка печатает `$_.ErrorDetails.Message` (идиом есть и в Windows PowerShell 5.1, и в pwsh 7), POSIX-`token expired?` удалён целиком (`grep` по раннеру). В §3 чек-листа добавлен отдельный пункт: Windows-половина, обе оболочки, причина + сохранение `HOST_TOKEN` в `C:\ProgramData\ucm\agent.conf`; в этой среде непроходимо (pwsh нет), закреплено только на уровне текста генерируемого скрипта |
| 2 | MINOR | Тело ответа печаталось целиком и в WARN, и в `die`: многострочная HTML-страница прокси на 5xx залила бы cron/syslog строками без префикса `[ucm-ssh-agent]` | Добавлен `brief()` (`tr '\n\t' '  '` + `cut -c1-160`), обе точки вывода причины проходят через него. Проверено `sh -n`/`bash -n` на обеих POSIX-сборках; закрепление рантаймом (многострочный 5xx → одна строка с префиксом, ≤ 160 символов) — задача Tester'а |
| 3 | NOTE | Строка безопасна: `log()` = `printf '[ucm-ssh-agent] %s\n' "$1"` (формат — первый операнд), расширение переменной в двойных кавычках без word splitting/глобинга/повторного разбора | Принято, проверено ревьюером в sh/bash/dash; busybox ash не проверялся |
| 4 | NOTE | Ветка цела: `sed` снимает только `^BOOTSTRAP_TOKEN=`, `chmod 600`, `return 0`, `$CONF.tmp.$$` съедается `mv -f` | Принято; остаток temp-файла возможен только при осечке `sed` — поведение вне этого дифа, и §3 чек-листа уже требует отсутствия `agent.conf.tmp.*` |
| 5 | NOTE | Раздел чек-листа: новые пункты легли в §4 «Public KRL…», хотя по смыслу это §3 | Оставлено как есть (§4 переписан под «KRL проверяется по сертификату» — это ровно §4-шный предмет); путающие заголовки не правим ради правки |
| 6 | NOTE | Состав прод-изменений после `9e9ab3c16` | Подтверждено ревьюером: `git diff 9e9ab3c16..a0c950daf --stat` = только `backend/services/ucm_agent_scripts.py` (1 строка лога + 2 комментария), остальное тесты и docs |

Ревьюер отдельно подтвердил: выпуск ветки локально (без push/PR) после ручного прогона чек-листа допустим; непроходимые в этой среде разделы перечислены в конце этого отчёта и в чек-листе.

Порядок закрытия IMPORTANT №1 повлиял на тесты: текстовая половина теста
`test_the_posix_scripts_parse_and_carry_the_answer_exactly_once` (авторства Tester'а) была
переведена на новую форму строки (`$(brief "${resp:-no response}")`) — рантайм-половина того же
набора, которая и является настоящим доказательством (причина UCM в логе, `HOST_TOKEN` сохранён,
exit 0), не изменялась.

Закрытие MINOR из Tester-раунда 9 (тот же класс утечки, который лечил `brief()`): тело ответа
печаталось дословно ещё в трёх точках — `renew refused:` (две) и `check-in refused:` (одна), то есть
прокси-5xx на обычном тике таймера залил бы лог безпрефиксными строками именно там, хотя enroll-точки
уже были защищены. Все три теперь проходят через `brief()`. Windows-половина в этой правке не нуждалась:
tam `Invoke-RestMethod` при HTTP-ошибке бросает `HttpResponseException` (ветка catch), а
`renew refused: $($resp.message)` печатает поле制御ного JSON-ответа, а не сырое тело. Проверено
`sh -n`/`bash -n` и целевыми наборами (89 passed в `test_ucm_agent_scripts.py` + `test_ssh_managed_hosts.py`).

NOTE Tester-а про `cut -c1-160` принята как есть: в раннере `cut` работает в C/POSIX-локали и режет по
байтам, поэтому нет-ASCII-причина длиннее 160 байт может быть рассечена на середине символа. Все причины
отказа этой системы — ASCII (сообщения `host_management.py`/политик CA), практика не затронута; при
появлении локализованных причин — вызывать `brief()` с `LC_ALL=C.UTF-8`, чтобы `-c` считал символы.

---

## Tester раунды 9–10 (2026-11-22) и закрытие цикла: вердикт **ок**, дальнейших раундов нет

Раунд 9: 358 passed / 4 skipped; PG ×3 по 346; полный 17149 passed / 1 разрешённый baseline.
Раунд 10: 362 passed / 4 skipped; PG ×3 по 350; полный 17153 passed / 1 разрешённый baseline (6:00).
Коммиты: `4210903a3` (причина отказа UCM в обеих половинах + `brief()`), `5ed7dd1a5` (свёртка трёх
оставшихся POSIX-точек), `61614069f` (тесты, крепящие контракт вместо пунктуации исходника).

Цикл остановлен намеренно: последние две находки — MINOR/NOTE одного и того же класса (видимость и
свёртка текста отказа) и касаются только Windows-половины агента, которую в этой среде исполнить нечем
(pwsh 5.1 / 7 нет). Дальнейшие раунды плодили бы только новые строки логов, поэтому они записаны
долгом, а не лечатся бесконечно:

| ID | Уровень | Что не так | Статус |
|---|---|---|---|
| **D11** | MINOR | В PowerShell-раннере `WARN enrollment failed ($($_.ErrorDetails.Message))` не сворачивается: аналога `brief()` там нет, поэтому многострочная HTML-страница прокси ляжет в лог планировщика несколькими строками без префикса. Сузит видимость причины, поведение не меняет | **Долг.** Требует pwsh 5.1 и 7 для проверки; лечится одним хелпером `Brief` + его использованием в этой единственной строке |
| **D12** | NOTE | На Windows причина отказа check-in/renew вообще не печатается (`check-in failed (will retry on next run)`), то есть POSIX-половина информативнее Windows | **Долг.** Это изменение поведения Windows-ветки, в задачу не входило |

Оба закрыты пунктом чек-листа §3 (Windows-половина, обе оболочки) — до релиза на живой Windows-машине.

---

## UI-прогон §8 (2026-11-22, реальный браузер на живом стенде): два дефекта найдено и исправлено

Прогон в Chrome на `https://127.0.0.1:8443/ssh/hosts` (стенд: UCM + реальный OpenSSH). Страница, KPI-карточки
(Hosts / Online / Expiring / Revoked), поиск, таблица со всеми бейджами, группа SSH в сайдбаре — на месте.
Мастер Connect Server: оба выбора CA, поле hostname, «Generate install command» → `curl -sSL
"…/ssh/agent-setup?token=ucm_boot_…" | sudo bash` + Copy + подсказка про одноразовость и 4 часа; новая строка
в таблице с настоящим hostname, `None yet` и auto-renew ON. Переключатель auto-renew ON → OFF без перезагрузки.
Reinstall → новый one-liner с новым bootstrap-токеном. Rotate → диалог подтверждения. Delete → «Unlink
walk5.lab.internal from UCM? …» и строка уходит. Пустой результат поиска → «No matching results …».

**D13 (FIXED, `15d822400`)** — поле hostname в мастере: `onChange={(v) => …}` при том, что общий `Input`
передаёт в `onChange` DOM-событие (так устроены все остальные страницы: `e.target.value`). React-состояние
становилось событием, контролируемое поле рисовало `[object Object]`, и хост создался бы с таким hostname.
**D14 (FIXED, `15d822400`)** — то же самое в поле причины отзыва (`onChange={setRevokeReason}`): в KRL и в
аудит ушло бы событие вместо написанного текста. Закреплено двумя тестами в `SSHHostsPage.pull-only.test.jsx`:
на старом монтаже оба падают именно со значением `'[object Object]'`, на исправленном — 13 passed.

**Почему страница была мёртвой до прогона (дефекта в исходниках нет):** стенд отдавал устаревшую сборку SPA
(`frontend/dist` не в git, собирается при упаковке) — её чанк `SSHHostsPage` импортировал `Server`, которого
в `@phosphor-icons/react` 2.1.10 нет (проверено на самом пакете: `typeof Server === undefined`, `HardDrives`
есть) → `ReferenceError: Server is not defined` в `useMemo` статистики → страница не выходила из «Loading…».
HEAD импортирует `HardDrives`. Ручной прогон: пересобрать фронтенд (`npx vite build`) или брать пакетную установку.

**Открытым записано (не трогано: это общий код дизайн-системы, а не эта фича):**

| ID | Уровень | Что не так | Статус |
|---|---|---|---|
| **D15** | MINOR | Кнопка закрытия общего `Modal` (`Dialog.Close`, внутри только иконка `<X>`) не имеет доступного имени — скринридер объявляет её как просто «button». `Modal` использует 33 страницы, включая эту | **Долг дизайн-системы** (один `aria-label`), вне рамок этой фичи |
| **D16** | MINOR | Общие `Input`/`Textarea` рисуют `<label>` без `htmlFor`/`id`: подпись не связана с полем (WCAG 1.3.1 / 3.3.2) — во всём приложении | **Долг дизайн-системы**, здесь не менялось |
| **D17** | **FIXED** | Диалог отзыва открывался с предзаполненной причиной `key compromise`: не поменявший текст оператор отправлял в KRL и аудит причину, которую никто не утверждал | Дефолт пустой: UCM пишет `unspecified` (`host_management.py: (data.get('reason') or 'unspecified')`), и причина, набранная для одного хоста, больше не переезжает к следующему. Проверено в браузере: поле открывается пустым |
| **D19** | **FIXED** | `SSHHostsPage` | Таблица с `table-layout: fixed` резала строку сертификата («Dec 22, 2026, 02:17 AM • #1»需要 162 px, доставалось 51) и колонку KRL («Synced 7h …») | Колонкам `cert_status` и `last_krl_sync_at` задана собственная ширина (200 / 140 px): замер в браузере — ни одного обрезанного элемента больше |
| **D20** | **FIXED** | `SSHHostsPage` | Колонка действий (до пяти иконочных кнопок) выходила за правый край таблицы на 17 px — Delete обрезался | Колонка `actions` получила свою ширину (160 px): последний правый край 1410 при правом краю таблицы 1438 |
| **D23** | **FIXED** | `frontend/src/components/Select.jsx` (общий компонент) | Оба комбобокса мастера подключения не имели доступного имени: видимый `<label>` ни с чем не связан (`for` отсутствует), а `SelectComponent` вообще не принимает посторонние пропы → `aria-label` с страницы до контрола не доходил. Замер в браузере: `combobox name="(NONE)"` на обоих, `input name="(NONE)"` — для скринридера мастер был тремя безымянными полями | Триггер (Radix и searchable-ветка) получает `aria-label` из видимой подписи; у поля hostname и у поля причины отзыва `aria-label` передан со страницы. Тест «every control in the connect wizard has an accessible name» без этой правки падает (`Unable to find ... role "combobox" and name ...`), с ней — зелёный; полный фронтенд-набор 322 файла / 2551 passed |
| **D22** | **FIXED** | `SSHHostsPage` (11 мест) | Row-действия и кнопки копирования рендерились **пустыми**: страница передавала `Button`-у проп `icon={Warning}`, которого у общего `Button` нет (`Button.jsx` рендерит только `{loading ? spinner : children}`, а `{...props}` уходит в DOM) → вместо иконок были слепые капсулы 20×12 px; опознавались только по title/aria-label. Плюс колонка 160 px не вмещала пять кнопок: flex их сжимал, и у кнопки отзыва иконка схлопнулась до 0 px ширины | Иконки передаются детьми, как во всём остальном приложении (`<Button size="sm">…<Warning size={14} /></Button>`), колонка действий 210 px. Замер после фикса: svg 14×14 у всех семи, кнопки 31–35 × 26–27 px (порог WCAG 2.5.8 24×24 выдержан), `needRight 1427 < cellRight 1439`, обрезанных колонок ноль. `grep -rn "<Button[^>]*icon=" frontend/src` — ноль по всему фронтенду |
| **D21** | **FIXED** | `SSHHostsPage` | Бейдж статуса сертификата растягивался на всю колонку (175 px) и выглядел как плашка, а не как пилюля | `items-start` в контейнере ячейки: 73 / 73 / 55 px по тексту |
| **D18** | NOTE | На этом стенде SPA не поднимает websocket-транспорт (`wss://…/socket.io/?transport=websocket` падает), при этом сервер отвечает на polling-рукопожатие (`{"sid":…,"upgrades":["websocket"]}`); хук `transports: ['websocket','polling']` и socket.io — код upstream, в этот дифф не входит | **Наблюдение.** Доставка live-событий через WS на этом стенде не проверена; к фиче отношения не имеет |
