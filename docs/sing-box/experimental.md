# experimental, Clash API и services (sing-box 1.14.2)

Справочник по разделу `experimental` (`cache_file`, `clash_api`, `v2ray_api`, `debug`), по REST API, который поднимает `clash_api`, по разделу `services` (все типы 1.14.2, включая недокументированный `oom-killer`). Поля `certificate_providers` (`acme`, `cloudflare-origin-ca`, `tailscale`) перенесены в [shared.md](shared.md#провайдеры-сертификатов-certificate_provider), здесь от них остались build-теги и [указатель](#раздел-certificate_providers). Всё сверено с исходниками v1.14.2 (ревизия `af6e64c`); где документация расходится с кодом, прав код, и расхождение отмечено. Поведение `sing-box check` проверено на реальном `sing-box.exe` 1.14.2 (windows-amd64).

Обозначения типов: `string`, `int`, `bool`, `duration` (строка в синтаксисе Go: `"10s"`, `"1h30m"`), `string|[string]` — поле `badoption.Listable` (одно значение или массив), `object`, `[object]`, `-> outbound` и т. п. — ссылка на тег. «check» — `sing-box check`: он вызывает `box.New` и сразу закрывает экземпляр, то есть ловит всё, что проверяют конструкторы, и ничего из того, что происходит при старте (открытие файлов, `listen`, загрузки, поиск тегов, которые ищутся лениво).

Смежные файлы: общие вложенные блоки (Listen-поля, Dial-поля, TLS, HTTP2) и поставщики сертификатов — [shared.md](shared.md); HTTP-клиент и `http_clients` — [config.md](config.md#http_clients); `route.final`, правило `clash_mode`, rule-set — [route.md](route.md); DNS-кэш, `optimistic`, fakeip, DNS-сервер `resolved` — [dns.md](dns.md); группы `selector`/`urltest` и `interrupt_exist_connections` — [outbounds.md](outbounds.md); команды `sing-box api …` — [cli.md](cli.md); загрузка конфига и сопоставление ключей — [config.md](config.md); устаревшее — [deprecations.md](deprecations.md).

## Официальная сборка для Windows и build-теги

`sing-box version` у официального `sing-box-1.14.2-windows-amd64` печатает теги: `with_gvisor, with_quic, with_dhcp, with_wireguard, with_utls, with_acme, with_clash_api, with_tailscale, with_ccm, with_ocm, with_cloudflared, with_naive_outbound, with_purego, with_usbip, with_openvpn, with_openconnect` (+ служебные `badlinkname`, `tfogo_checklinkname0`), CGO выключен.

| Возможность | Build-тег | Есть в официальной Windows-сборке | Без тега |
|---|---|---|---|
| `clash_api` | `with_clash_api` | да | box.New: `clash api is not included in this build` — ошибка при **любом** объекте `clash_api`, даже пустом |
| `v2ray_api` | `with_v2ray_api` | **нет** (нет ни в одной официальной сборке, см. `release/DEFAULT_BUILD_TAGS*`) | box.New: `v2ray api is not included in this build` при непустом `listen` |
| service `derp`, cert-provider `tailscale` | `with_tailscale` | да | ошибка конструктора |
| service `hysteria-realm` | `with_quic` | да | ошибка конструктора |
| service `ccm` / `ocm` | `with_ccm` / `with_ocm` | да | ошибка конструктора (`ccm` на macOS ещё требует CGO) |
| service `usbip-server` / `usbip-client` | `with_usbip` и Linux / Windows / macOS+CGO | да | ошибка конструктора |
| cert-provider `acme` | `with_acme` | да | ошибка конструктора |
| service `api`, `resolved`, `ssm-api`, `oom-killer`, cert-provider `cloudflare-origin-ca`, `cache_file`, `debug` | нет (всегда собраны) | да | — |

Исходники: include/registry.go, include/clashapi*.go, include/v2rayapi*.go, include/tailscale*.go, include/quic*.go, include/ccm*.go, include/ocm*.go, include/usbip*.go, include/acme*.go, release/DEFAULT_BUILD_TAGS_WINDOWS.

## Ключи JSON: регистр и дискриминаторы

Общие правила загрузки описаны в [config.md](config.md); для этого файла проверено на 1.14.2:

- Имена полей внутри `experimental` и внутри объектов `services[]` / `certificate_providers[]` сопоставляются **без учёта регистра**: `{"Clash_API": {"External_Controller": "127.0.0.1:19090"}}` и `{"type":"api","SECRET":"s","Dashboard":{"Enabled":true}}` проходят check, `format` выводит их в нижнем регистре. Два ключа, отличающиеся только регистром, не ошибка: побеждает последний.
- **Исключение — дискриминаторы `type` и `tag` элементов типизированных списков** (`services`, `outbounds`, `certificate_providers`, …): они должны быть написаны строго строчными. `{"Type":"api"}` или `{"type":"api","Tag":"x"}` check отвергает: `services[0].Type: json: unknown field "Type"`. Причина: общий объект `{type, tag}` читается без учёта регистра, но при разборе остальных полей из JSON вырезаются только точные ключи `type`/`tag`, а остаток разбирается с `DisallowUnknownFields`.
- Неизвестное поле — ошибка check (`experimental.clash_api.foo: json: unknown field "foo"`).

Исходники: option/service.go, option/certificate_provider.go, option/options.go.

## Раздел experimental

Объект верхнего уровня с четырьмя необязательными подразделами. Каждый создаётся по своему условию (box.go):

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `cache_file` | object | нет | Постоянный кэш на диске, см. [experimental.cache_file](#experimentalcache_file). Создаётся только при `enabled: true`; остальные поля без него ни на что не влияют. |
| `clash_api` | object | нет | REST API в стиле Clash, см. [experimental.clash_api](#experimentalclash_api). **Само наличие объекта** (даже `{}`) создаёт сервер Clash API, менеджер трафика и менеджер режима Clash — без этого (или без службы [`api`](#service-api)) правила `clash_mode` никогда не срабатывают. HTTP-порт открывается только при непустом `external_controller`. |
| `v2ray_api` | object | нет | gRPC-статистика в формате V2Ray, см. [experimental.v2ray_api](#experimentalv2ray_api). Учитывается только при непустом `listen`. |
| `debug` | object | нет | Параметры рантайма Go и отладочный HTTP-сервер, см. [experimental.debug](#experimentaldebug). В документации не описан. |

Исходники: option/experimental.go, box.go (New, preStart).

## experimental.cache_file

Файл базы bbolt, в котором sing-box между перезапусками хранит выбор в группах `selector`, режим Clash, скачанные удалённые rule-set, fakeip-соответствия и (по флагам) DNS-кэш. С 1.8.0 (раньше жил в `clash_api`).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включает кэш. Без него файл не открывается и ничего не сохраняется (исключение — графические клиенты с platform log writer). |
| `path` | string | `cache.db` | Путь к файлу. Относительный — от рабочего каталога процесса (или каталога `-D`), **не** от папки конфига. Переменные окружения не раскрываются. |
| `cache_id` | string | `""` | Пространство имён внутри файла: выбор в selector, раскрытие групп, режим Clash, rule-set, RDRC и DNS-кэш хранятся в отдельной вложенной корзине с этим ключом (так несколько конфигов делят один файл). FakeIP-данные — **общие**, `cache_id` на них не действует. |
| `store_fakeip` | bool | `false` | Сохранять соответствия fakeip-адрес ↔ домен и метаданные пула (см. [dns.md](dns.md)). |
| `store_rdrc` | bool | `false` | Сохранять RDRC — кэш «отклонённых» DNS-ответов для устаревших address-filter полей DNS-правил. С 1.9. **Устарело в 1.14.0, удаление в 1.16.0** (замена — `store_dns`); при использовании check печатает WARN, но проходит. В JSON-схеме опущено. |
| `rdrc_timeout` | duration | `7d` | Срок жизни записи RDRC. Действует только при `store_rdrc: true`. С 1.9. |
| `store_dns` | bool | `false` | С 1.14. Хранить весь DNS-кэш в файле, чтобы он переживал перезапуск (работает вместе с `dns.optimistic`, см. [dns.md](dns.md)). При включении in-memory LRU-кэш DNS не создаётся — ответы читаются из bbolt и пишутся туда асинхронно; при старте сохранённый RDRC стирается, просроченные записи чистятся периодически. |

Что лежит в файле (корзины bbolt): `selected` (группа -> выбранный тег), `clash_mode`, `group_expand` (для GUI-клиентов), `rule_set` (содержимое удалённых rule-set с ETag и хешем URL), `rdrc2`, `dns_cache`, `fakeip_*`. Незнакомые корзины при открытии удаляются.

Поведение:
- Файл открывается на стадии Initialize при старте, **до** групп: selector при своём старте уже читает сохранённый выбор. `sing-box check` файл не создаёт и не открывает.
- Блокировка: bbolt берёт на файл эксклюзивную блокировку (на Windows — `LockFileEx`); открытие повторяется 10 раз с таймаутом 1 с. Второй экземпляр sing-box с тем же `cache.db` (или любой процесс, держащий его открытым) ждёт около 10 с и падает на старте.
- Повреждённый или несовместимый файл удаляется и создаётся заново (в лог: `database corrupted … resetting`); ошибка удаления — ошибка старта.
- Удалённый rule-set при старте сначала восстанавливается из `rule_set`, если хеш URL совпадает; без `cache_file` каждый старт качает его заново — отсюда случаи «check проходит, а старт падает», когда `download_detour`/`http_client` rule-set недоступен и кэшированной копии нет (см. [route.md](route.md)).

Исходники: option/experimental.go, experimental/cachefile/cache.go, experimental/cachefile/dns_cache.go, experimental/cachefile/rdrc.go, experimental/cachefile/fakeip.go, dns/router.go, dns/client.go, route/rule/rule_set_remote.go, box.go.

## experimental.clash_api

Встроенный HTTP-сервер, совместимый с панелями Clash/mihomo (Yacd, metacubexd и т. п.): список прокси, переключение selector, тесты задержки, соединения, логи, режим. Протокол описан в разделе [Clash REST API](#clash-rest-api).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `external_controller` | string | `""` | Адрес `host:port` для HTTP (только TCP, без TLS). Пусто — порт не открывается, но сервер, учёт соединений и режим Clash всё равно работают (см. выше). Адрес не проверяется при check (`"not-an-address"` проходит); ошибка `listen` (занятый порт, неверный адрес) **обрывает старт всего sing-box** (`external controller listen error`). Слушает последним, на стадии Started, через обычный `net.Listen` — Listen-поля sing-box (bind_interface и т. п.) здесь не действуют. |
| `external_ui` | string | `""` | Каталог со статической веб-панелью, отдаётся по `/ui/`. Относительный путь — от рабочего каталога; **переменные окружения раскрываются** (`os.ExpandEnv`). Каталог читается в конструкторе: отсутствие — не ошибка, любая другая ошибка чтения — ошибка check (`read external UI directory`). На Windows путь к существующему обычному файлу check тем не менее пропускает (проверено: ошибка чтения такого «каталога» считается отсутствием) — сбой проявится позже. При старте отсутствующий каталог создаётся, пустой — заполняется загрузкой. |
| `external_ui_download_url` | string | `https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip` | ZIP, который скачивается в пустой `external_ui`. Архив с одной корневой папкой распаковывается без неё. При ошибке распаковки содержимое каталога удаляется. Ошибка загрузки при старте только пишется в лог. |
| `external_ui_download_detour` | string -> outbound | outbound по умолчанию (`route.final` или первый) | Через какой outbound качать панель. Check тег не проверяет; отсутствующий тег даёт ошибку загрузки в логе (старт продолжается). |
| `secret` | string | `""` | Секрет API. Пусто — **аутентификации нет вовсе**. Проверка: заголовок `Authorization: Bearer <secret>` или, только для WebSocket-запросов, параметр `?token=<secret>`. Сравнение не константное по времени. |
| `default_mode` | string | `Rule` | Начальный режим Clash (значение для правил `clash_mode`). Если его нет среди режимов, найденных в правилах, он добавляется в начало списка. Сохранённый в `cache_file` режим при старте имеет приоритет. |
| `access_control_allow_origin` | string\|[string] | `["*"]` | CORS: разрешённые Origin. С 1.10. Разрешены методы GET, POST, PUT, PATCH, DELETE, заголовки `Content-Type`, `Authorization`, кэш preflight 300 с. |
| `access_control_allow_private_network` | bool | `false` | Отвечать на preflight Private Network Access (`Access-Control-Allow-Private-Network`), чтобы публичный сайт мог обратиться к API в локальной сети. С 1.10. |
| `cache_file` | string | — | Устарело в 1.8.0. В 1.14.2 **любое** из пяти старых полей кэша делает box.New ошибкой (`cache_file and related fields in Clash API is deprecated in sing-box 1.8.0, use experimental.cache_file instead.`). Замена — `experimental.cache_file.enabled/path`. |
| `cache_id` | string | — | То же; замена — `experimental.cache_file.cache_id`. |
| `store_mode` | bool | — | То же; режим теперь сохраняется всегда, когда включён `cache_file`. |
| `store_selected` | bool | — | То же; выбор в selector теперь сохраняется всегда, когда включён `cache_file`. |
| `store_fakeip` | bool | — | То же; замена — `experimental.cache_file.store_fakeip`. |

Прочее поведение:
- Логи для `/logs` включаются только при непустом `external_controller`. Поток получает записи **всех** уровней независимо от `log.level` (фильтр — параметр `level` запроса); при этом каждый вызов логгера форматирует сообщение, даже если оно ниже `log.level`. При `log.disabled: true` `/logs` отвечает 204.
- Статика `/ui/` отдаётся **без** проверки секрета (включая листинг каталогов без `index.html`); API — только с секретом.
- Заголовок `Host` не проверяется: без `secret` API на `127.0.0.1` доступен любой локальной программе и, через DNS rebinding, веб-страницам.
- В режиме `debug` у логгера код пытается смонтировать `/debug/pprof` и `PUT /debug/gc`, но из-за затенённой переменной маршрутизатор никуда не подключается: этих путей в Clash API 1.14.2 **нет** (pprof есть только в [experimental.debug](#experimentaldebug)).

Исходники: option/experimental.go, experimental/clashapi.go, experimental/clashapi/server.go, experimental/clashapi/server_resources.go, experimental/clashapi/server_fs.go, experimental/clashapi/api_meta.go, experimental/clashmode/manager.go, experimental/clashmode/mode_list.go, route/rule/rule_item_clash_mode.go, log/observable.go, box.go.

## Clash REST API

Документация sing-box описывает только настройки `clash_api`, сами эндпоинты — нет; всё ниже взято из кода 1.14.2.

### Общие правила Clash API

- База: `http://<external_controller>`. Только HTTP/1.1 без TLS.
- Аутентификация (если задан `secret`): заголовок `Authorization: Bearer <secret>` — ровно слово `Bearer`, один пробел, секрет. Для запросов с `Upgrade: websocket` можно вместо заголовка передать `?token=<secret>` (браузерный WebSocket не умеет свои заголовки). Ошибка — `401 {"message":"Unauthorized"}`.
- Ошибки: JSON `{"message": "..."}`. Типовые: `400 Body invalid`, `404 Resource not found`, `504 Timeout`.
- Имена прокси/групп в пути (`{name}`) — URL-кодированные (`%20`, `%2F` для `/`); сервер дополнительно раскодирует их `PathUnescape`.
- Потоковые эндпоинты (`/traffic`, `/memory`, `/logs`) работают двумя способами: при `Upgrade: websocket` — WebSocket, одно JSON-сообщение на событие; иначе — бесконечный chunked-ответ с JSON-объектом на строку. `/connections` без WebSocket отдаёт один снимок.
- `GET /proxies` и `GET /proxies/{name}` пишут JSON без заголовка `Content-Type: application/json` (Go подставит `text/plain`); остальные ответы — с ним.

### Эндпоинты Clash API

| Метод | Путь | Запрос | Ответ и поведение |
|---|---|---|---|
| GET | `/` | — | `{"hello":"clash"}`; если задан `external_ui` и `Content-Type` запроса не `application/json` — `307` на `/ui/`. |
| GET | `/version` | — | `{"version":"sing-box 1.14.2","premium":true,"meta":true}`. |
| GET | `/configs` | — | `{"port":0,"socks-port":0,"redir-port":0,"tproxy-port":0,"mixed-port":0,"allow-lan":false,"bind-address":"*","mode":"<текущий>","mode-list":[…],"log-level":"…","ipv6":false,"tun":null}`. Порты — всегда 0 (заглушки для панелей). `log-level`: `trace` показывается как `debug`, `fatal`/`panic` — как `error`. |
| PATCH | `/configs` | `{"mode":"<режим>"}` (прочие поля игнорируются) | `204`. Режим ищется в списке сначала точно, потом без учёта регистра; неизвестный молча игнорируется. Смена режима очищает DNS-кэш и сохраняется в `cache_file` (если включён). |
| PUT | `/configs` | любое | `204`, ничего не делает. |
| GET | `/proxies` | — | `{"proxies":{"<tag>":<прокси>, …, "GLOBAL":{…}}}` — все outbound и endpoint с тегом. См. [Объект прокси](#объект-прокси-и-список-proxies). |
| GET | `/proxies/{name}` | — | Объект прокси; `404`, если тега нет. |
| PUT | `/proxies/{name}` | `{"name":"<тег участника>"}` | Переключение selector, `204`. См. [Переключение selector](#переключение-selector-через-api-и-его-сохранение). |
| GET | `/proxies/{name}/delay` | `?timeout=<мс>&url=<https-URL>` | `{"delay":<мс>}`. См. [Тесты задержки](#тесты-задержки-delay). |
| GET | `/group` | — | `{"proxies":[<объекты всех групп>]}` — массив, не словарь. |
| GET | `/group/{name}` | — | Объект группы; `404`, если тег не группа. |
| GET | `/group/{name}/delay` | `?timeout=<мс>&url=<https-URL>` | `{"<tag>":<мс>, …}` — тест всех участников. |
| GET | `/rules` | — | `{"rules":[{"type":"default"\|"logical","payload":"<текст правила>","proxy":"<действие>"}]}`; действие — строка вида `route(proxy)`, `reject`, `reject(drop)`, `direct`. Без правил `rules` = `null`. |
| GET | `/connections` | WebSocket: `?interval=<мс>` (по умолчанию 1000) | Снимок `{"downloadTotal","uploadTotal","connections":[…],"memory"}`; по WebSocket — такой снимок сразу и затем каждые `interval` мс. См. [Соединения](#соединения-connections). |
| DELETE | `/connections` | — | Закрывает все соединения и вызывает сброс сетевого состояния (`ResetNetwork`), `204`. |
| DELETE | `/connections/{id}` | — | Закрывает соединение с этим UUID, `204` (и для несуществующего id). |
| GET | `/traffic` | — | Поток раз в секунду: `{"up":<байт за секунду>,"down":<байт за секунду>}` по всем отслеживаемым соединениям. |
| GET | `/memory` | — | Поток раз в секунду: `{"inuse":<байт>,"oslimit":0}`; первое значение всегда 0 (для графиков панелей). `inuse` = стек + куча в использовании + простаивающая неотданная ОС куча. |
| GET | `/logs` | `?level=trace\|debug\|info\|warn\|warning\|error\|fatal\|panic` (по умолчанию `info`) | Поток `{"type":"<уровень>","payload":"<сообщение>"}` для записей не ниже заданного уровня; неверный уровень — `400`. |
| GET | `/dns/query` | `?name=<домен>&type=<A\|AAAA\|…>` (по умолчанию `A`, имя типа — заглавными) | Запрос через DNS-роутер sing-box (с его правилами), таймаут 10 с. Ответ: `{"Status":<rcode>,"Question":[…],"Server":"internal","TC","RD","RA","AD","CD","Answer":[{"name","type","TTL","data"}],"Authority":[…],"Additional":[…]}` (пустые секции отсутствуют). Неизвестный тип — `400 invalid query type`; ошибка обмена — `500`. |
| POST | `/cache/fakeip/flush` | — | Сбрасывает fakeip-хранилище в `cache_file` (если кэш включён), `204`. |
| POST | `/cache/dns/flush` | — | Очищает DNS-кэш роутера, `204`. |
| POST | `/upgrade/ui` | — | Заново скачивает `external_ui_download_url` в `external_ui`: `{"status":"ok"}`; без `external_ui` — `404`; ошибка — `500`. |
| GET | `/providers/proxies` | — | `{"providers":{}}` — провайдеров в sing-box нет. |
| GET, PUT | `/providers/proxies/{name}` | — | Всегда `404`. |
| GET | `/providers/proxies/{name}/healthcheck` | — | Всегда `404`. |
| GET | `/providers/rules` | — | `{"providers":[]}`. |
| GET, PUT | `/providers/rules/{name}` | — | Всегда `404`. |
| POST | `/script` | — | `400 {"message":"not implemented"}`. |
| PATCH | `/script` | — | `204`, ничего не делает. |
| GET | `/profile/tracing` | — | Всегда `404`. |
| GET | `/ui`, `/ui/*` | — | Только при `external_ui`: `/ui` -> `301` на `/ui/`, дальше файлы каталога. **Без аутентификации.** |

Исходники: experimental/clashapi/server.go, configs.go, proxies.go, api_meta.go, api_meta_group.go, api_meta_upgrade.go, connections.go, dns.go, cache.go, rules.go, provider.go, ruleprovider.go, script.go, profile.go, common.go, errors.go.

### Объект прокси и список proxies

Каждый outbound/endpoint описывается объектом:

| Поле | Тип | Смысл |
|---|---|---|
| `type` | string | Отображаемое имя типа: `Direct`, `Block` -> **`Reject`**, `SOCKS`, `HTTP`, `Shadowsocks`, `VMess`, `Trojan`, `VLESS`, `Hysteria`, `Hysteria2`, `TUIC`, `AnyTLS`, `WireGuard`, `Tailscale`, `SSH`, `ShadowTLS`, `Naive`, `Snell`, `Tor`, `Selector`, `URLTest`, `OpenConnect`, `OpenVPN Client`, `Cloudflared`, …; неизвестный — `Unknown`. |
| `name` | string | Тег. |
| `udp` | bool | Поддерживает ли outbound UDP (для selector — выбранный участник). |
| `history` | [object] | Пусто или один элемент `{"time":"<RFC 3339>","delay":<мс>}` — последний успешный тест задержки этого тега (для группы — её текущего конечного участника). История только в памяти, между перезапусками не хранится. |
| `now` | string | Только у групп: текущий выбор (у `urltest` — `""`, пока тест ещё не выбрал). |
| `all` | [string] | Только у групп: участники в порядке конфига. |

Псевдозапись `GLOBAL` (тип `Fallback`) добавляется для совместимости с панелями: `all` — все теги, кроме `direct`/`block`/`dns`-типов, outbound по умолчанию первым; `now` — тег outbound по умолчанию. Это не настоящая группа: `PUT /proxies/GLOBAL` даёт `404` (если только у вас нет outbound с тегом `GLOBAL`), сменить outbound по умолчанию через API нельзя.

### Переключение selector через API и его сохранение

`PUT /proxies/{group}` с телом `{"name":"<участник>"}`:
- `404` — группы нет; `400 Must be a Selector` — тег не `selector` (`urltest` так не переключить); `400 Selector update error: not found` — имени нет среди участников; `400 Body invalid` — тело не JSON.
- Выбор меняется атомарно в памяти. Затем, если выбор действительно изменился: при включённом `experimental.cache_file` он записывается в `cache.db` (корзина `selected`, ключ — тег группы, с учётом `cache_id`); соединения, открытые через группу, прерываются — внутренние всегда, внешние (от inbound) только при `interrupt_exist_connections: true` у группы (см. [outbounds.md](outbounds.md)); подписчики истории уведомляются.
- **Файл конфига не меняется никогда.** Без `cache_file` выбор теряется при перезапуске.
- При следующем старте selector берёт сохранённый в `cache.db` выбор, **если этот тег всё ещё среди участников** — и это важнее поля `default` в конфиге. Только если сохранённого выбора нет или участник исчез, используется `default` (отсутствующий в участниках `default` — ошибка старта), иначе — первый участник.
- Тот же эффект у gRPC-метода `SelectOutbound` сервиса [`api`](#service-api) и у `sing-box api group select`.

Исходники: experimental/clashapi/proxies.go, protocol/group/selector.go, common/interrupt/group.go, experimental/cachefile/cache.go, daemon/started_service.go.

### Тесты задержки (delay)

**`GET /proxies/{name}/delay?timeout=<мс>&url=<URL>`** — тест одного outbound:
- `timeout` обязателен: целое в диапазоне int16 (до 32767 мс); отсутствует или не число — `400 Body invalid`; 0 или отрицательный — сразу `504`.
- `url`: пусто **или начинается с `http://`** — используется `https://www.gstatic.com/generate_204`. То есть свой URL можно задать только `https://`. URL без схемы не работает (порт не определить) — `503`.
- Тест идёт **напрямую через объект outbound**, минуя правила маршрутизации. Для группы (`selector`/`urltest`) — через её текущий выбор; результат записывается под тегом конечного участника.
- Контекст — `context.Background()` с таймаутом `timeout`: обрыв HTTP-соединения клиентом тест не отменяет.
- Ответы: `200 {"delay":N}`; `504 {"message":"Timeout"}`, если истёк `timeout`; `503 {"message":"An error occurred in the delay test"}` при любой другой ошибке **и при `delay == 0`** (ответ быстрее 1 мс считается ошибкой).
- После теста: успех — запись в историю (`history` в `/proxies`), неудача — удаление записи; все `urltest`-группы, в которые тег входит (в том числе через вложенные группы), тут же пересчитывают выбор. Ручной тест может переключить `urltest`.

**`GET /group/{name}/delay?timeout=<мс>&url=<URL>`** — тест всех участников группы:
- `timeout` обязателен (int32, мс) — общий дедлайн; контекст запроса, обрыв клиента отменяет тест.
- Группа `urltest`: используется **её собственный** `url` из конфига, параметр `url` игнорируется; тест принудительный (без учёта `interval`); если группа уже тестируется, сразу возвращается `{}`.
- Группа `selector`: тестируются все участники с `url` из запроса (правило про `http://` то же), вложенные группы раскрываются рекурсивно, `urltest` внутри тестирует себя сам.
- До 10 тестов параллельно, каждый ещё ограничен 15 с.
- Ответ `200`: словарь `тег -> мс` только для **успешных** участников (неудачные и не успевшие к дедлайну отсутствуют); для вложенных групп — задержка их текущего выбора. Не-группа — `404`.

**Как меряется задержка** (`common/urltest`):
1. `DialContext` к хосту URL через outbound (порт из URL, иначе 80/443). Отсчёт с начала dial; если соединение откладывает рукопожатие до первой записи (VLESS/Trojan и т. п. с ленивым handshake), отсчёт перезапускается после dial — рукопожатие тогда попадает в запрос.
2. `HEAD <url>` через это соединение; TLS к целевому хосту проверяется по хранилищу сертификатов sing-box; редиректы не выполняются; **любой HTTP-статус считается успехом**; HTTP-клиент ограничен 15 с.
3. Результат — миллисекунды от начала до заголовков ответа (uint16). В число входят TCP/TLS/протокольное рукопожатие с сервером прокси, TLS с целевым сайтом и один HTTP-обмен.
4. Если у outbound включён multiplex, сначала делается прогревочный тест, измеряется второй.

**gRPC-вариант** (сервис [`api`](#service-api), метод `URLTest{outboundTag}`, CLI `sing-box api group urltest`): только запускает тесты и сразу возвращает пустой ответ — результаты приходят в потоках `SubscribeGroups`/`SubscribeOutbounds`. URL и таймаут не задаются: `urltest` — свой URL, `selector` — все участники с URL по умолчанию, одиночный outbound — URL по умолчанию.

Для функции «тест задержек» в tray-sing-box отсюда следует: достаточно `clash_api` на `127.0.0.1:<порт>` с `secret`; на каждый узел — `GET /proxies/<tag>/delay?timeout=5000&url=https://…` (или один `GET /group/<selector>/delay` на всех); узел не обязан быть выбран и правила не участвуют. Цена — фиксированный порт: если он занят, **не стартует весь VPN**.

Исходники: experimental/clashapi/proxies.go, experimental/clashapi/api_meta_group.go, common/urltest/urltest.go, protocol/group/urltest.go, constant/timeout.go, daemon/started_service.go.

### Соединения (connections)

Элемент `connections[]`:

| Поле | Смысл |
|---|---|
| `id` | UUID соединения (для `DELETE /connections/{id}`). |
| `metadata.network` | `tcp` / `udp`. |
| `metadata.type` | `<тип inbound>/<тег inbound>` (или только тип). |
| `metadata.sourceIP`, `metadata.sourcePort`, `metadata.destinationIP`, `metadata.destinationPort` | Адреса; порты — строки. |
| `metadata.host` | Домен (сниффинг/запрос) или FQDN назначения. |
| `metadata.dnsMode` | Всегда `normal`. |
| `metadata.processPath` | Путь процесса (если `route.find_process` его определил), с `(пользователь)` или `(uid)`; на Android — имя пакета. |
| `upload`, `download` | Байты. |
| `start` | Время создания (RFC 3339). |
| `chains` | Цепочка групп в порядке Clash: конечный outbound первым, затем группы до сработавшего в правиле (detour-цепочки не показываются). |
| `rule` | `<правило> => <действие>` или `final`. |
| `rulePayload` | Всегда `""`. |

Соединения DNS-типа в список не попадают. `memory` в снимке — то же число, что `inuse` у `/memory`.

Исходники: experimental/clashapi/connections.go, common/trafficcontrol/tracker.go.

## experimental.v2ray_api

gRPC-сервис статистики, совместимый с клиентами V2Ray/Xray (имя сервиса `v2ray.core.app.stats.command.StatsService`), без TLS и без аутентификации. **Требует тега `with_v2ray_api`, которого нет ни в одной официальной сборке**: с официальным `sing-box.exe` любой непустой `listen` делает check ошибкой (проверено, в том числе без `stats`).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `listen` | string | `""` | `host:port` для gRPC. Пусто — раздел игнорируется целиком. Слушает на стадии PostStart. |
| `stats` | object | нет | Настройки счётчиков. Если `stats.enabled` не `true`, сервис статистики не регистрируется, но сам gRPC-сервер (в сборке с тегом) всё равно создаётся и слушает `listen` — пустой, вызовы `StatsService` получают `Unimplemented` (по коду `experimental/v2rayapi/server.go`). |

Объект `stats`:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включает счётчики и сервис `StatsService` (слушает сервер и без него). |
| `inbounds` | [string] -> inbound | `[]` | Теги inbound, для которых считать трафик. Теги не проверяются. |
| `outbounds` | [string] -> outbound | `[]` | Теги outbound (по тегу, выбранному маршрутизацией). |
| `users` | [string] | `[]` | Имена пользователей inbound. |

Счётчики создаются при первом соединении: `inbound>>><tag>>>>traffic>>>uplink|downlink`, `outbound>>>…`, `user>>>…`. Методы: `GetStats{name, reset}` (нет счётчика — ошибка `<name> not found.`), `QueryStats{patterns, regexp, reset}` (подстрока или регулярное выражение; пустой `patterns` — все; устаревшее поле `pattern` **игнорируется**), `GetSysStats{}` (горутины, GC, память, uptime).

Исходники: option/experimental.go, experimental/v2rayapi.go, experimental/v2rayapi/server.go, experimental/v2rayapi/stats.go, experimental/v2rayapi/stats.proto, include/v2rayapi_stub.go, box.go.

## experimental.debug

Параметры рантайма Go и отладочный HTTP-сервер. В документации sing-box не описан (есть только в `schema.json`). Применяются при старте (preStart), check их только разбирает.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `listen` | string | `""` | `host:port` отладочного HTTP-сервера **без аутентификации**: `GET /debug/gc` (204, освобождает память ОС), `GET /debug/memory` (JSON: `heap`, `stack`, `idle`, `goroutines`, `rss`; `rss` = -1 на Windows), `/debug/pprof/` (index, `cmdline`, `profile`, `symbol`, `trace` и именованные профили — куча, горутины со стеками). Ошибка listen — ошибка старта. |
| `gc_percent` | int | не задано | `debug.SetGCPercent`; отрицательное отключает GC. |
| `max_stack` | int | не задано | `debug.SetMaxStack`, байты на стек горутины. |
| `max_threads` | int | не задано | `debug.SetMaxThreads`. |
| `panic_on_fault` | bool | не задано | `debug.SetPanicOnFault`. |
| `trace_back` | string | `""` | `debug.SetTraceback`: значения как у `GOTRACEBACK` (`none`, `single`, `all`, `system`, `crash`, на Windows ещё `wer`). |
| `memory_limit` | int\|string | не задано | Мягкий лимит памяти Go: ставится **2/3 значения** (`SetMemoryLimit(value / 1.5)`). Число байт или строка «число + единица»: `"100 MB"`, `"100mb"`, `"512 KB"`, `"1GB"`, `"1 TB"`, `"100m"` проходят; `"100"` (строка без единицы), `"1.5GB"`, `"100 MiB"`, `"100 kib"` — ошибка разбора. |
| `oom_killer` | bool | — | **Удалено**: любое значение — ошибка box.New (`legacy oom_killer in debug options is removed, use oom-killer service instead`). Замена — сервис [`oom-killer`](#service-oom-killer). |

Исходники: option/debug.go, debug.go, debug_http.go, debug_stub.go, debug_unix.go, box.go.

## Раздел services

Список фоновых служб, не являющихся inbound/outbound/endpoint. С 1.12.0.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — | Тип службы (таблица ниже). Строго строчными (см. [Ключи JSON](#ключи-json-регистр-и-дискриминаторы)). Неизвестный тип — ошибка разбора, причём с неверным текстом `unknown inbound type: <type>`. |
| `tag` | string | индекс в списке | Имя службы (в логах `service/<type>[<tag>]`). **Повторяющиеся теги не ошибка**: check проходит, более поздняя служба молча заменяет более раннюю. |

Службы создаются в box.New после inbound и до outbound (поэтому `ssm-api` может проверить свои inbound при check, а ссылки на outbound разрешаются лениво), стартуют на стадии Start вместе с inbound.

| type | С версии | Платформы | Build-тег | Назначение |
|---|---|---|---|---|
| [`api`](#service-api) | 1.14 | все | — | gRPC API управления экземпляром (+ веб-дашборд) для `sing-box api`, GUI-клиентов и sing-box Dashboard |
| [`ccm`](#service-ccm-и-ocm) | 1.13 | все (macOS — с CGO) | `with_ccm` | прокси-мультиплексор подписки Claude Code |
| [`ocm`](#service-ccm-и-ocm) | 1.13 | все | `with_ocm` | прокси-мультиплексор подписки OpenAI Codex |
| [`derp`](#service-derp) | 1.12 | все | `with_tailscale` | собственный DERP-ретранслятор Tailscale |
| [`hysteria-realm`](#service-hysteria-realm) | 1.14 | все | `with_quic` | точка встречи для NAT traversal Hysteria2 |
| [`resolved`](#service-resolved) | 1.12 | **только Linux** | — | имитация systemd-resolved по D-Bus |
| [`ssm-api`](#service-ssm-api) | 1.12 | все | — | REST API управления пользователями Shadowsocks-серверов |
| [`usbip-server`](#service-usbip-server) | 1.14 | Linux, Windows, macOS+CGO | `with_usbip` | экспорт USB-устройств по USB/IP |
| [`usbip-client`](#service-usbip-client) | 1.14 | Linux, Windows, macOS+CGO | `with_usbip` | импорт удалённых USB-устройств |
| [`oom-killer`](#service-oom-killer) | не документировано | все (режим зависит от платформы) | — | сброс соединений при нехватке памяти |

Ни одна служба не нужна VPN-клиенту; в tray-sing-box раздел `services` вообще не разрешён guard'ом. `acme`, `cloudflare-origin-ca` и `tailscale` из `service/` — не службы, а поставщики сертификатов ([shared.md](shared.md#провайдеры-сертификатов-certificate_provider)).

Общие вложенные блоки — в [shared.md](shared.md): **[Listen-поля](shared.md#поля-прослушивания-listen)** (`listen`, `listen_port`, `bind_interface`, `routing_mark`, `reuse_addr`, `netns`, `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`, `tcp_fast_open`, `tcp_multi_path`, `udp_fragment`, `udp_timeout`, `detour`), **[Dial-поля](shared.md#поля-подключения-dial)**, **TLS** ([inbound](shared.md#входящий-tls-сервер)/[outbound](shared.md#исходящий-tls-клиент)), **[HTTP2-поля](shared.md#параметры-http2-http2-fields)**; **HTTP-клиент** — в [config.md](config.md#http_clients).

Исходники: option/service.go, adapter/service/manager.go, include/registry.go, constant/proxy.go, box.go.

### service api

gRPC-сервер управления запущенным экземпляром — тот же интерфейс, что GUI-клиенты используют локально. Принимает нативный gRPC (HTTP/2, в том числе h2c без TLS), gRPC-Web (`application/grpc-web`, `application/grpc-web-text`) и gRPC-Web поверх WebSocket (совместимо с `@improbable-eng/grpc-web`). С 1.14.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| Listen-поля | — | — | Адрес и порт (только TCP), см. [shared.md](shared.md). |
| `secret` | string | `""` | Секрет: gRPC-метаданные `authorization: Bearer <secret>`. Пусто — без аутентификации. Проверяется для всех gRPC-сервисов сервера (включая health и reflection), но **не** для файлов дашборда. |
| `access_control_allow_origin` | string\|[string] | `["*"]` | CORS для gRPC-Web: методы GET, POST, OPTIONS; заголовки `Content-Type`, `Authorization`, `X-Grpc-Web`, `X-User-Agent`, `Grpc-Timeout`; открытые `Grpc-Status`, `Grpc-Message`, `Grpc-Status-Details-Bin`. |
| `access_control_allow_private_network` | bool | `false` | Ответ на preflight Private Network Access. |
| `dashboard` | bool\|string\|object | нет | Веб-дашборд по `/dashboard/`; любой другой не-gRPC запрос перенаправляется туда (`302`); без дашборда — `404`. `true`/`false` = `{"enabled": …}`; строка = `{"enabled": true, "path": "<строка>"}`. С 1.14. |
| `tls` | object | нет | Inbound TLS; ALPN дополняется `h2` и `http/1.1`. |

Объект `dashboard`:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включить. |
| `path` | string | `dashboard` | Каталог файлов; относительный — от рабочего каталога; переменные окружения раскрываются. Пустой каталог заполняется загрузкой и получает файл `.etag`; непустой без `.etag` считается пользовательским — отдаётся как есть и не обновляется. |
| `download_url` | string | `https://github.com/SagerNet/sing-box-dashboard/archive/refs/heads/gh-pages.zip` | ZIP дашборда. |
| `http_client` | string\|object -> http_client | прямое соединение | Тег из `http_clients` или встроенный объект HTTP-клиента ([shared.md](shared.md)). Неизвестный тег check **не** ловит — старт падает (`start dashboard: create dashboard http client`), если дашборд не пользовательский. |
| `update_interval` | duration | `1d` | Период проверки обновлений (по ETag). |

gRPC: сервис `daemon.StartedService`, версия API 4 (`GetVersion` -> `{version, apiVersion}`), плюс `grpc.health.v1` и reflection. Методы: `GetVersion`, `SubscribeServiceStatus`, `SubscribeLog`, `GetDefaultLogLevel`, `ClearLogs`, `SubscribeStatus{interval}` (интервал — наносекунды, по умолчанию 1 с; память, горутины, число соединений, скорость и итоги трафика), `SubscribeGroups` (группы: `tag`, `type`, `selectable`, `selected`, `isExpand`, участники с `urlTestTime` — Unix-секунды и `urlTestDelay` — мс), `GetClashModeStatus`, `SubscribeClashMode`, `SetClashMode`, `URLTest{outboundTag}`, `SelectOutbound{groupTag, outboundTag}`, `SetGroupExpand` (пишет в `cache_file`), `SubscribeConnections`, `CloseConnection`, `CloseAllConnections`, `GetDeprecatedWarnings`, `GetStartedAt`, `SubscribeOutbounds`, `StartNetworkQualityTest`, `StartSTUNTest`, методы Tailscale (статус, ping, exit node, logout, сертификат, SSH, Taildrop), USB/IP (`ProvideUSBDevices` — для `provider: dynamic`, `SubscribeUSBIPServerStatus`), OpenConnect/OpenVPN (статус и ответы на запросы аутентификации), `SubscribeNotifications`. Методов остановки/перезагрузки экземпляра (`ManagedService`) у этого сервера нет. Режим Clash и учёт соединений включаются самим наличием службы `api` (как у `clash_api`).

CLI: `sing-box api --url <адрес> --secret <секрет> <команда>` (или `BOX_API_URL`, `BOX_API_SECRET`; без схемы подставляется `http://`) — подробно в [cli.md](cli.md).

Исходники: option/api.go, service/api/server.go, service/api/web_bridge.go, service/api/web_bridge_websocket.go, service/api/dashboard.go, daemon/server.go, daemon/started_service.go, daemon/started_service.proto, cmd/sing-box/cmd_api*.go.

### service ccm и ocm

HTTP-прокси, через который удалённые клиенты Claude Code (`ccm`) или OpenAI Codex (`ocm`) пользуются подпиской, авторизованной OAuth на этой машине: sing-box подставляет свой токен доступа, обновляет его и пишет обратно в файл. С 1.13. Поля обоих типов одинаковы.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| Listen-поля | — | — | См. [shared.md](shared.md). |
| `tls` | object | нет | Inbound TLS (ALPN дополняется `h2`). |
| `credential_path` | string | ccm: `$CLAUDE_CONFIG_DIR/.credentials.json`, иначе `~/.claude/.credentials.json` (на macOS сначала связка ключей); ocm: `$CODEX_HOME/auth.json`, иначе `~/.codex/auth.json` | Файл OAuth-учётных данных. Нет файла — **ошибка старта** (`read credentials`). |
| `usages_path` | string | `""` | Файл агрегированной статистики (запросы, токены, стоимость по моделям и пользователям); сохраняется раз в минуту и при остановке. Пусто — не считать. |
| `users` | [object] | `[]` | Пользователи `{name, token}`. Пусто — без аутентификации. Клиент передаёт `Authorization: Bearer <token>` (Claude Code — через `ANTHROPIC_AUTH_TOKEN`). |
| `users[].name` | string | — | Имя для статистики и логов. |
| `users[].token` | string | — | Токен клиента. |
| `headers` | object | нет | Заголовки, добавляемые (с заменой) к запросам в API Anthropic/OpenAI; значение — string или [string]. |
| `detour` | string -> outbound | outbound по умолчанию | Через что ходить к API. Тег ищется лениво: отсутствующий тег проходит check и старт, ошибка — на первом запросе. |

Принимаются только пути `/v1/…`; `ocm` также проксирует WebSocket для `/v1/responses`.

Исходники: option/ccm.go, option/ocm.go, service/ccm/*.go, service/ocm/*.go, include/ccm*.go, include/ocm*.go.

### service derp

Собственный DERP-сервер Tailscale (аналог `derper`). С 1.12.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| Listen-поля | — | — | TCP-адрес HTTPS-сервера. |
| `tls` | object | — | Inbound TLS. **Обязателен и должен быть `enabled: true`**: иначе box.New — `TLS is required for DERP server` (документация этого не говорит). Сертификат читается в конструкторе — отсутствующий файл ловит check. |
| `config_path` | string | — | **Обязателен** (`missing config_path`). JSON с приватным ключом узла; если файла нет, при старте создаётся с новым ключом. Переменные окружения раскрываются. |
| `verify_client_endpoint` | string\|[string] -> endpoint | `[]` | Теги endpoint'ов `tailscale`, через которые проверять клиентов. Отсутствующий или не-Tailscale тег — ошибка на стадии PostStart (check не ловит). |
| `verify_client_url` | string\|object\|[string\|object] | `[]` | URL проверки клиентов. Строка = `{"url": …}`; объект — `url` плюс поля HTTP-клиента ([shared.md](shared.md)); объектная форма — с 1.14. |
| `home` | string | `""` | Что отдавать на `/`: `""` — стандартная страница, `blank` — пустая, `http(s)://…` — редирект `302`. Иное — ошибка старта (`invalid home value`). |
| `mesh_with` | object\|[object] | `[]` | Другие DERP-серверы для mesh. Поля: `server` (string, обязателен), `server_port` (int, обязателен), `host` (string, своё имя хоста), `tls` (outbound TLS; с ним `https://…/derp`, без — `http://`), Dial-поля. |
| `mesh_psk` | string | `""` | Ключ mesh: ровно 64 **строчные** hex-цифры (проверяет check). |
| `mesh_psk_file` | string | `""` | Файл с ключом; содержимое должно быть ровно 64 hex-цифрами — **без перевода строки в конце**, иначе ошибка старта. Используется, если `mesh_psk` пуст. |
| `stun` | int\|object | нет | STUN-сервер по UDP. Число = `{"enabled": true, "listen_port": <число>}`. Объект: `enabled` (bool) + Listen-поля; `listen` по умолчанию `::`, `listen_port` — `3478`. `true` не принимается. |

HTTP-пути: `/derp`, `/derp/probe`, `/derp/latency-check`, `/bootstrap-dns`, `/generate_204`, `/robots.txt`, `/`.

Замечание: `sing-box format` падает на `"stun": <число>` — при сериализации сокращённая форма пишется как `true`, а `true` при повторном разборе не принимается.

Исходники: option/tailscale.go, service/derp/service.go, include/tailscale*.go.

### service hysteria-realm

Сервер встречи для NAT traversal Hysteria2: сервер за NAT регистрирует свои внешние адреса (найденные через STUN), клиенты узнают их и пробивают UDP. Через realm идёт только сигнализация. С 1.14. Поля `realm` у inbound/outbound Hysteria2 — в [inbounds.md](inbounds.md) и [outbounds.md](outbounds.md).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| Listen-поля | — | — | TCP. |
| `tls` | object | нет | Inbound TLS; с ним HTTP/2 поверх TLS (ALPN `h2` добавляется), без — открытый HTTP/1.1 или h2c. |
| HTTP2-поля: `idle_timeout`, `keep_alive_period`, `stream_receive_window`, `connection_receive_window`, `max_concurrent_streams` | duration, duration, int\|string, int\|string, int | нет | Параметры HTTP/2-сервера, см. [shared.md](shared.md). |
| `users` | [object] | — | **Обязателен** (`missing users`). |
| `users[].name` | string | — | **Обязателен**; имя в логах и ключ квоты. |
| `users[].token` | string | — | **Обязателен**; Bearer-токен, который предъявляют inbound/outbound Hysteria2. |
| `users[].max_realms` | int | `0` | Сколько realm-слотов пользователь держит одновременно; `0` — без ограничения. |

Протокол: `POST /v1/{id}` (регистрация), `DELETE /v1/{id}`, `GET /v1/{id}/events`, `POST /v1/{id}/heartbeat`, `POST /v1/{id}/connect`, `POST /v1/{id}/connects/{nonce}`; сессия живёт 60 с без heartbeat.

Исходники: option/hysteria2.go, option/http.go, protocol/hysteria2/realm.go, protocol/hysteria2/realm_server.go, include/quic*.go.

### service resolved

Поддельная служба systemd-resolved на D-Bus: принимает DNS-настройки от других программ (NetworkManager и т. п.) и отвечает на DNS-запросы; парный DNS-сервер `resolved` описан в [dns.md](dns.md). С 1.12.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `listen` | string | `127.0.0.53` | Адрес DNS-слушателя (TCP и UDP). Документация помечает как обязательный, но код подставляет значение по умолчанию. |
| `listen_port` | int | `53` | Порт; то же замечание. |
| прочие Listen-поля | — | — | См. [shared.md](shared.md). |

**Windows:** служба существует только в Linux-сборке; на Windows box.New (и check) — ошибка `resolved service is only supported on Linux`. Больше одной службы `resolved` — ошибка старта.

Исходники: option/resolved.go, service/resolved/service.go, service/resolved/stub.go, service/resolved/resolve1.go, service/resolved/transport.go.

### service ssm-api

REST API управления пользователями и статистикой Shadowsocks-серверов по спецификации Shadowsocks Server Management API v1. Без аутентификации. С 1.12.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| Listen-поля | — | — | TCP. |
| `servers` | object (string -> string) | — | **Обязателен.** Без ключа или с пустым `{}` в 1.14.2 до проверки `missing servers` дело не доходит: check падает с паникой `nil pointer dereference` (`service/ssmapi/server.go:69`, код выхода 2; проверено). Ключ — префикс HTTP-пути, значение — тег inbound `shadowsocks` с `managed: true`. Отсутствующий (`inbound X not found`) или не-managed (`is not a SSM server`) inbound ловит check (проверено). |
| `cache_path` | string | `""` | JSON-файл с трафиком и пользователями: читается при старте, пишется раз в минуту и при остановке (документация упоминает только остановку). |
| `tls` | object | нет | Inbound TLS (ALPN дополняется `h2`). |

Под каждым префиксом: `GET /server/v1/` (`{"server":"sing-box 1.14.2","apiVersion":"v1"}`), `GET|POST /server/v1/users`, `GET|PUT|DELETE /server/v1/users/{username}`, `GET /server/v1/stats[?clear=true]`.

Исходники: option/ssmapi.go, service/ssmapi/server.go, service/ssmapi/api.go, service/ssmapi/cache.go, service/ssmapi/traffic.go, service/ssmapi/user.go.

### service usbip-server

Экспорт локальных USB-устройств по USB/IP (библиотека sing-usbip: совместима со стандартным протоколом, плюс расширения вроде hotplug). С 1.14.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| Listen-поля | — | — | TCP; `listen_port` по умолчанию `3240`. |
| `provider` | string | `default` | `default` — экспортировать локальные устройства из `devices`; `dynamic` — устройства передаёт во время работы клиент службы `api` (GUI на macOS/Android, sing-box Dashboard в Chromium). Иное — ошибка разбора. |
| `devices` | [object] | — | Только для `default`, там **обязателен**: пустой список или пустой объект — ошибка check (`devices: at least one match is required`). Поля — [USB-фильтр](#usb-фильтр-устройств). |

По документации провайдер `default` работает только при запуске через CLI (Linux, Windows, macOS) и требует повышенных прав.

Исходники: option/usbip.go, service/usbip/server.go, service/usbip/service.go, include/usbip*.go.

### service usbip-client

Импорт удалённых USB-устройств с сервера `usbip-server` sing-box (или sing-usbip). С 1.14.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — | **Обязателен** (`missing server address`). |
| `server_port` | int | `3240` | Порт. |
| `devices` | [object] | `[]` | Какие устройства импортировать; пусто — все. Поля — [USB-фильтр](#usb-фильтр-устройств). |
| Dial-поля | — | — | Принимаются все, но действует только `detour` (-> outbound, ищется лениво). |

#### USB-фильтр устройств

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `bus_id` | string | `""` | Идентификатор шины, например `1-2`. |
| `vendor_id` | int | `0` | Vendor ID числом (JSON-число, не hex-строка). |
| `product_id` | int | `0` | Product ID числом. |
| `serial` | string | `""` | Серийный номер. |

Внутри объекта поля объединяются по «И», объекты списка — по «ИЛИ»; в объекте нужно хотя бы одно поле.

Исходники: option/usbip.go, service/usbip/client.go, service/usbip/service.go.

### service oom-killer

Служба следит за потреблением памяти и при угрозе нехватки закрывает все соединения (`ResetNetwork`) и возвращает память ОС. **В документации не описана** (ни в `service/`, ни в changelog; есть в `schema.json`); заменила удалённое `experimental.debug.oom_killer`.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `memory_limit` | int\|string | нет | Лимит памяти (формат — как у `debug.memory_limit`, основание 1024). Задан — режим «лимит»: срабатывание при приближении к лимиту или при критической скорости роста. Не задан — режим «доступная память ОС», если платформа умеет её запрашивать; иначе старт падает: `memory pressure monitoring is not available on this platform without memory_limit`. Windows умеет (библиотека sing: `GlobalMemoryStatusEx`, потребление — рабочий набор процесса), как и Linux и macOS с CGO. |
| `safety_margin` | int\|string | 5 MiB (5·1024·1024 байт) при заданном лимите | Запас до лимита. |
| `min_interval` | duration | `100ms` | Минимальный период замеров; ≤ 0 — ошибка. |
| `max_interval` | duration | `10s` | Максимальный период; ≤ 0 или меньше `min_interval` — ошибка (check ловит). |

Исходники: option/oom_killer.go, service/oomkiller/service.go, service/oomkiller/service_stub.go, service/oomkiller/policy.go, service/oomkiller/timer.go.

## Раздел certificate_providers

Верхний уровень `certificate_providers` (с 1.14): поставщики серверных сертификатов (`acme`, `cloudflare-origin-ca`, `tailscale`), на которые входящий TLS ссылается через `tls.certificate_provider` (строка-тег или встроенный объект). Их код лежит в `service/`, но это не службы раздела `services`. Все поля, проверки и умолчания описаны в [shared.md](shared.md#провайдеры-сертификатов-certificate_provider) (там основное описание), список верхнего уровня — в [config.md](config.md#certificate_providers). Build-теги поставщиков — в таблице [в начале этого файла](#официальная-сборка-для-windows-и-build-теги).

Исходники: option/certificate_provider.go, service/acme/service.go, service/origin_ca/service.go, protocol/tailscale/certificate_provider.go.

## Что ловит check, а что — только старт

Проверено на `sing-box.exe` 1.14.2 для этого раздела (формулировки ошибок — дословно):

| Ситуация | check | Старт |
|---|---|---|
| Старые поля кэша в `clash_api` (`store_selected` и др.) | ошибка `create clash-server: cache_file and related fields in Clash API is deprecated…` | — |
| `v2ray_api.listen` непуст (официальная сборка) | ошибка `create v2ray-server: v2ray api is not included in this build…` | — |
| `debug.oom_killer` задан | ошибка `legacy oom_killer in debug options is removed…` | — |
| `cache_file.store_rdrc: true` | проходит с WARN об устаревании | работает |
| `clash_api.external_controller` — мусор или занятый порт | проходит | **старт падает** (`external controller listen error`) |
| `clash_api.external_ui_download_detour` — нет такого outbound | проходит | ошибка загрузки в логе, старт продолжается |
| `debug.listen` — занятый порт | проходит | старт падает |
| `cache.db` занят другим процессом | проходит (файл не открывается) | старт падает примерно через 10 с |
| service неизвестного типа | ошибка разбора (`unknown inbound type: …`) | — |
| service с `"Type"`/`"Tag"` не в нижнем регистре | ошибка `unknown field "Type"` | — |
| два service с одним тегом | **проходит** (поздний заменяет ранний) | — |
| `resolved` на Windows | ошибка `resolved service is only supported on Linux` | — |
| `ssm-api`: inbound не найден / не managed | ошибка | — |
| `ssm-api` без `servers` или с `servers: {}` | паника (код выхода 2), не `missing servers` | — |
| `clash_api.external_ui` указывает на обычный файл (Windows) | проходит | сбой позже |
| `derp` без `tls.enabled` / без `config_path` / нет файла сертификата | ошибка | — |
| `derp.verify_client_endpoint` — нет такого endpoint; неверный `home`; `mesh_psk_file` с переводом строки | проходит | старт падает |
| `hysteria-realm` без `users` или без `name`/`token` | ошибка | — |
| `usbip-server` без `devices` (provider `default`), пустой фильтр; `usbip-client` без `server` | ошибка | — |
| `oom-killer`: `max_interval < min_interval` | ошибка | — |
| `ccm`/`ocm`: нет файла учётных данных | проходит | старт падает (`read credentials`) |
| `ccm`/`ocm`/`usbip-client`: `detour` на несуществующий outbound | проходит | старт проходит, ошибка на первом запросе |
| `api.dashboard.http_client` — неизвестный тег | проходит | старт падает, если дашборд качается |

Проверки поставщиков сертификатов (`acme`, `cloudflare-origin-ca`, `tailscale`) — в [shared.md](shared.md#что-ловит-check-а-что-всплывает-позже).

## Расхождения документации и кода

- `clash_api`: документация не описывает REST API вообще; альтернатива заголовку — `?token=` для WebSocket — не упомянута; пути `/debug/*` в Clash API 1.14.2 фактически не подключены (ошибка затенения переменной в `setupMetaAPI`).
- `clash_api` — старые поля кэша: документация пишет «deprecated в 1.8.0», в коде они уже приводят к ошибке box.New.
- `external_ui`, `dashboard.path`, `acme`/`cloudflare-origin-ca` `data_directory`, `derp.config_path`: код раскрывает переменные окружения (`os.ExpandEnv`) — не документировано. «Относительно каталога конфигурации» в документации `external_ui` фактически означает рабочий каталог процесса (`-D`), а не папку файла конфига.
- `v2ray_api`: документация не говорит, что без тега `with_v2ray_api` (все официальные сборки) ошибкой становится уже `listen` без `stats`, и что при `listen` без `stats.enabled` сервер слушает порт впустую (без сервиса статистики); поле `QueryStatsRequest.pattern` игнорируется.
- `experimental.debug` и служба `oom-killer` в документации отсутствуют (есть только в `schema.json`); индекс служб не содержит `oom-killer`.
- `services[].tag` в документации описан как «тег endpoint» (опечатка); ошибка неизвестного типа службы говорит `unknown inbound type`; повторные теги служб не отвергаются (у inbound/outbound/cert-provider — отвергаются).
- `derp.tls`: в документации необязателен, в коде обязателен (`TLS is required for DERP server`). У `derp.stun` документация одновременно называет `listen`/`listen_port` обязательными и даёт им значения по умолчанию — код подставляет `::` и `3478`. `mesh_psk` должен быть строчным hex (64 символа) — не документировано.
- `resolved`: документация помечает `listen`/`listen_port` обязательными, код подставляет `127.0.0.53`/`53`; ограничение «только Linux» в документации явно не сказано.
- `ssm-api.cache_path`: документация — «сохраняется перед остановкой», код — ещё и раз в минуту, и загружается при старте.
- `ssm-api.servers`: проверка `missing servers` в коде недостижима — `options.Servers.Size()` вызывается у nil-указателя, и без `servers` (или с `{}`) `check` 1.14.2 падает с паникой.
- `usbip-client`: документация «действует только `detour`» — подтверждено кодом (остальные Dial-поля принимаются и игнорируются).
- `sing-box format` ломается на `derp.stun` в числовой форме (сериализуется как `true`).
- Не проверено: путь хранилища certmagic по умолчанию на Windows (по коду certmagic — от `HOME`/`USERPROFILE`). Разрешено редактором по исходникам библиотеки sing той версии, что в go.mod 1.14.2: основание единиц `memory_limit`/`safety_margin` — 1024 (тип `MemoryBytes`, `"100 MB"` = 100 МиБ); `oom-killer` без `memory_limit` на Windows работает — `memory.AvailableAvailable()` там истинно (`GlobalMemoryStatusEx`), а потребление берётся как рабочий набор процесса (`GetProcessMemoryInfo`); вне Linux, Windows и macOS с CGO такой режим недоступен.

## Заметки для tray-sing-box

- Guard приложения уже запрещает раздел `services`, ключи `external_ui`/`external_ui_download_url`, любой `experimental.debug.listen`, не-loopback `clash_api.external_controller`/`v2ray_api.listen` и `cache_file.path` вне имени файла в каталоге данных. Раскрытие переменных окружения в `external_ui`, `dashboard.path`, `data_directory` — ещё один довод держать эти ключи закрытыми: sing-box работает с повышенными правами. Под приложением окружение sing-box собирается заново (`process.SingBoxEnv`: системные каталоги, `PATH`, `TEMP`/`TMP` и `USERPROFILE` в каталоге данных, плюс переключатели `ENABLE_DEPRECATED_*`), так что `$VAR` раскрывается только из этого набора, а не из переменных пользователя.
- `v2ray_api` в официальных сборках не работает — не предлагать.
- Если в конфиге есть `selector` и включён `cache_file`, выбор, сделанный через Clash API / `sing-box api`, при каждом перезапуске важнее `default` в конфиге. Способ переключения сервера в приложении (правка правил и `route.final`) этим не затронут, но правка `default` у selector не подействует, пока в `cache.db` есть сохранённый выбор существующего участника.
- Тест задержек: `GET /proxies/{tag}/delay` меряет узел независимо от маршрутизации и текущего выбора; только `https://`-URL; `timeout` обязателен; результат 0 мс считается ошибкой; ручной тест может переключить `urltest`-группу. Порт `external_controller` фиксирован в конфиге и при занятости валит старт всего VPN — нужен неконфликтный порт и обязательный `secret` (Host не проверяется, CORS по умолчанию `*`).
