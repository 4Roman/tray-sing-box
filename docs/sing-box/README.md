# Интерфейс sing-box 1.14.2 — справочник

Справочник по внешнему интерфейсу sing-box — командной строке и конфигу — для проекта tray-sing-box (менеджер sing-box в трее Windows). Описана версия **1.14.2**: последняя стабильная, выпущена 24.09.2026 (тег `v1.14.2`, ревизия `af6e64c`). Ветка 1.15.0-alpha в справочник не входит; где это важно для обновления, есть прогноз ([deprecations.md](deprecations.md#1150-alpha-прогноз-не-проверено)).

Как составлялось: поля и поведение взяты из исходников v1.14.2 (`option/*.go` — перечень полей, `protocol/**`, `dns/**`, `route/**`, `common/**`, `experimental/**`, `service/**`, `cmd/sing-box/**`) и библиотеки `github.com/sagernet/sing` той версии, что указана в `go.mod`. Спорные места проверены на официальной сборке `sing-box-1.14.2-windows-amd64` командами `check`, `format`, `version`, `generate`, `rule-set` — без `run`, сетевых команд и `api`. Поэтому всё, что происходит при запуске или на соединении, установлено чтением кода; в файлах это помечено «по коду», а проверенное на бинарнике — «проверено». Где документация sing-box расходится с кодом, прав код; расхождения собраны в конце каждого файла. Текст пересказан своими словами, документация sing-box не копировалась.

## Файлы справочника

| Файл | Что описывает |
|---|---|
| [config.md](config.md) | Конфиг как целое: ключи верхнего уровня; правила разбора JSON (синтаксис, неизвестные поля, регистр ключей, повторы, числа, Listable, длительности, `null`); пространства имён тегов; секции `log`, `ntp`, `certificate`, `certificate_providers` (список), `http_clients` (и объект HTTP-клиента — основное описание), `network_namespaces`; жизненный цикл `box.New` → `Start` → `Close`; главная таблица «что ловит check, что падает при запуске, что ломает отдельные соединения». |
| [cli.md](cli.md) | Командная строка: все команды и флаги, откуда берётся конфиг (`-c`, `-C`, `-D`, `stdin`, слияние файлов, комментарии, `$schema`), `check`, `format`, `merge`, `version`, `generate`, `rule-set`, `geoip`/`geosite`, `tools`, `api`; коды завершения; переменные окружения, в том числе `ENABLE_DEPRECATED_*`; особенности Windows; как sing-box запускает приложение. |
| [inbounds.md](inbounds.md) | Входящие: все 19 типов, пользователи по протоколам, TLS у входящих, `detour` и инъекция соединений, подробно `tun` (адреса, маршруты, `dns_mode`, `strict_route`, поведение на Windows). |
| [outbounds.md](outbounds.md) | Исходящие (20 рабочих типов и 3 удалённых), группы `selector`/`urltest`, эндпоинты `wireguard`, `tailscale`, `openconnect`, `openvpn-client`, `openvpn-server`; общее пространство тегов, граф зависимостей и порядок старта, поле `network`, build-теги официальной сборки. |
| [shared.md](shared.md) | Общие блоки: dial-поля и `domain_resolver`, listen-поля, UDP NAT, TLS клиента и сервера (движки, uTLS, ECH, Reality, фрагментация и spoof, встроенный ACME), поставщики сертификатов и DNS-01, V2Ray-транспорты, multiplex, TCP Brutal, UDP over TCP, поля HTTP/2 и QUIC, поиск соседей, Wi-Fi. HTTP-клиент и pre-match здесь только упомянуты. |
| [dns.md](dns.md) | Секция `dns`: общие параметры и кэш, все типы DNS-серверов, устаревший формат и миграция, FakeIP, DNS-правила и действия, режимы правил legacy и новый, что ловит check. |
| [route.md](route.md) | Секция `route`: поля, правила и логические правила, все действия, сниффинг, pre-match (основное описание), rule-set (`inline`, `local`, `remote`, исходный и бинарный формат, AdGuard), регистр ключей в `route`, платформы. |
| [experimental.md](experimental.md) | Build-теги официальной сборки для Windows; `experimental` (`cache_file`, `clash_api` и его REST API, `v2ray_api`, `debug`); `services` (`api`, `ccm`/`ocm`, `derp`, `hysteria-realm`, `resolved`, `ssm-api`, `usbip-*`, `oom-killer`). |
| [deprecations.md](deprecations.md) | Механизм устаревания 1.14.2 и переменные `ENABLE_DEPRECATED_*`, полный список заметок, жёстко удалённые возможности с сообщениями, изменения по версиям 1.8 → 1.14, устаревшие поля по типам, таблица миграции «было → стало», что проверить перед обновлением sing-box. |

Где у блока несколько потребителей, полное описание лежит в одном месте, а остальные файлы ссылаются на него: listen-поля, поставщики сертификатов и поля QUIC — в shared.md; HTTP-клиент — в config.md; pre-match — в route.md.

Обозначения во всех файлах: типы JSON (`string`, `int`, `bool`, `object`, `[object]`); `string|[string]` — поле `badoption.Listable`; `duration` — строка длительности Go; `size` — объём памяти; `-> outbound`, `-> dns server`, `-> rule-set`, `-> http_client` и т. п. — строка-тег, ссылка на элемент другого списка; «с 1.X» — поле появилось в 1.X (отмечается для 1.10 и новее); «check» — `sing-box check`.

## Карта конфига

| Ключ верхнего уровня | Что внутри | Где описано |
|---|---|---|
| `$schema` | URI JSON Schema для редактора | [cli.md](cli.md#ключ-schema-и-команда-schema) |
| `log` | журнал сервиса | [config.md](config.md#log) |
| `dns` | `servers[]`, `rules[]`, `final`, кэш, стратегия | [dns.md](dns.md#верхний-уровень-dns); серверы — [dns.md](dns.md#dns-серверы-общие-поля-и-сводка-типов); правила — [dns.md](dns.md#dns-правила); действия — [dns.md](dns.md#действия-dns-правил) |
| `ntp` | встроенный NTP-клиент | [config.md](config.md#ntp) |
| `certificate` | доверенные корневые сертификаты экземпляра | [config.md](config.md#certificate) |
| `certificate_providers` | поставщики серверных сертификатов | список — [config.md](config.md#certificate_providers); поля — [shared.md](shared.md#провайдеры-сертификатов-certificate_provider) |
| `http_clients` | общие HTTP-клиенты для собственных запросов sing-box | [config.md](config.md#http_clients) |
| `network_namespaces` | сетевые пространства имён (только Linux) | [config.md](config.md#network_namespaces) |
| `endpoints` | wireguard, tailscale, openconnect, openvpn-client, openvpn-server | [outbounds.md](outbounds.md#сводка-типов-эндпоинтов) |
| `inbounds` | входящие, в том числе `tun` | [inbounds.md](inbounds.md#сводка-типов-входящих); `tun` — [inbounds.md](inbounds.md#tun) |
| `outbounds` | исходящие и группы | [outbounds.md](outbounds.md#сводка-типов-исходящих); группы — [selector](outbounds.md#selector), [urltest](outbounds.md#urltest) |
| `route` | `rules[]`, `rule_set[]`, `final`, умолчания для dial | [route.md](route.md#раздел-route); правила — [route.md](route.md#правило-маршрутизации); действия — [route.md](route.md#действия-правил); rule-set — [route.md](route.md#rule-set) |
| `services` | api, derp, resolved, ssm-api и др. | [experimental.md](experimental.md#раздел-services) |
| `experimental` | `cache_file`, `clash_api`, `v2ray_api`, `debug` | [experimental.md](experimental.md#раздел-experimental) |

Вложенные блоки, которые встречаются во многих местах:

| Блок | Где встречается | Где описан |
|---|---|---|
| dial-поля (`detour`, `bind_interface`, `domain_resolver`, …) | исходящие, эндпоинты, DNS-серверы, NTP, HTTP-клиент | [shared.md](shared.md#поля-подключения-dial) |
| listen-поля (`listen`, `listen_port`, `udp_timeout`, …) | входящие, сервисы, openvpn-server | [shared.md](shared.md#поля-прослушивания-listen) |
| `tls` клиента | исходящие, DNS-серверы `tls`/`quic`/`https`/`h3`, HTTP-клиент | [shared.md](shared.md#исходящий-tls-клиент) |
| `tls` сервера | входящие, сервисы | [shared.md](shared.md#входящий-tls-сервер) |
| `transport` | vmess, vless, trojan | [shared.md](shared.md#v2ray-транспорты-transport) |
| `multiplex` | shadowsocks, vmess, vless, trojan | [shared.md](shared.md#мультиплексирование-multiplex) |
| `udp_over_tcp` | shadowsocks, socks, naive | [shared.md](shared.md#udp-over-tcp-udp_over_tcp) |
| поля QUIC | hysteria, hysteria2, tuic, HTTP-клиент версии 3 | [shared.md](shared.md#параметры-quic-quic-fields) |
| поля HTTP/2 | HTTP-клиент версии 2, hysteria-realm | [shared.md](shared.md#параметры-http2-http2-fields) |
| UDP NAT | tun, tproxy, wireguard, openvpn, openconnect | [shared.md](shared.md#udp-nat) |
| `http_client` (тег или объект) | удалённые rule-set, `acme`, `cloudflare-origin-ca`, realm hysteria2, дашборд `api`, DERP | [config.md](config.md#ссылка-на-клиент-тег-или-объект) |

## Правила, которые нужно знать

- **Синтаксис.** Конфиг — JSON с комментариями `//`, `/* */`, `#` и висячими запятыми; UTF-8 BOM, одинарные кавычки и ключи без кавычек — ошибка. Несколько файлов (`-c` несколько раз, `-C`) сливаются: объекты рекурсивно, массивы складываются, у конфликтующего скаляра побеждает файл, который раньше по сортировке путей ([cli.md](cli.md#слияние-нескольких-файлов)).
- **Неизвестные поля** — ошибка разбора `json: unknown field` почти везде. Молча отбрасываются лишние ключи только в нескольких местах (все — типы со своим нестрогим `UnmarshalJSON`): секция `certificate`, правила (маршрутизации и DNS) с действием `reject` или `route-options`, объект `obfs` типа `salamander` у hysteria2, объект `domain_resolver`, объект `stun` у службы `derp` (проверено) ([config.md](config.md#строгость-неизвестные-поля)).
- **Регистр ключей.** Имена полей сопоставляются без учёта регистра и с простым свёртыванием Unicode (KELVIN SIGN = `k`, LONG S = `s`): `"Detour"` — это `detour`. Исключения: ключи-дискриминаторы двухпроходных объектов (`type` и `tag` у inbounds, outbounds, endpoints, services, certificate_providers, network_namespaces, DNS-серверов, rule-set; ключи условий и `action` в правилах — в зависимости от действия; базовые ключи `http_clients` при `version` 2 и 3) нужно писать строго строчными, иначе `unknown field`. Значения (`type`, теги, ссылки на теги, домены в условиях) чувствительны к регистру. Повтор ключа — не ошибка, побеждает последний ([config.md](config.md#регистр-ключей), [route.md](route.md#регистр-ключей-в-разделе-route), [dns.md](dns.md#ключи-и-неизвестные-поля-внутри-dns)).
- **Listable.** Поле `string|[string]` принимает одно значение или массив; `format` сворачивает массив из одного элемента в строку ([config.md](config.md#listable-значение-или-список)).
- **Длительности** — только строкой Go (`"300ms"`, `"1h30m"`, плюс `d` = 24 часа); число — ошибка, `""` — ошибка, `"0"` допустим. Исключения: `udp_timeout` принимает и целое число секунд, `fallback_delay` в `route-options` — целое число наносекунд ([config.md](config.md#длительности-duration), [route.md](route.md#route-options)).
- **Объёмы** (`size`) — число байт или строка с единицей, основание 1024, `KiB`/`MiB` не принимаются; скорости `up`/`down` hysteria v1 — свои сетевые единицы ([shared.md](shared.md#условные-обозначения)).
- **Теги и пространства имён.** Исходящие и эндпоинты делят одно пространство; входящие, DNS-серверы, rule-set, службы, поставщики сертификатов и HTTP-клиенты — каждый своё. Без `tag` тегом становится номер элемента (у rule-set, `http_clients` и `network_namespaces` тег обязателен). Повтор тега — ошибка check, кроме DNS-серверов и служб: там более поздний молча заменяет ранний ([config.md](config.md#теги-и-пространства-имён)).
- **check против запуска.** `sing-box check` = разбор + `box.New` + `Close`, без `Start`. Он ловит синтаксис, типы, неизвестные поля, повторы тегов, файлы, которые читаются при создании, ссылки DNS-правил и `route_address_set` на rule-set, `domain_resolver` исходящих. Только **при запуске** падают: зависимости и кольца `detour`/групп, `route.final`, `dns.final`, `rule_set`/`preferred_by` правил маршрутизации, теги `http_client` и `route.default_http_client`, `detour` и `domain_resolver` DNS-серверов, загрузка удалённого rule-set без кэша и без `initial_path`, порты, TUN, `cache.db` и `external_controller`. **Только на соединениях** ломаются `outbound` правила, `server` DNS-правила, `resolve.server`, `detour` исходящего на «пустой» `direct`. Сводная таблица — [config.md](config.md#где-всплывает-ошибка-check-запуск-отдельные-соединения).
- **Устаревание.** Заметка, у которой удаление назначено на текущую или следующую минорную версию, без `ENABLE_DEPRECATED_<ИМЯ>=true` (значение по `strconv.ParseBool`) — FATAL и в `check`, и в `run`. В 1.14.2 таких три: пункт `outbound` в DNS-правиле, отсутствие резолвера доменов, `domain_strategy` в dial-полях. Ловушка: при двух и более DNS-серверах любой `direct` требует `route.default_domain_resolver` ([deprecations.md](deprecations.md#механизм-устаревания-в-1142)).
- **Пути.** Относительные пути в конфиге отсчитываются от рабочего каталога процесса, а не от папки конфига; часть путей раскрывает `$VAR` (не `%VAR%`) ([cli.md](cli.md#рабочий-каталог-и-относительные-пути)).
- **Журнал.** Без `log.level` уровень — `trace`; сообщения CLI (ошибки разбора, `FATAL start service`, заметки устаревания) всегда идут в stderr, а не в `log.output` ([config.md](config.md#log)).

## Как это использует tray-sing-box

### Команды

| Когда | Команда | Как |
|---|---|---|
| Запуск VPN | `sing-box.exe run -c <Data>\config.json` | Рабочий каталог — каталог данных (через `cmd.Dir`, не `-D`), окружение собрано заново (`process.SingBoxEnv`), stdout и stderr идут в `<Data>\sing-box-console.log` (дескриптор с дозаписью), `--disable-color` не передаётся — ANSI-коды приложение вырезает при показе. Остановка — `TerminateProcess` по PID, без штатного `Close`; любое изменение конфига применяется перезапуском (`SIGHUP` на Windows нет). `internal/infrastructure/process/manager.go` |
| Каждое сохранение конфига | `sing-box.exe check -c <Data>\.singbox-check-*.json` | Копия проверяемого конфига пишется в каталог данных, окно скрыто, окружение и рабочий каталог те же, что у `run`. Без `sing-box.exe` обычное сохранение идёт без проверки, а первый конфиг установки отвергается. `internal/infrastructure/singboxcheck/checker.go` |
| Обновление sing-box | `version` и `check -c <Data>\config.json` | `version` установленного и скачанного бинарника (скачанный должен сообщить ожидаемую версию); затем `check` текущего конфига скачанным бинарником из `Bin\.sing-box-update-*` и установленным (оба запуска делаются всегда, решение — по паре ответов). `internal/infrastructure/updater/updater.go` |

`format`, `merge`, `-C`, `-D`, `generate`, `rule-set`, `tools` и `api` приложение не использует. Подробности — [cli.md](cli.md#как-это-использует-tray-sing-box).

Окружение sing-box (`process.SingBoxEnv`, `internal/infrastructure/process/env_windows.go`): `SystemRoot`, `windir`, `SystemDrive`, `ProgramData`, `ProgramFiles`, `PATH` = `<Bin>;System32;Windows;System32\Wbem`, `TEMP` = `TMP` = `<Data>\tmp`, `USERPROFILE` = `<Data>`; из окружения приложения переходят только переключатели `ENABLE_DEPRECATED_*`, нормализованные через `ParseBool` (так же их читает sing-box). Следствия: `$VAR` в путях конфига раскрывается только из этого набора; `LOCALAPPDATA` нет, поэтому WinDivert (исходящий `bridge`, TLS spoof) под приложением не работает ([cli.md](cli.md#остальные-переменные)).

### Что приложение разрешает добавить в конфиг (guard)

`internal/infrastructure/configfile/guard.go` проверяет каждую запись конфига (разделы страницы настроек, откат истории, импорт, подписки, DPI) и не даёт **добавить** опасное; то, что уже было в прежнем конфиге (написано администратором вручную), остаётся. Сравнение — по элементам (свёрнутый ключ + каноническое значение), ключи сворачиваются `foldKey` (нижний регистр, KELVIN SIGN, LONG S) — то есть так же или строже, чем sing-box.

| Список в guard.go | Значения | Сверка с 1.14.2 |
|---|---|---|
| `allowedSections` | `log`, `dns`, `ntp`, `certificate`, `inbounds`, `outbounds`, `endpoints`, `route`, `experimental`, `http_clients` | Не входят: `services`, `certificate_providers`, `network_namespaces`, `$schema` |
| `allowedOutboundTypes` | `direct`, `block`, `dns`, `selector`, `urltest`, `socks`, `http`, `shadowsocks`, `vmess`, `vless`, `trojan`, `naive`, `hysteria`, `hysteria2`, `tuic`, `wireguard`, `shadowtls`, `ssh`, `anytls` | `dns` и исходящий `wireguard` удалены в 1.13 — sing-box их и так отвергает ([outbounds.md](outbounds.md#удалённые-типы-dns-wireguard-shadowsocksr)). Новых типов 1.14 `snell` и `bridge` в списке нет; `tor` исключён намеренно (запускает программу) |
| `allowedInboundTypes` | `tun`, `mixed`, `socks`, `http`, `direct` | Серверные протоколы, `redirect`, `tproxy`, `cloudflared` не входят |
| `allowedEndpointTypes` | `wireguard` (без `listen_port`) | `tailscale`, `openconnect`, `openvpn-*` не входят |

Кроме того, нельзя добавить: ключи `*_path` и `*_directory` (кроме условия `process_path`), `executable_path`, `extra_args`, `torrc`, `log.output`, `external_ui`, `external_ui_download_url`, `masquerade`, `ntp.write_to_system: true`, объекты баз `geoip`/`geosite` в `route`, `path` кроме URL-путей (исходящий `http`, транспорт, DoH/H3) и голого имени файла у локального rule-set и `cache_file`, `cert` внутри `plugin_opts` shadowsocks, `tls.spoof` и `tls_spoof` в `route-options` (ставят драйвер WinDivert, а под приложением нет `LOCALAPPDATA` для него — соединения бы ломались), слушатель вне loopback (`listen` входящего, `clash_api.external_controller`, `v2ray_api.listen`), любой `experimental.debug.listen`. Что guard пропускает, но под приложением не сработает: `"listen": "localhost"` (sing-box принимает только IP — check отвергнет).

### Что производит импортёр

- Ссылки (`internal/infrastructure/sharelink`): исходящие `vless`, `vmess`, `trojan`, `shadowsocks`, `hysteria`, `hysteria2`, `tuic`, `anytls`, `socks`; транспорты `ws`, `grpc`, `http`, `httpupgrade`, `quic`; uTLS `chrome` по умолчанию для TLS поверх TCP ([outbounds.md](outbounds.md#сводка-типов-исходящих), [shared.md](shared.md#v2ray-транспорты-transport)).
- sing-box-профили (JSON подписки): из профиля берутся прокси-типы `shadowsocks`, `vmess`, `vless`, `trojan`, `hysteria`, `hysteria2`, `tuic`, `anytls`, `shadowtls`, `http`, `socks`, `naive`, `ssh`; `direct`, `block`, `dns`, `selector`, `urltest` провайдера отбрасываются (`profileProxyTypes`, `profileStructural` в profile.go).
- Обход DPI добавляет исходящий `http` с тегом `dpi-bypass` (`127.0.0.1:3128`) и `detour` на него.
- Все эти типы входят в `allowedOutboundTypes`. Что важно знать о них в 1.14.2: `uuid` vmess/vless check не проверяет; исходящий `naive` требует `libcronet.dll` рядом с `sing-box.exe` (иначе check отвергает весь конфиг); hysteria2 с 1.14 имитирует QUIC Chrome, серверам с сертификатом Ed25519 нужен `disable_chrome_parrot` ([outbounds.md](outbounds.md#заметки-для-tray-sing-box)).

### Проверка зависимостей (dependency.go)

`internal/infrastructure/configfile/dependency.go` (вызывается для каждой записи, вместе с guard и `checkSelectorDefaults`) отвергает конфиг, в котором появилась бы проблема, на которой sing-box упадёт при запуске, хотя `check` её пропускает:

- `detour` и участники `selector`/`urltest`, указывающие на несуществующий тег, и кольца зависимостей — `dependency[X] not found` / `circular outbound dependency` ([outbounds.md](outbounds.md#пространство-тегов-detour-и-порядок-старта));
- `route.final`; `rule_set` и `preferred_by` правил маршрутизации, включая вложенные в логические ([route.md](route.md#что-проверяет-check-а-что--только-запуск));
- `download_detour` удалённого rule-set, `detour` его встроенного `http_client`, `http_client` по тегу, `route.default_http_client`, `detour` того элемента `http_clients`, через который rule-set скачивается ([config.md](config.md#клиент-по-умолчанию-для-rule-set));
- `detour` DNS-серверов; `rule_set` DNS-правил (его отвергает и сам check); `ntp.detour` при `ntp.enabled` (здесь проверка строже sing-box: тот на этом не падает).

Не покрыто (по таблице [config.md](config.md#заметки-для-tray-sing-box)): `dns.final`, `detour` на «пустой» `direct`, `domain_resolver` DNS-серверов, `interval` больше `idle_timeout` у `urltest`, создание первого элемента `http_clients`, `http_client` вместе с `download_detour`, `tls.certificate_provider`, загрузка rule-set без кэша, порты и TUN. Ссылки правил на несуществующий `outbound` и DNS-правил на несуществующий `server` ломают только соединения; их не проверяют ни `check`, ни `dependency.go`.

### Обновление sing-box (updater)

`internal/infrastructure/updater` + `internal/domain/update_service.go`: последний стабильный релиз `SagerNet/sing-box` с GitHub (клиент `nettrust`), архив `sing-box-<версия>-windows-<arch>.zip`, без понижения версии. Скачанный архив распаковывается в `Bin\.sing-box-update-*`; бинарник должен ответить на `version` ожидаемой версией; затем им выполняется `check` текущего `config.json`. Если новая версия конфиг отвергает, а установленная принимает, обновление отменяется с текстом sing-box; если отвергают обе, обновление идёт только при остановленном VPN. Иначе VPN останавливается, `sing-box.exe` (и библиотеки релиза, в том числе `libcronet.dll`) заменяется с копией `.old`, VPN запускается; не запустившаяся новая версия откатывается — если прежняя принимает конфиг (иначе остаётся новая, и попытки запуска продолжаются). Откат ловит только ошибку, которую процесс выдал в пределах `StartGraceMs` (1,5 с), а `check` не видит того, что падает при запуске, — см. [deprecations.md](deprecations.md#для-tray-sing-box) и [deprecations.md](deprecations.md#что-проверить-перед-обновлением-sing-box). Обновление может перескочить через несколько минорных версий: в 1.15 заметки с удалением в 1.16 станут фатальными, и четыре из них сообщаются только при старте ([deprecations.md](deprecations.md#1150-alpha-прогноз-не-проверено)).

### Другие места, где поведение sing-box касается приложения

- Проба связи (`Editor.LocalProxyURL`) берёт `listen_port` первого `mixed`/`http` (иначе `socks`) по точным ключам и ходит на `127.0.0.1`; при `listen` на `::1`, `users` или `tls` у входящего она даст ложное «нет связи» ([inbounds.md](inbounds.md#заметки-для-tray-sing-box)).
- Стеки `tun` `system` и `mixed` оставляют постоянное правило брандмауэра `sing-tun (<путь к sing-box.exe>)`; `set_system_proxy` после `TerminateProcess` остаётся указывать на закрытый порт; с 1.14 `dns_mode: hijack` меняет DNS адаптера ([inbounds.md](inbounds.md#tun-на-windows)).
- Выбор в `selector`, сделанный через Clash API, при включённом `cache_file` важнее `default` в конфиге ([experimental.md](experimental.md#переключение-selector-через-api-и-его-сохранение)).
- Без `log.output` весь журнал sing-box и все сообщения CLI попадают в `sing-box-console.log`; с `log.output` строки в файле без времени, пока не задан `timestamp` ([config.md](config.md#заметки-для-tray-sing-box)).

## Как обновить справочник под новую версию sing-box

1. Получить исходники нового тега (`go mod download -json github.com/sagernet/sing-box@vX.Y.Z` или `git clone` и `git checkout vX.Y.Z`) и официальный архив `sing-box-X.Y.Z-windows-amd64.zip`.
2. Сравнить с `v1.14.2` (`git diff v1.14.2 vX.Y.Z -- <пути>`) и перенести изменения в файлы:

   | Что сравнивать | Что это даёт | Куда |
   |---|---|---|
   | `option/*.go` | перечень полей: json-теги, типы (`badoption.Listable`, `badoption.Duration`, `byteformats.*`), устаревшие поля с `schema:"omit"`, собственные `UnmarshalJSON` (строгость и регистр) | таблицы всех файлов |
   | `experimental/deprecated/constants.go` | заметки устаревания, версии удаления, имена `ENABLE_DEPRECATED_*` | [deprecations.md](deprecations.md), [cli.md](cli.md#enable_deprecated_) |
   | `include/*.go`, `release/DEFAULT_BUILD_TAGS_WINDOWS` | зарегистрированные типы, заглушки удалённых, build-теги | сводки в inbounds.md, outbounds.md, experimental.md |
   | `constant/*.go` | перечисления и умолчания (тайм-ауты, версии rule-set, протоколы) | соответствующие таблицы |
   | `box.go`, `adapter/*/manager.go`, `dns/transport_manager.go`, `route/router.go`, `common/httpclient/manager.go`, `common/dialer/*.go` | что проверяется в `box.New` (видит check), а что только в `Start` | [config.md](config.md#где-всплывает-ошибка-check-запуск-отдельные-соединения) и `configfile/dependency.go` проекта |
   | `cmd/sing-box/*.go` | команды и флаги | [cli.md](cli.md) |
   | `docs/changelog.md`, `docs/deprecated.md`, `docs/migration.md`, `docs/configuration/**` | новые поля (пометки «Since sing-box …»), заявленные удаления; при расхождении прав код | пометки «с 1.X», разделы «Расхождения» |
   | вывод `sing-box schema` старой и новой версии | быстрый список добавленных и удалённых полей | сверка полноты таблиц |
   | библиотека `github.com/sagernet/sing` версии из `go.mod` (`common/json`, `badoption`, `byteformats`, `control`) | сопоставление ключей, единицы объёма, платформенные функции | [config.md](config.md#разбор-json), [shared.md](shared.md#условные-обозначения) |

3. Повторить опыты новым бинарником (только `check`, `format`, `version`, `rule-set`, `generate`, никогда `run`): регистр ключей, `MISSING_DOMAIN_RESOLVER`, фатальность заметок (в 1.15 фатальными станут заметки с удалением в 1.16), примеры из таблиц «что ловит check».
4. Сверить проект: списки `guard.go` (новые типы и секции), `dependency.go` (новые ссылки, которые разрешаются только при запуске), типы импортёра в `sharelink`; прогнать тесты проекта с `SINGBOX_REAL_DIR`, указывающим на новый бинарник.
5. Обновить номер версии и дату в заголовках файлов и в этом README.
