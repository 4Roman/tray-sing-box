# Маршрутизация (route) и rule-set

Справочник по интерфейсу sing-box **1.14.2**: раздел `route` целиком — поля верхнего уровня, условия правил, логические правила, все действия правил, сниффинг протоколов, наборы правил (rule-set) и их форматы. Факты взяты из кода (option/*.go, route/**), спорные места проверены на бинарнике 1.14.2 (`sing-box check`, `sing-box rule-set compile/match/convert`). Где документация и код расходятся, прав код; такие места отмечены и собраны в конце.

Смежные файлы: общие блоки (dial-поля, `domain_resolver`, поиск соседей, Wi-Fi) — [shared.md](shared.md); HTTP-клиент — [config.md](config.md#http_clients); DNS-правила, DNS-серверы и DNS-сторона rule-set'ов — [dns.md](dns.md); входящие (tun, `route_address_set`, `auto_redirect`) — [inbounds.md](inbounds.md); исходящие, группы и эндпоинты — [outbounds.md](outbounds.md); верхний уровень конфига (`http_clients`) и правила разбора JSON — [config.md](config.md); команды `check` и `rule-set` — [cli.md](cli.md); сводка устаревшего — [deprecations.md](deprecations.md); `clash_api`, `cache_file` — [experimental.md](experimental.md).

Обозначения: типы — типы JSON; `string|[string]` — поле `badoption.Listable` (одно значение без скобок или массив); `duration` — строка в синтаксисе длительностей Go (`"300ms"`, `"1h30m"`, принимается и `"1d"`), число вместо строки — ошибка разбора; `-> outbound`, `-> inbound`, `-> dns server`, `-> rule-set`, `-> http_client` — ссылка по тегу. «с 1.X» — поле появилось в 1.X (отмечено для 1.10 и новее). «check» — ошибку ловит `sing-box check` (разбор JSON + `box.New`); «при старте» — check проходит с кодом 0, падает запуск; «при подключении» — не падает ни то, ни другое, ошибка в логе на каждом затронутом соединении.

## Как обрабатывается соединение

1. Подготовка метаданных: поиск процесса (если нужен и источник — локальный адрес), поиск соседа (MAC/имя хоста, не на Windows), восстановление домена по FakeIP или по обратному DNS-отображению, определение версии IP назначения.
2. Правила `route.rules` перебираются по порядку. Правило с **нефинальным** действием (`route-options`, `sniff`, `resolve`) применяет его и перебор продолжается. Первое совпавшее правило с **финальным** действием (`route`, `reject`, `hijack-dns`, `bypass` с `outbound`) завершает перебор.
3. Если финальное правило не найдено — соединение уходит в исходящий по умолчанию (`route.final`).
4. Для L3-входящих (tun, wireguard, tailscale) правила дополнительно прогоняются до установления соединения — это pre-match, см. раздел [Pre-match](#pre-match) ниже.

Особый случай: соединения tun к адресам его DNS-перехвата (`dns_address`/режим `hijack`, см. [inbounds.md](inbounds.md)) передаются в DNS-модуль ещё до правил — отдельное правило `hijack-dns` для них не нужно.

Исходники: route/route.go (`routeConnection`, `routePacketConnection`, `matchRule`, `prepareMatchMetadata`, `PreMatch`), route/process_cache.go, protocol/tun/inbound.go.

## Раздел route

Объект `route` верхнего уровня (`RouteOptions`). Сам объект разбирается строго: неизвестный ключ — check (`route.foo: json: unknown field "foo"`).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `rules` | [object] | — | Правила маршрутизации, см. [Правило маршрутизации](#правило-маршрутизации). |
| `rule_set` | [object] | — | Определения наборов правил, см. [Rule-set](#rule-set). С 1.8. |
| `final` | string -> outbound | первый элемент `outbounds` | Исходящий по умолчанию (может быть группой или эндпоинтом). Пустое значение: первый исходящий из списка `outbounds`; если `outbounds` пуст — автоматически созданный `direct` с тегом `direct` (эндпоинты сами по умолчанию не выбираются). Несуществующий тег — **при старте**: `default outbound not found: X`. |
| `find_process` | bool | `false` | Искать процесс-владельца для логов, даже если нет правил по процессу. При наличии `process_*`, `package_name*`, `user`, `user_id` в правилах маршрутизации, DNS-правилах или в любом rule-set поиск включается сам. Linux, Windows, macOS (Android — в графическом клиенте). |
| `find_neighbor` | bool | `false` | с 1.14. Искать MAC и имя хоста источника для логов. Включается сам при `source_mac_address`/`source_hostname` в правилах или `neighbor_domain` у DNS-сервера `local`. Linux и macOS; **на Windows ничего не делает** (резолвера соседей нет, ошибки нет). См. [shared.md](shared.md#поиск-соседей-neighbor). |
| `dhcp_lease_files` | string\|[string] | автоопределение | с 1.14. Пути к файлам аренд DHCP для имён хостов (по умолчанию ищутся файлы dnsmasq, odhcpd, ISC dhcpd, Kea). Linux и macOS; на Windows игнорируется. |
| `auto_detect_interface` | bool | `false` | Привязывать исходящие соединения к интерфейсу по умолчанию (защита от петли под tun). Не действует на исходящий с собственным `bind_interface` / `inet4_bind_address` / `inet6_bind_address`. Только Linux, Windows, macOS, иначе check: `` `auto_detect_interface` is only supported on Linux, Windows and macOS ``. |
| `override_android_vpn` | bool | `false` | Считать VPN Android допустимым интерфейсом при `auto_detect_interface`. Только Android, **на Windows — check**: `` `override_android_vpn` is only supported on Android `` (проверено). |
| `default_interface` | string | — | Имя интерфейса, к которому по умолчанию привязываются исходящие. Только Linux, Windows, macOS. По коду **побеждает** `auto_detect_interface`, а не наоборот (см. расхождения). Не действует на исходящий с собственной привязкой. |
| `default_mark` | int\|string | `0` | Метка маршрутизации (fwmark) по умолчанию; строка допускает запись `"0x10"`. Не действует, если у исходящего свой `routing_mark`. Только Linux, **на Windows любое ненулевое значение — check**: `` `default_mark` is only supported on linux `` (проверено). |
| `default_domain_resolver` | string\|object -> dns server | — | с 1.12. Как разрешать доменные имена в dial-полях, если у исходящего нет своего `domain_resolver`. См. [default_domain_resolver](#default_domain_resolver). |
| `default_network_strategy` | string | — | с 1.11. `default`, `fallback`, `hybrid` (иное — check `unknown network strategy`). Требует `auto_detect_interface` (иначе check: `` `auto_detect_interface` is required by `default_network_strategy` ``), конфликтует с `default_interface` (check: `` `default_network_strategy` is conflict with `default_interface` ``). Работает только в графических клиентах Android/Apple; на Windows принимается и ни на что не влияет. Исходящий может переопределить своим `network_strategy`. |
| `default_network_type` | string\|[string] | — | с 1.11. `wifi`, `cellular`, `ethernet`, `other` (иное — ошибка разбора `unknown interface type`). Только графические клиенты Android/Apple. |
| `default_fallback_network_type` | string\|[string] | — | с 1.11. Те же значения; запасные сети для стратегии `fallback`. Только графические клиенты Android/Apple. |
| `default_fallback_delay` | duration | `300ms` | с 1.11. Задержка перед запасной попыткой (RFC 6555 / переключение сети). Смысл — в [shared.md](shared.md#сетевые-стратегии). |
| `default_http_client` | string -> http_client | первый элемент `http_clients` | с 1.14. Тег HTTP-клиента по умолчанию для удалённых rule-set'ов. Несуществующий тег — **при старте** (`resolve default http client: http_client not found: X`), причём даже когда удалённых rule-set'ов нет. Если `http_clients` пуст и поле не задано — неявный клиент через исходящий по умолчанию (устарело в 1.14, удаление в 1.16; пока только предупреждение). |
| `geoip` | object | — | Устарело в 1.8, удалено в 1.12. **Разбирается и молча игнорируется** (check 0, проверено). Поля — в [route.geoip и route.geosite](#routegeoip-и-routegeosite-удалены). |
| `geosite` | object | — | То же. |

Исходники: option/route.go, route/router.go (`NewRouter`, `Initialize`, `Start`), route/network.go (`NewNetworkManager`), common/dialer/default.go, adapter/outbound/manager.go (`Start`, исходящий по умолчанию), common/httpclient/manager.go, box.go.

### default_domain_resolver

Строка — сокращение для `{"server": "<тег>"}`. Объект — те же поля, что у `domain_resolver` в dial-полях, полное описание в [shared.md](shared.md#domain_resolver):

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string -> dns server | — (обязательно) | Тег DNS-сервера. Пустой в объектной форме — ошибка разбора `empty domain_resolver.server`. |
| `strategy` | string | `""` | `""`/`as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. |
| `timeout` | duration | `dns.timeout` | с 1.14. |
| `disable_cache` | bool | `false` | Не использовать DNS-кэш в этом запросе. |
| `disable_optimistic_cache` | bool | `false` | с 1.14. |
| `rewrite_ttl` | int\|null | `null` | Переписать TTL ответа. |
| `client_subnet` | string\|null | `null` | IP или префикс для EDNS0 Client Subnet; голый IP дополняется до `/32` или `/128`. |

Поведение и проверки (проверено на 1.14.2):

- Несуществующий тег — **check**: `initialize outbound[0]: default domain resolver not found: X`. Срабатывает на любом исходящем, которому нужно разрешать имена, в том числе на обычном `direct` (он разрешает имя из запроса).
- Если поле не задано, у исходящего нет своего `domain_resolver`, а DNS-серверов **два или больше**, check и запуск завершаются фатально: `missing route.default_domain_resolver or domain_resolver in dial fields is deprecated … set environment variable ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true`. Хватает даже конфига из одного `direct`. С переменной окружения `ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true` — только предупреждение. При 0–1 DNS-сервере используется сервер по умолчанию, ошибки нет. Подробнее — [deprecations.md](deprecations.md).
- Исключение: у `naive`, эндпоинтов `openconnect`, `openvpn-client`, `tailscale` (и у mesh-узлов службы `derp`) диалер создаётся с `NewDialer: true`, и тот же случай (доменный `server`, 2+ DNS-сервера, резолвер не задан) — жёсткая ошибка `missing domain resolver for domain server address`, переменная окружения её не снимает (проверено для `naive`).
- Исходящий переопределяет значение своим `domain_resolver`.

Исходники: option/outbound.go (`DomainResolveOptions`), route/network.go, common/dialer/dialer.go (`NewWithOptions`, `NewDNSQueryOptions`), protocol/naive/outbound.go, protocol/openconnect/client.go, protocol/openvpn/client.go, protocol/tailscale/endpoint.go, experimental/deprecated/constants.go (`OptionMissingDomainResolver`).

### route.geoip и route.geosite (удалены)

Объекты `GeoIPOptions` и `GeositeOptions`; устарели в 1.8, удалены в 1.12. В 1.14.2 ключи всё ещё входят в структуру, поэтому **разбираются без ошибки и ни на что не влияют** (ни загрузки, ни проверки `download_detour`; проверено). Условия правил `geoip`/`geosite`/`source_geoip`, наоборот, дают ошибку check.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `path` | string | — | Путь к базе (не используется). |
| `download_url` | string | — | URL загрузки (не используется). |
| `download_detour` | string -> outbound | — | Исходящий для загрузки (не используется, не проверяется). |

Исходники: option/route.go.

## Правило маршрутизации

Элемент `route.rules`. Два вида: обычное (`type` пуст или `default`) и логическое (`type: logical`). Каждое правило верхнего уровня состоит из **условий** и **действия** (поля действия лежат в том же объекте, см. [Действия правил](#действия-правил)).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | `default` | `default` (или пусто) либо `logical`. Иное — check: `unknown rule type: X`. |

Исходники: option/rule.go (`Rule`, `RawDefaultRule`, `RawLogicalRule`), route/rule/rule_default.go.

### Логика совпадения

Условия обычного правила делятся на группы. Внутри группы достаточно одного совпавшего условия (ИЛИ), группы и прочие условия объединяются через И:

- адрес назначения: `domain` ∨ `domain_suffix` ∨ `domain_keyword` ∨ `domain_regex` ∨ `ip_cidr` ∨ `ip_is_private`;
- порт назначения: `port` ∨ `port_range`;
- адрес источника: `source_ip_cidr` ∨ `source_ip_is_private`;
- порт источника: `source_port` ∨ `source_port_range`;
- все остальные условия — каждое обязательно (И).

`rule_set` встраивается в эту схему особо, см. [Семантика rule_set](#семантика-rule_set-в-правиле). Правило **без условий совпадает всегда**, и `invert` этого не меняет (так записываются правила вида `{"action": "sniff"}`). `invert: true` у правила с условиями инвертирует итог.

Имя для доменных условий берётся из сниффинга (`metadata.Domain`), а если его нет — из доменного адреса назначения. Имя сравнивается **в нижнем регистре, а значения из конфига не приводятся**: `"domain": "Example.COM"` не совпадёт никогда, заглавные буквы в `domain_keyword` и в литералах `domain_regex` тоже (проверено `rule-set match`). IP-условия назначения для доменного назначения совпадают только с адресами, полученными действием `resolve`.

Исходники: route/rule/rule_abstract.go, route/rule/match_state.go, route/rule/rule_item_domain*.go, route/rule/rule_item_cidr.go.

### Условия обычного правила

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `inbound` | string\|[string] -> inbound | — | Тег входящего. Несуществующий тег не проверяется — правило просто не совпадёт. |
| `ip_version` | int | `0` (любая) | `4` или `6`, иначе check: `invalid ip version: N`. Строка `"4"` — ошибка разбора. Смотрит на IP назначения; для доменного назначения не совпадает. |
| `network` | string\|[string] | — | `tcp`, `udp`, `icmp` (с 1.13; эхо-запросы ICMP из tun, wireguard, tailscale). Другие значения check не отвергает — они просто никогда не совпадут. |
| `auth_user` | string\|[string] | — | Имя пользователя, прошедшего аутентификацию во входящем (mixed, socks, http, протоколы с `users`). |
| `protocol` | string\|[string] | — | Протокол, определённый сниффингом: `tls`, `http`, `quic`, `dns`, `stun`, `bittorrent`, `dtls`, `ssh`, `rdp`, `ntp`. Нужен предшествующий `sniff`. Значения не проверяются. |
| `client` | string\|[string] | — | с 1.10. Клиент по сниффингу: для QUIC — `chromium`, `safari`, `firefox`, `quic-go`, `unknown`; для SSH — строка программы клиента (часть баннера после `SSH-2.0-`). |
| `domain` | string\|[string] | — | Точное совпадение имени. Пустая строка — check: `domain: empty item is not allowed`. Писать в нижнем регистре. |
| `domain_suffix` | string\|[string] | — | Суффикс по границе метки: `b.com` совпадает с `b.com` и `x.b.com`, но не с `xb.com`; `.c.com` — только поддомены, без самого `c.com` (так с 1.9, проверено). Пустая строка — check. Нижний регистр. |
| `domain_keyword` | string\|[string] | — | Подстрока имени. Пустая строка допустима и совпадает с любым доменом. Значение не приводится к нижнему регистру. |
| `domain_regex` | string\|[string] | — | Регулярное выражение Go (RE2) по имени в нижнем регистре. Синтаксическая ошибка — check. |
| `geosite` | string\|[string] | — | Устарело в 1.8, удалено в 1.12: check `geosite database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0`. Замена — rule-set. |
| `source_geoip` | string\|[string] | — | Устарело в 1.8, удалено в 1.12: check (`geoip database is deprecated …`). |
| `geoip` | string\|[string] | — | Устарело в 1.8, удалено в 1.12: check. |
| `source_ip_cidr` | string\|[string] | — | Префикс CIDR или одиночный IP источника. Ошибка разбора — check. |
| `source_ip_is_private` | bool | `false` | Источник — непубличный адрес (частные, loopback, link-local и т. п.). |
| `ip_cidr` | string\|[string] | — | Префикс или одиночный IP назначения; для домена — адреса из `resolve`. Ошибка разбора — check. |
| `ip_is_private` | bool | `false` | Назначение (или любой адрес из `resolve`) непубличное. |
| `source_port` | int\|[int] | — | Порт источника, 0–65535. Строка или число вне диапазона — ошибка разбора. |
| `source_port_range` | string\|[string] | — | `"a:b"`, `":b"` (от 0), `"a:"` (до 65535). Без двоеточия (`"1000-2000"`) — check: `bad port range`. |
| `port` | int\|[int] | — | Порт назначения. |
| `port_range` | string\|[string] | — | Диапазон портов назначения, формат как у `source_port_range`. |
| `process_name` | string\|[string] | — | Имя файла процесса (последний элемент пути), точное сравнение **с учётом регистра**: `chrome.exe`. Linux, Windows, macOS. Процесс ищется только для соединений с локального адреса (loopback или адрес своего интерфейса). |
| `process_path` | string\|[string] | — | Полный путь, точно и с учётом регистра. На Windows с 1.9 — путь Win32 (`C:\Program Files\...\x.exe`), не `\Device\HarddiskVolumeN\...`. На Android сравнивается и с именами пакетов. |
| `process_path_regex` | string\|[string] | — | с 1.10. Регулярное выражение по полному пути (регистр учитывается, для Windows удобно `(?i)`). Ошибка синтаксиса — check. |
| `package_name` | string\|[string] | — | Имя пакета Android. На других ОС не совпадает. |
| `package_name_regex` | string\|[string] | — | с 1.14. Регулярное выражение по имени пакета Android. Ошибка синтаксиса — check. |
| `user` | string\|[string] | — | Имя пользователя-владельца процесса. Только Linux; на Windows поиск процесса имя пользователя не даёт — не совпадает. |
| `user_id` | int\|[int] | — | UID владельца процесса (int32). Только Linux. |
| `clash_mode` | string (не список) | — | Текущий режим Clash; сравнение без учёта регистра. Менеджер режимов создаётся только при `experimental.clash_api`, сервисе `api` или в графическом клиенте, без них условие не совпадает никогда. Список режимов собирается из всех `clash_mode` в правилах; по умолчанию `Rule` (или `clash_api.default_mode`), см. [experimental.md](experimental.md). |
| `network_type` | string\|[string] | — | с 1.11. Тип сети интерфейса по умолчанию: `wifi`, `cellular`, `ethernet`, `other`; иное — ошибка разбора. Тип знают только графические клиенты Android/Apple. На Windows (CLI) тип не определяется и остаётся нулевым значением, то есть `wifi`: по коду `network_type: wifi` совпадёт при любом интерфейсе по умолчанию, остальные значения — никогда (вывод по коду, запуском не проверялся). |
| `network_is_expensive` | bool | `false` | с 1.11. Лимитная (Android) или «дорогая» (Apple) сеть. Графические клиенты Android/Apple; на Windows не совпадает. |
| `network_is_constrained` | bool | `false` | с 1.11. Режим экономии трафика Apple. Только графические клиенты Apple. |
| `wifi_ssid` | string\|[string] | — | SSID текущей Wi-Fi-сети. Android/Apple (графические клиенты), Linux (с 1.13, NetworkManager/IWD/wpa_supplicant/ConnMan), **Windows (с 1.13, WLAN API)**. См. [shared.md](shared.md#состояние-wi-fi-wifi_state). |
| `wifi_bssid` | string\|[string] | — | BSSID точки доступа; платформы те же. |
| `interface_address` | object | — | с 1.13. `{"<имя интерфейса>": string\|[string]}` — префиксы или IP. Каждый названный интерфейс должен существовать и иметь адрес, пересекающийся хотя бы с одним префиксом (И по интерфейсам, ИЛИ по префиксам). Linux, Windows, macOS; имя — как его видит ОС (на Windows — имя адаптера, например `Ethernet`). |
| `network_interface_address` | object | — | с 1.13. `{"wifi"\|"cellular"\|"ethernet"\|"other": string\|[string]}`; неизвестный ключ — ошибка разбора. Только графические клиенты Android/Apple; на Windows не совпадает. |
| `default_interface_address` | string\|[string] | — | с 1.13. **Каждый** указанный префикс должен пересекаться с адресом интерфейса по умолчанию (И по списку). Linux, Windows, macOS. Невалидный префикс — ошибка разбора. |
| `source_mac_address` | string\|[string] | — | с 1.14. MAC устройства-источника в локальной сети (поиск соседей). Linux, macOS, графические клиенты Android/macOS; **на Windows не совпадает**. Невалидный MAC check не отвергает (сравнивается как строка). |
| `source_hostname` | string\|[string] | — | с 1.14. Имя хоста источника из аренд DHCP. Платформы те же, на Windows не совпадает. |
| `preferred_by` | string\|[string] -> outbound | — | с 1.13. Совпадает с «предпочтительными маршрутами» указанных исходящих/эндпоинтов. По коду поддерживают: эндпоинты `wireguard` (allowed IPs пиров), `tailscale` (домены MagicDNS и allowed IPs), `openvpn-client`, `openconnect`, исходящий `bridge` (все адреса, кроме адресов своей машины; только в pre-match). Несуществующий тег — **при старте** (`outbound not found`), неподходящий тип — **при старте** (`outbound type does not support preferred routes: direct`). |
| `rule_set` | string\|[string] -> rule-set | — | Теги наборов из `route.rule_set`. Несуществующий тег — **при старте**: `initialize rule[i]: rule-set not found: X`. См. [Семантика rule_set](#семантика-rule_set-в-правиле). |
| `rule_set_ip_cidr_match_source` | bool | `false` | с 1.10. `ip_cidr` внутри наборов этого правила сравнивается с IP **источника**. Без `rule_set` ни на что не влияет. |
| `rule_set_ipcidr_match_source` | bool | `false` | Старое имя; устарело в 1.10, удалено в 1.11. Вместе с `rule_set` — check (`rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0`); без `rule_set` молча игнорируется. |
| `invert` | bool | `false` | Инвертировать результат. |

Исходники: option/rule.go (`RawDefaultRule`), route/rule/rule_default.go (`NewDefaultRule`), route/rule/rule_item_*.go, route/rule/rule_interface_address.go, route/rule/rule_network_interface_address.go, route/rule/rule_default_interface_address.go, route/rule_conds.go, route/process_cache.go, common/process/searcher_windows.go, route/network.go (`DefaultNetworkInterface`), experimental/clashmode/.

### Логическое правило

Объединяет вложенные правила через И/ИЛИ. Поля действия задаются на самом логическом правиле.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — | `logical` (обязательно). |
| `mode` | string | — (обязательно) | `and` или `or`. Отсутствие или иное значение — check: `unknown logical mode: X`. |
| `rules` | [object] | — (обязательно) | Вложенные правила: обычные или логические (вложенность не ограничена). Пустой массив — check: `missing conditions`. |
| `invert` | bool | `false` | Инвертировать итог. |

Исходники: option/rule.go (`RawLogicalRule`, `LogicalRule`), route/rule/rule_default.go (`NewLogicalRule`), route/rule/rule_abstract.go (`abstractLogicalRule`).

### Ограничения вложенных правил

Правило внутри `rules` логического правила — только условия:

- Любой ключ действия (`action`, `outbound`, `override_address`, `override_port`, `network_strategy`, `fallback_delay`, `udp_*`, `tls_*`) — check: `route.rules[0].rules[0]: rule action is not supported in nested rules`. Прочие ключи действий (`method`, `sniffer`, `server` …) дают `unknown field`.
- Вложенное правило без условий — check: `missing conditions` (в отличие от правила верхнего уровня, где правило без условий допустимо).
- `type`, `mode`, `rules`, `invert` у вложенного логического правила — как выше.

Исходники: option/rule_nested.go, route/rule/rule_nested_action.go, option/rule.go (`unmarshalDefaultRuleContext`, `unmarshalLogicalRuleContext`).

### Семантика rule_set в правиле

С 1.14 «слияние» набора с правилом ограничено одним случаем:

- набор состоит **ровно из одного** обычного правила без `invert` (и без собственного `rule_set`) — его условия встраиваются в группы внешнего правила. Пример: внешнее `domain: a.org` + набор `{domain_suffix: b.com}` = (`a.org` ∨ `*.b.com`) — по ИЛИ внутри группы адреса;
- во всех остальных случаях (несколько правил, `invert`, логическое правило) набор — отдельное обязательное условие, которое истинно, если совпало **любое** из его правил само по себе (внешние группы его не «добирают»);
- несколько наборов в одном `rule_set` — всегда ИЛИ, условия разных наборов между собой не объединяются;
- `query_type` из набора в правилах маршрутизации никогда не совпадает (поле только для DNS).

До 1.14 поведение в сложных случаях было неопределённым; changelog 1.14 не считает это ломающим изменением.

Исходники: route/rule/rule_item_rule_set.go (`matchWithOuterGroups`, `mergeableRuleIn`), route/rule/rule_abstract.go, route/rule/rule_set_semantics_test.go, route/rule/rule_item_query_type.go.

## Действия правил

С 1.11 каждое правило верхнего уровня несёт действие: ключ `action` и его поля в том же объекте. Без `action` действие — `route`, поэтому классическая запись `{"domain": "x", "outbound": "proxy"}` полностью допустима (документация помечает `outbound` на уровне правила как перенесённый в действие — ключ тот же, предупреждения нет). Неизвестное значение `action` — check: `unknown rule action: X`.

Финальные действия: `route`, `reject`, `hijack-dns`, `bypass` (с `outbound`). Нефинальные: `route-options`, `sniff`, `resolve`; `bypass` без `outbound` вне pre-match пропускается; недокументированное `direct` при маршрутизации ничего не делает.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `action` | string | `route` | `route`, `route-options`, `bypass`, `reject`, `hijack-dns`, `sniff`, `resolve`, `direct`. |

Исходники: option/rule_action.go (`RuleAction`), route/rule/rule_action.go (`NewRuleAction`), route/route.go (`matchRule`), constant/rule.go.

### route

Финальное: отправить соединение в исходящий.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `outbound` | string -> outbound | — | Тег исходящего, группы или эндпоинта. Проверяется **при подключении**: несуществующий или пустой тег — check 0, соединение закрывается с `outbound not found: X`; исходящий без нужной сети — `TCP is not supported by outbound` / `UDP is not supported by outbound`. |
| поля route-options | — | — | Все поля из [route-options](#route-options), применяются при совпадении. Проверка взаимоисключения `tls_fragment`/`tls_record_fragment` здесь **не выполняется** (оба принимаются). |

Исходники: option/rule_action.go (`RouteActionOptions`), route/route.go.

### route-options

с 1.11. Нефинальное: задаёт параметры для дальнейшей маршрутизации и продолжает перебор. Хотя бы одно поле обязательно, иначе check: `empty route option action`. Сюда же относятся поля, общие с `route` и `bypass`. Несколько `route-options` накапливаются: более позднее значение перекрывает, а булевы флаги можно только включить.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `override_address` | string | — | Заменить адрес назначения (IP или домен, без порта; порт сохраняется). Сбрасывает адреса, полученные `resolve`. Для UDP ответы пересчитываются обратно к исходному адресу. |
| `override_port` | int | — | Заменить порт назначения (0–65535). |
| `network_strategy` | string | — | `default`, `fallback`, `hybrid`. Действует только для `direct` без собственной привязки и только в графических клиентах Android/Apple. |
| `fallback_delay` | int | — | **Целое число наносекунд** (uint32; максимум ≈ 4,29 с), а не duration: `"300ms"` — ошибка разбора `cannot unmarshal string … of type uint32` (проверено; документация показывает строку). Задержка перехода на запасную сеть. |
| `udp_disable_domain_unmapping` | bool | `false` | В ответах на UDP-запросы к домену отдавать исходный адрес пакета, а не домен (для клиентов вроде Surge, не принимающих доменные адреса в UDP). |
| `udp_connect` | bool | `false` | Для UDP делать `connect` к назначению вместо прослушивания. |
| `udp_timeout` | duration | по протоколу | Тайм-аут простоя UDP-сессии; больше тайм-аута входящего — без эффекта. По умолчанию: `dns`, `ntp`, `stun` — 10 с; `quic`, `dtls` — 30 с; протокол без сниффинга угадывается по порту (53 → dns, 123 → ntp, 443 → quic, 3478 → stun); иначе тайм-аут входящего (5 мин). Число вместо строки — ошибка разбора. |
| `tls_fragment` | bool | `false` | с 1.12. Резать TLS ClientHello на TCP-сегменты (против простого DPI по открытому тексту; медленно). Время ожидания подбирается автоматически на Linux, Apple и Windows (на Windows — только с правами администратора), иначе — `tls_fragment_fallback_delay`; измеренное время < 20 мс тоже заменяется им. |
| `tls_fragment_fallback_delay` | duration | `500ms` | с 1.12. Фиксированная пауза, когда автоматически определить не удалось. |
| `tls_record_fragment` | bool | `false` | с 1.12. Резать ClientHello на несколько TLS-записей (дешевле, пробовать первым). Вместе с `tls_fragment` в действии `route-options` — check: `` `tls_fragment` and `tls_record_fragment` are mutually exclusive ``. |
| `tls_spoof` | string | — | с 1.14. SNI поддельного ClientHello, отправляемого перед настоящим (обход фильтров по белому списку SNI). Нужны повышенные права: Linux/macOS — root или `CAP_NET_RAW`+`CAP_NET_ADMIN`, Windows — администратор (WinDivert, только amd64/386; на ARM64 и прочих платформах — check `tls_spoof is not supported on this platform`). Подробно — [shared.md](shared.md#фрагментация-и-spoof). |
| `tls_spoof_method` | string | `wrong-sequence` | с 1.14. `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` (не на macOS). Неизвестное — check `tls_spoof: unknown method`; без `tls_spoof` — check `spoof_method requires spoof`. |

Документированных здесь `network_type` и `fallback_network_type` в коде нет: `network_type` в правиле разбирается как **условие** правила (см. таблицу условий), `fallback_network_type` в `route`/`bypass` — ошибка `unknown field`, в `route-options` — молча игнорируется. Лишние ключи в действии `route-options` вообще не отвергаются (проверено), в `route` и `bypass` — отвергаются.

Исходники: option/rule_action.go (`RawRouteOptionsActionOptions`, `RouteOptionsActionOptions`), route/rule/rule_action.go (`newRuleActionRouteOptions`, `RuleActionRouteOptions`), route/route.go (`matchRule`, `applyRouteOptionsOverride`), route/conn.go (UDP-тайм-ауты), constant/timeout.go, common/tlsspoof/spoof.go, common/tlsspoof/raw_windows.go.

### bypass

с 1.13. Обход sing-box на уровне ядра для соединений `auto_redirect` в pre-match — **только Linux** с `auto_redirect`. В остальных случаях: с `outbound` работает как `route` (финальное), без `outbound` правило пропускается. На Windows `auto_redirect` нет, так что `bypass` = `route` либо ничего.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `outbound` | string -> outbound | — | Необязательно. Проверяется при подключении, как у `route`. |
| поля route-options | — | — | Как у `route`. |

Исходники: option/rule_action.go, route/route.go (`PreMatch`, `matchRule`).

### reject

Финальное: отклонить соединение.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `method` | string | `default` | TCP/UDP: `default` — TCP RST или ICMP port unreachable для UDP; `drop` — молча отбросить. ICMP echo (с 1.13): `default` — ICMP host unreachable, `drop`, `reply` — ответить эхо-ответом. `reply` для TCP/UDP — ошибка при подключении (`reject method reply is not supported for TCP connections`). Неизвестный метод — check `unknown reject method`. |
| `no_drop` | bool | `false` | Без него после более чем 50 срабатываний правила за 30 с метод временно заменяется на `drop`. С `method: drop` — check: `no_drop is not available in current context`. |

Особые ответы (RST, ICMP) возможны только для tun и только до сниффинга; прочие и уже установленные соединения просто закрываются. Лишние ключи в правиле с `reject` молча игнорируются (проверено).

Исходники: option/rule_action.go (`RejectActionOptions`), route/rule/rule_action.go (`RuleActionReject`), route/route.go.

### hijack-dns

Финальное: передать соединение (TCP или UDP) DNS-модулю sing-box, дальше работают DNS-правила ([dns.md](dns.md)). Полей нет; лишний ключ — check `unknown field`. В pre-match — только для UDP.

Исходники: route/route.go (`hijackDNSStream`, `hijackDNSPacket`), route/dns.go.

### sniff

Нефинальное: определить протокол по первым данным и заполнить `protocol`, `domain`, `client` в метаданных. Адрес назначения **не заменяется** (старое `sniff_override_destination` удалено вместе с полями входящих в 1.13; ключ `override_destination` в действии — `unknown field`); домен используется условиями последующих правил.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `sniffer` | string\|[string] | все | Имена снифферов из [таблицы](#сниффинг-протоколов). Неизвестное — check: `unknown sniffer: X`. |
| `timeout` | duration | `300ms` | Сколько ждать данных. |

Поведение: повторный сниффинг пропускается, если протокол уже известен; пропускаются порты протоколов, где первым говорит сервер: 25, 465, 587 (SMTP), 143, 993 (IMAP), 110, 995 (POP3). Для TCP работают потоковые снифферы, для UDP — пакетные; если в `sniffer` только потоковые, UDP не сниффится, и наоборот. Для фрагментированного QUIC ClientHello читаются дополнительные пакеты. С 1.14 в pre-match UDP сниффится по первому пакету.

Исходники: option/rule_action.go (`RouteActionSniff`), route/rule/rule_action.go (`RuleActionSniff.build`), route/route.go (`actionSniff`, `defaultPacketSniffers`), common/sniff/sniff.go (`Skip`).

### resolve

Нефинальное: разрешить доменное назначение в IP-адреса (для `ip_cidr`/`ip_is_private` последующих правил и для набора номера исходящим). Для IP-назначения ничего не делает.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string -> dns server | — | DNS-сервер напрямую, минуя DNS-правила. Проверяется **при подключении**: `DNS server not found: X` (check 0). Без `server` работают DNS-правила ([dns.md](dns.md)). |
| `strategy` | string | `dns.strategy` | `""`/`as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`; иное — ошибка разбора `unknown domain strategy`. |
| `disable_cache` | bool | `false` | с 1.12. Не читать и не пополнять кэш. |
| `disable_optimistic_cache` | bool | `false` | с 1.14. |
| `rewrite_ttl` | int\|null | `null` | с 1.12. Переписать TTL ответа. |
| `timeout` | duration | `dns.timeout` | с 1.14. |
| `client_subnet` | string\|null | `null` | с 1.12. IP или префикс для EDNS0 Client Subnet (перекрывает `dns.client_subnet`). |

Ошибка разрешения прерывает соединение; в pre-match ведёт к отказу. Для FakeIP в pre-match `resolve` обязателен.

Исходники: option/rule_action.go (`RouteActionResolve`), route/rule/rule_action.go (`RuleActionResolve`), route/route.go (`actionResolve`).

### direct (не документировано)

Значение `direct` есть в перечислении действий кода и схемы, в документации его нет. Поля — dial-поля без `detour` (`bind_interface`, `inet4_bind_address`, `inet6_bind_address`, `bind_address_no_port`, `protect_path`, `routing_mark`, `reuse_addr`, `netns`, `connect_timeout`, `tcp_fast_open`, `tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`, `udp_fragment`, `domain_resolver`, `network_strategy`, `fallback_network_type`, `fallback_delay`; `network_type` уходит в условия), описание — [shared.md](shared.md#поля-подключения-dial); `detour` — `unknown field`. Check собирает для него dialer, но **в 1.14.2 маршрутизатор это действие не исполняет**: при обычном переборе правило пропускается, в pre-match на нём перебор останавливается. Использовать не нужно.

Исходники: option/rule_action.go (`DirectActionOptions`), route/rule/rule_action.go (`RuleActionDirect`), route/route.go.

## Сниффинг протоколов

Список из кода (`RuleActionSniff.build`). Значения годятся и для `sniffer` действия `sniff`, и для условия `protocol`.

| Имя | Сеть | Домен | client | По умолчанию |
|---|---|---|---|---|
| `tls` | TCP | SNI | — | потоковый |
| `http` | TCP | заголовок Host | — | потоковый |
| `quic` | UDP | SNI | `chromium`, `safari`, `firefox`, `quic-go`, `unknown` | пакетный |
| `dns` | TCP и UDP | — | — | оба |
| `stun` | UDP | — | — | пакетный |
| `bittorrent` | TCP и UDP (uTP, UDP-трекер) | — | — | оба |
| `dtls` | UDP | — | — | пакетный |
| `ssh` | TCP | — | программа клиента из баннера | потоковый |
| `rdp` | TCP | — | — | потоковый |
| `ntp` | UDP | — | — | пакетный |

Без `sniffer` включены все: потоковые — tls, http, dns, bittorrent, ssh, rdp; пакетные — dns, quic, stun, bittorrent (uTP и UDP-трекер), dtls, ntp.

Исходники: route/rule/rule_action.go, route/route.go, constant/protocol.go, common/sniff/*.go.

## Pre-match

Прогон правил маршрутизации до установления соединения. Касается L3-входящих — tun и эндпоинтов wireguard и tailscale: у TCP ещё нет данных, у UDP есть только первый пакет. Правило, действию которого нужно больше данных, чем есть, останавливает pre-match на себе, и дальше соединение идёт обычным путём. Этот раздел — основное описание pre-match. Что делает каждое действие в pre-match по коду 1.14.2:

| Действие | В pre-match |
|---|---|
| `route` | L3-пересылка без перевода в L4, если целевой исходящий её поддерживает: ICMP — direct, bridge, эндпоинты wireguard и tailscale; TCP и UDP (с 1.14, раньше только ICMP) — bridge и эти эндпоинты; иначе продолжение обычным путём. Без совпавшего правила — то же для исходящего по умолчанию (у группы — текущий выбранный участник). Для FakeIP-адресов нужен предшествующий `resolve` в pre-match, иначе соединение отвергается. |
| `route-options` | применяются подмены адреса/порта и `udp_timeout`, перебор продолжается |
| `sniff` | с 1.14: UDP — сниффинг первого пакета, перебор продолжается; TCP или нехватка данных (например, фрагментированный QUIC ClientHello) — остановка |
| `resolve` | разрешение; ошибка — отказ |
| `reject` | TCP RST / ICMP unreachable / drop; `reply` для ICMP — продолжение |
| `hijack-dns` | только UDP, иначе остановка |
| `bypass` | с 1.13: обход sing-box на уровне ядра — только Linux с `auto_redirect` (без `outbound` правило действует только в pre-match от `auto_redirect`); с `outbound` вне этого случая — как `route` |
| `direct` и прочее | остановка pre-match, дальше обычный путь |

На Windows `bypass` (обход ядром) недоступен, `bridge` работает через WinDivert. Документация pre-match перечисляет только `reject`, `route`, `sniff`, `bypass`; обработку `route-options`, `resolve`, `hijack-dns` видно лишь в коде.

Исходники: route/route.go (`PreMatch`, `preMatchFlow`), route/rule/rule_action.go; документация: docs/configuration/shared/pre-match.md.

## Rule-set

Элемент `route.rule_set` (с 1.8): именованный набор «безголовых» правил (headless rule), на который ссылаются по тегу правила маршрутизации (`rule_set`), DNS-правила ([dns.md](dns.md)) и tun (`route_address_set`, `route_exclude_address_set` — [inbounds.md](inbounds.md)). Объект — двухпроходный: сначала общие поля, затем поля конкретного типа (строго). Наборы, на которые ничего не ссылается, после запуска выгружаются из памяти.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | `inline` | `inline` (с 1.10), `local`, `remote`. Пустое значение = `inline` (документация называет поле обязательным). Иное — check `unknown rule-set type`. |
| `tag` | string\|[string] | — (обязательно) | Тег. Пустой или отсутствующий, в том числе пустая строка в списке, — check `missing tag`. Повтор тега в любом месте `rule_set` — check `duplicate rule-set tag: X`. Список (с 1.14) — см. [Несколько тегов](#несколько-тегов-и-tag). |
| `format` | string | по расширению | `source` или `binary`. Для `local`/`remote` выводится из расширения `path` / пути в `url` (`.json` → `source`, `.srs` → `binary`; строка запроса `?…` не мешает, проверено). Не выводится — check `missing format`; иное значение — check `unknown rule-set format`. У `inline` значение игнорируется. **Windows:** абсолютный путь с буквой диска и обратными косыми (`C:\rules\a.json`) расширение не даёт: путь сначала разбирается как URL, `C:` становится схемой, и путь теряется — check `missing format` (проверено). Работают `C:/rules/a.json`, относительный `rules\a.json` или явный `format`. |

Исходники: option/rule_set.go (`RuleSet`, `ruleSetDefaultFormat`), route/rule/rule_set.go, route/router.go (`Initialize`).

### inline

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `rules` | [object] | — (обязательно) | [Headless-правила](#headless-правило). Пустой массив — check: `empty inline rule-set`. |

Исходники: option/rule_set.go (`PlainRuleSet`), route/rule/rule_set_local.go.

### local

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `path` | string | — | Путь к файлу. Относительный путь — от рабочего каталога sing-box (`-D`, иначе текущий каталог процесса); tray-sing-box запускает sing-box с каталогом данных в качестве рабочего. Файл читается уже в check: отсутствие, ошибка разбора, неизвестные поля, неверная версия — ошибка check. С 1.10 файл отслеживается и перечитывается при изменении; ошибка перечитывания пишется в лог, старые правила остаются. |

Исходники: option/rule_set.go (`LocalRuleSet`), route/rule/rule_set_local.go.

### remote

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `url` | string | — | Адрес загрузки. Отсутствие check не ловит — ошибка при старте (загрузка не удастся). |
| `initial_path` | string | — | с 1.14. Локальный файл с начальным содержимым: читается при старте, если в кэше нет копии, чтобы запуск не ждал загрузки; сразу после старта набор всё равно обновляется. Отсутствующий или битый файл — предупреждение, затем обычная загрузка. |
| `http_client` | string\|object -> http_client | `route.default_http_client` | с 1.14. HTTP-клиент загрузки: тег из `http_clients` или встроенный объект ([config.md](config.md#http_clients)). Пустой объект = клиент по умолчанию. Несуществующий тег — **при старте**, даже при наличии кэша. |
| `update_interval` | duration | `1d` | Интервал обновления. |
| `download_detour` | string -> outbound | — | Устарело в 1.14, удаление в 1.16 (пока предупреждение). Исходящий для загрузки. Вместе с непустым `http_client` — **при старте**: `http_client is conflict with deprecated download_detour field`. |

Порядок при старте: копия из `experimental.cache_file` (только если кэш включён и копия скачана с того же URL; при смене URL — перекачка) → `initial_path` → загрузка (запуск ждёт её; неудача — ошибка старта `initial rule-set: <tag>`). Поэтому несуществующий исходящий в `download_detour` или в `detour` HTTP-клиента роняет запуск, только когда кэша нет. Дальше — фоновые обновления по `update_interval` (поддерживается ETag / 304); ошибка обновления пишется в лог, действуют прежние правила. Без `http_clients` и `default_http_client` используется неявный клиент через исходящий по умолчанию (устарело в 1.14, удаление в 1.16).

Исходники: option/rule_set.go (`RemoteRuleSet`), route/rule/rule_set_remote.go, route/rule/rule_set_updater.go, common/httpclient/manager.go, experimental/deprecated/constants.go.

### Несколько тегов и {tag}

с 1.14. `tag` может быть списком — это несколько наборов с общими остальными полями. Заполнитель `{tag}` в `path` (local), `url` и `initial_path` (remote) заменяется каждым тегом. Проверено:

- список тегов без `{tag}` в `path` или `url` — check: `missing {tag} placeholder in path` / `… in url`; если задан `initial_path` без `{tag}` — `… in initial_path`;
- `inline` со списком — check: `inline rule-set does not support multiple tags`;
- каждый тег затем — отдельный набор, ссылаться можно на любой (`"rule_set": ["a", "b"]`); повтор тега внутри списка — `duplicate rule-set tag`.

Пример: `{"type": "local", "tag": ["geosite-a", "geosite-b"], "path": "rules/{tag}.srs"}`.

Исходники: option/rule_set.go (`UnmarshalJSON`), constant/rule.go (`RuleSetTagPlaceholder`), route/router.go.

### Исходный формат (source)

JSON-файл набора (`format: source`) и вход `sing-box rule-set compile`. Разбирается строго: неизвестный ключ — ошибка.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `version` | int | — (обязательно) | 1–5. Отсутствие или 0 — `missing rule-set version`, больше 5 — `unknown rule-set version`. |
| `rules` | [object] | — | [Headless-правила](#headless-правило). |

Версии: 1 — 1.8 (первая); 2 — 1.10 (компактный `domain_suffix` в бинарном виде, правила AdGuard); 3 — 1.11 (`network_type`, `network_is_expensive`, `network_is_constrained`); 4 — 1.13 (`network_interface_address`, `default_interface_address`); 5 — 1.14 (`package_name_regex`). При загрузке исходного файла версия **не сверяется** с использованными полями (файл версии 1 с `package_name_regex` загружается, проверено); сверку делает только `compile`.

Исходники: option/rule_set.go (`PlainRuleSetCompat`), constant/rule.go.

### Headless-правило

Правило внутри набора: только условия, без действия. Логика совпадения та же, что у правила маршрутизации: группы адреса назначения (`domain*`, `ip_cidr`), порта назначения, адреса источника (`source_ip_cidr`), порта источника, остальное — И. Набор совпадает, если совпало любое его правило.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | `default` | `default` или `logical`. |
| `query_type` | string\|int\|[string\|int] | — | Тип DNS-запроса именем (`A`, `HTTPS`) или числом; неизвестное имя — ошибка разбора. Только для DNS-правил; в правилах маршрутизации не совпадает. С 1.14 действует и на внутренние DNS-запросы ([dns.md](dns.md)). |
| `network` | string\|[string] | — | `tcp`, `udp` (код принимает и `icmp`). |
| `domain` | string\|[string] | — | Как в правиле маршрутизации. |
| `domain_suffix` | string\|[string] | — | Как в правиле маршрутизации. |
| `domain_keyword` | string\|[string] | — | Как в правиле маршрутизации. |
| `domain_regex` | string\|[string] | — | Как в правиле маршрутизации. |
| `source_ip_cidr` | string\|[string] | — | IP источника. |
| `ip_cidr` | string\|[string] | — | IP назначения; при `rule_set_ip_cidr_match_source` у ссылающегося правила — IP источника. |
| `source_port` | int\|[int] | — | |
| `source_port_range` | string\|[string] | — | |
| `port` | int\|[int] | — | |
| `port_range` | string\|[string] | — | |
| `process_name` | string\|[string] | — | Linux, Windows, macOS. |
| `process_path` | string\|[string] | — | Linux, Windows, macOS. |
| `process_path_regex` | string\|[string] | — | с 1.10. Linux, Windows, macOS. |
| `package_name` | string\|[string] | — | Android. |
| `package_name_regex` | string\|[string] | — | с 1.14 (бинарная версия 5). Android. |
| `network_type` | string\|[string] | — | с 1.11 (бинарная версия 3). Графические клиенты Android/Apple. |
| `network_is_expensive` | bool | `false` | с 1.11 (версия 3). Графические клиенты Android/Apple. |
| `network_is_constrained` | bool | `false` | с 1.11 (версия 3). Графические клиенты Apple. |
| `wifi_ssid` | string\|[string] | — | Платформы — как у правила маршрутизации (включая Windows с 1.13). |
| `wifi_bssid` | string\|[string] | — | То же. |
| `network_interface_address` | object | — | с 1.13 (версия 4). Графические клиенты Android/Apple. |
| `default_interface_address` | string\|[string] | — | с 1.13 (версия 4). Linux, Windows, macOS. |
| `invert` | bool | `false` | |

Логическое headless-правило (`"type": "logical"`):

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — | `logical`. |
| `mode` | string | — (обязательно) | `and` или `or`; пусто или иное — check `unknown logical mode` (проверено). |
| `rules` | [object] | — (обязательно) | Вложенные headless-правила, обычные или снова логические (вложенность проверена). Пустой список — check `missing conditions` (проверено). |
| `invert` | bool | `false` | Инвертировать результат. |

Нельзя (ошибка `unknown field`, проверено на части): `inbound`, `ip_version`, `auth_user`, `protocol`, `client`, `ip_is_private`, `source_ip_is_private`, `user`, `user_id`, `clash_mode`, `interface_address`, `source_mac_address`, `source_hostname`, `preferred_by`, `rule_set`, любые ключи действий.

Исходники: option/rule_set.go (`DefaultHeadlessRule`, `LogicalHeadlessRule`), route/rule/rule_headless.go.

### Бинарный формат (.srs)

Файл: сигнатура `SRS`, байт версии, далее сжатый zlib поток правил. Версии те же 1–5; файл версии выше 5 — ошибка `unsupported version`. `rule-set compile` пишет минимальную достаточную версию, но не ниже 2: объявленная v5 понижается до v4 без `package_name_regex`, v4 до v3 без полей интерфейсных адресов, v3 до v2 без `network_type`/`network_is_*` (проверено: v5 с одним `domain` → файл v2; версия 1 остаётся 1). Если объявленная версия ниже нужной — ошибка компиляции, например `` `network_type` rule item is only supported in version 3 or later ``. Бинарный набор с правилами AdGuard нельзя декомпилировать.

Исходники: common/srs/binary.go, cmd/sing-box/cmd_rule_set_compile.go (`downgradeRuleSetVersion`).

### AdGuard DNS filter

с 1.10. Фильтр AdGuard не является исходным форматом набора: его переводят в бинарный `.srs` командой `sing-box rule-set convert --type adguard`. Поддерживается: `||`, `|`, `^`, `*`, исключения `@@`, доменные хосты, регулярные выражения `/…/`, модификатор `$important`; `$dnsrewrite` с неопределённым адресом (`0.0.0.0`, `::`) игнорируется; префикс схемы `…://` (например, `https://`) отбрасывается, и строка становится правилом суффикса домена, как с `||` (по коду); модификаторы `$app`, `$network`, `$dnstype` и любые другие выбрасывают строку целиком; строки hosts принимаются только с адресом `0.0.0.0`; файл из одних доменов считается простым списком точных доменов. Не поддерживаются IP-хосты, порты, пути, прочие модификаторы — такие строки пропускаются (в debug-логе). Совпадение проверено: `||ads.example.org^` ловит домен и поддомены, `@@||good.ads.example.org^` его исключает. Какое именно правило AdGuard совпало, sing-box не сообщает.

Исходники: common/convertor/adguard/convertor.go, route/rule/rule_item_adguard.go; документация: docs/configuration/rule-set/adguard.md.

### Команды sing-box rule-set

`compile`, `decompile`, `format`, `upgrade`, `match`, `merge`, `convert` — флаги, умолчания и особенности (вывод `match` в stderr, выбор формата) описаны в [cli.md](cli.md#rule-set). Для проверки семантики удобен `sing-box rule-set match <файл> <домен|IP>`: он печатает совпавшие правила.

Исходники: cmd/sing-box/cmd_rule_set*.go.

## Регистр ключей в разделе route

Общее правило сопоставления ключей — в [cli.md](cli.md#сопоставление-ключей-и-неизвестные-поля) и [config.md](config.md). Применительно к `route` (всё проверено на 1.14.2):

- **Объект `route`** и объекты, разбираемые одним проходом (`default_domain_resolver`, объект `http_client`), — ключи без учёта регистра, с простым свёртыванием Unicode: `"Rules"`, `"Final"`, `"Rule_Set"`, `"rule_ſet"` (U+017F), `"default_marK"` с KELVIN SIGN U+212A работают.
- **Правило маршрутизации** разбирается в два прохода: условия, затем действие; ключи условий, записанные не в точном виде, распознаются, но ещё раз попадают в разбор действия. Итог: `"Domain"`, `"Invert"`, `"Type"`, `"Mode"` дают `unknown field` в правилах с `route`, `bypass`, `sniff`, `resolve`, `hijack-dns`, но **проходят** в правилах с `reject` и `route-options` (у них нестрогий разбор): там `{"Domain": "a.com", "action": "reject"}` — рабочее условие. Сам ключ `"Action"` проходит с `reject`, `route-options`, `hijack-dns` и даёт `unknown field` с `route`, `bypass`, `sniff`, `resolve`. Ключи параметров действия (`Outbound`, `OVERRIDE_PORT`, `Sniffer`, `Method`, `STRATEGY`) принимаются в любом регистре.
- **Rule-set**: `type`, `tag`, `format` — только в точном виде (`"Tag"`, `"Type"`, `"Format"` — `unknown field`); `path`, `url`, `update_interval`, `rules` и ключи headless-правил — в любом регистре.
- **Лишние ключи**: в `route`, в правилах с `route`/`bypass`/`sniff`/`resolve`/`hijack-dns`, в rule-set и в исходных файлах наборов — ошибка; в правилах с `reject` и `route-options` — молча игнорируются.

Для tray-sing-box: свёртка регистра в `configfile/guard.go` и `dependency.go` по-прежнему консервативна — вариант ключа, который sing-box отвергает, до запуска не дойдёт, а принятый вариант свёрткой учтён.

Исходники: option/rule.go (`DefaultRule.UnmarshalJSON`, `unmarshalDefaultRuleContext`), option/rule_action.go (`RuleAction.UnmarshalJSON`, `RejectActionOptions`, `RouteOptionsActionOptions`), option/rule_set.go; библиотека github.com/sagernet/sing/common/json/badjson (`UnmarshallExcluded`; в дереве sing-box её нет, вывод по поведению бинарника).

## Что проверяет check, а что — только запуск

`sing-box check` = разбор JSON + `box.New` (создание маршрутизатора, правил, наборов, сетевого менеджера, исходящих) без `Start`. Всё ниже проверено на 1.14.2, кроме строк с пометкой «по коду».

| Ситуация | Когда падает |
|---|---|
| Неизвестный ключ (строгие части), неверный тип значения, неизвестные `type`/`mode`/`action`/`method`/стратегия/тип интерфейса | check |
| Действие во вложенном правиле; пустой `rules` логического правила; вложенное правило без условий | check |
| Пустой элемент `domain`/`domain_suffix`; ошибка в `domain_regex`/`process_path_regex`/`package_name_regex`; неверный CIDR; `port_range` без двоеточия; `ip_version` не 4/6 | check |
| `geosite`, `geoip`, `source_geoip` в правиле; `rule_set_ipcidr_match_source` вместе с `rule_set` | check |
| Пустой `route-options`; `tls_fragment` + `tls_record_fragment` в `route-options`; `drop` + `no_drop`; `tls_spoof_method` без `tls_spoof`; неизвестный `sniffer` | check |
| Rule-set: нет тега, повтор тега, список тегов без `{tag}`, `inline` со списком, неизвестные `type`/`format`, невыводимый `format`, пустой `inline`; local-файл отсутствует, битый, с неверной `version` или лишним ключом | check |
| `default_mark` не на Linux, `override_android_vpn` не на Android; `default_network_strategy` без `auto_detect_interface` или с `default_interface` | check |
| `default_domain_resolver` на несуществующий сервер; не задан при 2+ DNS-серверах (без `ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true`) | check |
| Ссылка на несуществующий rule-set из DNS-правила или из tun `route_address_set` ([dns.md](dns.md), [inbounds.md](inbounds.md)) | check |
| `route.final` на несуществующий тег | при старте |
| `rule_set` в правиле маршрутизации на несуществующий тег | при старте |
| `preferred_by` на несуществующий или неподходящий исходящий | при старте |
| `default_http_client` на несуществующий тег (даже без удалённых наборов); `http_client` набора на несуществующий тег; `http_client` вместе с `download_detour` | при старте (по коду) |
| Удалённый набор без кэша и без `initial_path` не загрузился: нет `url`, сеть, 404, битое содержимое, `download_detour`/`detour` клиента на несуществующий исходящий | при старте (по коду); с кэшем — старт проходит, ошибки обновлений в лог |
| `outbound` правила пустой или несуществующий; исходящий без TCP/UDP | при подключении |
| `resolve.server` на несуществующий DNS-сервер; ошибка разрешения | при подключении |
| `reject` c `method: reply` для TCP/UDP | при подключении |
| `inbound`, `clash_mode`, `protocol`, `network` с несуществующими значениями | никогда: условие просто не совпадает |
| `route.geoip` / `route.geosite` | никогда: игнорируются |

Проверка зависимостей исходящих (detour, члены групп) и ссылок из DNS — в [outbounds.md](outbounds.md#пространство-тегов-detour-и-порядок-старта) и [dns.md](dns.md#проверка-что-ловит-sing-box-check-а-что-только-запуск). В tray-sing-box то, что из этой таблицы падает при старте, повторяет `internal/infrastructure/configfile/dependency.go`: `route.final`, `rule_set` и `preferred_by` правил (включая вложенные), `download_detour` и `http_client` rule-set, `route.default_http_client`, `detour` элемента `http_clients`, через который rule-set скачивается. Не повторяет: неудачную загрузку rule-set без кэша и `http_client` вместе с `download_detour` ([config.md](config.md#заметки-для-tray-sing-box)).

Исходники: cmd/sing-box/cmd_check.go, box.go, route/router.go (`Initialize` — check, `Start` — старт), route/rule/rule_item_rule_set.go, route/rule/rule_item_preferred_by.go, adapter/outbound/manager.go, common/httpclient/manager.go, route/rule/rule_set_remote.go.

## Платформы и Windows

| Что | Где работает | На Windows (CLI, как в tray-sing-box) |
|---|---|---|
| `process_name`, `process_path`, `process_path_regex`, `find_process` | Linux, Windows, macOS; Android — графический клиент | работают для соединений с локального адреса; путь Win32, сравнение с учётом регистра |
| `package_name`, `package_name_regex` | Android | не совпадают |
| `user`, `user_id` | Linux | не совпадают |
| `wifi_ssid`, `wifi_bssid` | Android/Apple (графические), Linux, Windows | работают (WLAN API, с 1.13) |
| `network_type`, `network_is_expensive`, `network_is_constrained`, `network_interface_address` | графические клиенты Android/Apple | тип сети не определяется: по коду `network_type: wifi` совпадает всегда, остальные — никогда |
| `interface_address`, `default_interface_address` | Linux, Windows, macOS | работают |
| `source_mac_address`, `source_hostname`, `find_neighbor`, `dhcp_lease_files` | Linux, macOS; графические Android/macOS | не совпадают, поля ничего не делают |
| `clash_mode` | где есть `clash_api` / сервис `api` / графический клиент | нужен `experimental.clash_api` |
| `network: icmp`, ICMP в `reject` | tun, wireguard, tailscale | через tun |
| `auto_detect_interface`, `default_interface` | Linux, Windows, macOS | работают; `default_interface` приоритетнее (по коду) |
| `default_mark` | Linux | ошибка check |
| `override_android_vpn` | Android | ошибка check |
| `default_network_strategy` и прочие `default_network*`, `network_strategy` в route-options | графические клиенты Android/Apple | принимаются (стратегия — только с `auto_detect_interface`), не действуют |
| `bypass` (обход ядром) | Linux с `auto_redirect` | нет; с `outbound` = `route` |
| `tls_spoof` | Linux, macOS, Windows | amd64/386, через WinDivert, нужны права администратора; ARM64 — ошибка check |
| `tls_fragment` с автоподбором задержки | Linux, Apple, Windows | автоподбор — только с правами администратора |
| `preferred_by` → `bridge` | где есть bridge | bridge на Windows — через WinDivert |
| вывод `format` rule-set из `path` | везде | путь `C:\…` с обратными косыми формат не даёт (`missing format`); писать `C:/…`, относительный путь или явный `format` |

Исходники: common/process/searcher_windows.go, route/neighbor_resolver_stub.go, common/settings/wifi_windows.go, route/network.go, common/tlsspoof/raw_windows.go, common/dialer/default.go.

## Расхождения документации и кода

1. **`route-options.fallback_delay`** — в документации строка-длительность (`"fallback_delay": ""`, ссылка на dial-поля), в коде `uint32` в наносекундах; `"300ms"` не проходит разбор (проверено). JSON Schema из того же дерева правильно указывает integer.
2. **`route-options.network_type` / `fallback_network_type`** описаны в документации, в опциях 1.14.2 их нет. `network_type` становится условием правила, `fallback_network_type` — `unknown field` (или игнорируется в `route-options`). Внутренние поля `NetworkType`/`FallbackNetworkType` у действия в коде есть, но из конфига не заполняются.
3. **`tls_record_fragment`** в примере документации записан как строка `""`, в коде bool (строка — ошибка разбора).
4. **Действие `direct`** есть в коде и схеме, в документации нет, и при маршрутизации 1.14.2 оно не исполняется.
5. **`default_interface`**: документация говорит, что поле не действует при `auto_detect_interface`; в коде (`common/dialer/default.go`) наоборот — `default_interface` проверяется первым и побеждает.
6. **`preferred_by`**: таблица документации называет `tailscale`, `wireguard`, `bridge`; в коде интерфейс предпочтительных маршрутов реализуют также эндпоинты `openvpn-client` и `openconnect`.
7. **Pre-match**: документация перечисляет `reject`, `route`, `sniff`, `bypass`; код также обрабатывает `route-options`, `resolve`, `hijack-dns` (UDP).
8. **Rule-set `type`** помечен как обязательный (`local` или `remote`), в коде пустое значение = `inline`.
9. **Headless-правило**: документация пишет логику совпадения без группы `source_ip_cidr` и `network` только `tcp`/`udp`; в коде `source_ip_cidr` — отдельная группа (ИЛИ внутри, И с остальными), а `icmp` принимается.
10. **`route.geoip` / `route.geosite`** значатся удалёнными в 1.12, но ключи до сих пор разбираются и молча игнорируются; удалены только условия правил.
11. **Страница Protocol Sniff** начинается со слов о сниффинге «во входящем» — поля сниффинга входящих удалены в 1.13, осталось только действие `sniff`.
12. **`sing-box check` против документации «Required»**: `outbound` у действия `route` помечен обязательным, но check пропускает правило без него — ошибка появляется на каждом совпавшем соединении (`outbound not found: `). Так же `url` у remote-набора.
13. **Регистр значений доменных условий** документация не оговаривает; по коду и проверке значения должны быть в нижнем регистре, иначе условие никогда не совпадает.
14. **Лишние ключи** в правилах с `reject` и `route-options` не отвергаются вопреки строгому разбору остального конфига (это поведение библиотеки, а не документированная возможность).
15. **Вывод `format` по расширению** (`option/rule_set.go`, `ruleSetDefaultFormat`) сначала пропускает `path` через `url.Parse`; на Windows путь `C:\…\x.json` разбирается как URL со схемой `c` и пустым путём, формат не определяется, check падает с `missing format` (проверено). Документация обещает вывод по расширению без оговорок.

Не проверено запуском (только по коду, `run` запрещён в этой среде): что `network_type: wifi` на Windows совпадает всегда; ошибки старта для `default_http_client`/`http_client`/загрузки удалённых наборов; поведение `default_interface` против `auto_detect_interface`; неисполнение `direct`.

Исходники документации: docs/configuration/route/index.md, rule.md, rule_action.md, sniff.md; docs/configuration/rule-set/index.md, source-format.md, headless-rule.md, adguard.md; docs/configuration/shared/pre-match.md; docs/changelog.md; docs/deprecated.md; docs/migration.md; docs/schema.json.
