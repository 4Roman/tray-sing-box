# Устаревшие и удалённые возможности sing-box (1.8 → 1.14.2)

Справочник для обновления sing-box со старой версии сразу до последней стабильной 1.14.2 (выпущена 24.09.2026): что объявлено устаревшим, что удалено, переименовано или поменяло смысл, и что ответит бинарник 1.14.2 на старый конфиг. tray-sing-box обновляет sing-box с любой версии прямо до последней, поэтому в config.json пользователя могут остаться возможности, удалённые несколько версий назад.

Как проверялось: все цитаты сообщений получены прогоном `sing-box.exe check -c <файл>` версии 1.14.2 (windows-amd64) на небольших конфигах; ANSI-коды цвета из цитат убраны. `FATAL[0000] …` означает код выхода 1, `WARN[0000] …` — код 0. Где проверка требует запуска (`run`), поведение выведено из исходников и помечено «по коду». Сообщения sing-box всегда на английском.

Связанные файлы: общий формат конфига, декодер и регистр ключей — [config.md](config.md); команды CLI, в том числе что делает `check` — [cli.md](cli.md); актуальные поля — [inbounds.md](inbounds.md), [outbounds.md](outbounds.md), [shared.md](shared.md), [dns.md](dns.md), [route.md](route.md), [experimental.md](experimental.md).

Ключи конфига сопоставляются без учёта регистра (подробно — в [config.md](config.md)), и устаревшие ключи тоже: `"Sniff": true` и `"Inet4_Address"` дают те же ошибки, что и `sniff` / `inet4_address` (проверено).

## Механизм устаревания в 1.14.2

### Три судьбы устаревшей возможности

1. **Жёстко удалена.** Поле ещё объявлено в `option/*.go` (с пометкой `schema:"omit"`, в JSON Schema его нет), но код отвергает его текстом вида «… is deprecated in sing-box X and removed in sing-box Y». Переменные окружения не помогают. Ошибка возникает при декодировании (`decode config at <файл>: <путь>: …`) или при создании компонента (`initialize inbound[0]: …`, `initialize router: parse rule[0]: …`). В обоих случаях её ловит `check`. Исключения, которые падают только при старте, собраны в разделе [Принимается молча или падает только при старте](#принимается-молча-или-падает-только-при-старте).
2. **Заметка устаревания** (`experimental/deprecated`). Возможность работает, но при использовании сообщает о себе. Если удаление назначено на текущую или следующую минорную версию, sing-box пишет ERROR, затем FATAL и завершается. Отключается это переменной `ENABLE_DEPRECATED_<ИМЯ>=true`. В остальных случаях пишется WARN.
3. **Пережиток без реакции.** Поле декодируется и молча игнорируется или тихо переносится в новое, без ошибки и без предупреждения.

### Заметки устаревания и переменные ENABLE_DEPRECATED_*

Заметка считается «надвигающейся» (`Note.Impending`), если разница минорных номеров «версия удаления − текущая версия» не больше 1. Для 1.14.2 заметки с удалением в 1.14.0 (разница 0) фатальны, а с удалением в 1.16.0 (разница 2) дают только WARN. Если разница отрицательна и текущая версия не пререлиз, sing-box паникует (`invalid deprecated note`). Значит, в стабильном 1.15.0 заметок с удалением в 1.14.0 уже быть не может: они уйдут вместе с возможностями.

Менеджер устаревания CLI (`NewStderrManager`) работает одинаково для `run` и `check`:

| Случай | Что выводится | Итог |
|---|---|---|
| заметка не надвигающаяся | `WARN <описание> is deprecated in sing-box <A> and will be removed in sing-box <B>, checkout documentation for migration: <ссылка>`; без ссылки строка кончается на `… will be removed in sing-box <B>.` | работа продолжается |
| надвигающаяся, переменная не задана | `ERROR <то же>`, затем `FATAL to continuing using this feature, set environment variable ENABLE_DEPRECATED_<ИМЯ>=true` | выход с кодом 1 |
| надвигающаяся, переменная истинна | та же строка как `WARN` | работа продолжается |

- Каждая заметка сообщается один раз за процесс.
- Значение переменной разбирает `strconv.ParseBool`. Истиной считаются `1`, `t`, `T`, `true`, `TRUE`, `True`; `yes` и `on` не подходят (проверено: `=yes` оставляет FATAL).
- На Windows имя переменной не зависит от регистра (проверено: `enable_deprecated_outbound_dns_rule_item=true` сработала).
- Переменная снимает только свою заметку. В проверке `ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true` лишь пропустила разбор дальше, до следующей фатальной заметки того же конфига (`MISSING_DOMAIN_RESOLVER`).
- Графические клиенты (`daemon/deprecated.go`) процесс не завершают: они собирают заметки и показывают их. Локализованные тексты (`experimental/locale`) используются только там.

Часть заметок сообщается при создании компонентов (`box.New`), и её видит `check`. Другая часть сообщается только в `Start` (DNS-маршрутизатор, удалённые rule-set, HTTP-клиент по умолчанию), и `check` её не покажет никогда. Подробности — в колонке «Когда» таблицы ниже.

### Куда пишутся сообщения

Менеджер пишет в стандартный логгер CLI, то есть в stderr. Настройки `log.output` и `log.disabled` конфига на это не влияют (проверено: при заданном `log.output` WARN ушёл в stderr, а файл лога при `check` даже не создался). У tray-sing-box stderr sing-box попадает в `sing-box-console.log`, а не в файл из `log.output`.

Исходники: experimental/deprecated/constants.go, experimental/deprecated/manager.go, experimental/deprecated/stderr.go, cmd/sing-box/cmd.go, daemon/deprecated.go, experimental/locale/locale.go.

## Заметки устаревания 1.14.2 (полный список)

Колонка «Переменная» содержит суффикс; полное имя — `ENABLE_DEPRECATED_<суффикс>`.

| Имя заметки | Переменная | Что сообщается | Устарело | Удаление | Реакция 1.14.2 | Когда (видит ли `check`) |
|---|---|---|---|---|---|---|
| `outbound-dns-rule-item` | `OUTBOUND_DNS_RULE_ITEM` | поле `outbound` в DNS-правиле | 1.12.0 | 1.14.0 | ERROR + FATAL | создание DNS-правила (да) |
| `missing-domain-resolver` | `MISSING_DOMAIN_RESOLVER` | нет ни `route.default_domain_resolver`, ни `domain_resolver`, адрес назначения — домен, `detour` нет, DNS-серверов не меньше двух. У `naive`, `openconnect`, `openvpn-client`, `tailscale` то же условие — не заметка, а жёсткая ошибка `missing domain resolver for domain server address`, переменная не помогает (проверено для `naive`) | 1.12.0 | 1.14.0 | ERROR + FATAL | создание исходящего (да) |
| `legacy-domain-strategy-options` | `LEGACY_DOMAIN_STRATEGY_OPTIONS` | `domain_strategy` в dial-полях | 1.12.0 | 1.14.0 | ERROR + FATAL | создание исходящего (да) |
| `inline-acme-options` | `INLINE_ACME_OPTIONS` | `tls.acme` во входящем с непустым `domain` | 1.14.0 | 1.16.0 | WARN | создание TLS-сервера (да, проверено: WARN `inline ACME options in TLS is deprecated …` в выводе `check`, сеть при этом не нужна) |
| `legacy-rule-set-download-detour` | `LEGACY_RULE_SET_DOWNLOAD_DETOUR` | `download_detour` удалённого rule-set | 1.14.0 | 1.16.0 | WARN | старт rule-set (нет) |
| `dns-rule-rule-set-ip-cidr-accept-empty` | `DNS_RULE_RULE_SET_IP_CIDR_ACCEPT_EMPTY` | `rule_set_ip_cidr_accept_empty` в DNS-правиле | 1.14.0 | 1.16.0 | WARN в legacy-режиме DNS, иначе ошибка | создание DNS-правила (да) |
| `legacy-dns-address-filter` | `LEGACY_DNS_ADDRESS_FILTER` | адресные поля DNS-правил без `match_response` | 1.14.0 | 1.16.0 | WARN (в сочетании с полями нового режима — ошибка, см. ниже) | старт DNS-маршрутизатора (нет) |
| `legacy-dns-rule-strategy` | `LEGACY_DNS_RULE_STRATEGY` | `strategy` в действии DNS-правила | 1.14.0 | 1.16.0 | WARN (в сочетании с полями нового режима — ошибка) | старт DNS-маршрутизатора (нет) |
| `independent-dns-cache` | `INDEPENDENT_DNS_CACHE` | `dns.independent_cache` | 1.14.0 | 1.16.0 | WARN | создание DNS-маршрутизатора (да) |
| `store-rdrc` | `STORE_RDRC` | `experimental.cache_file.store_rdrc` | 1.14.0 | 1.16.0 | WARN | создание cache-file (да, но только при `cache_file.enabled: true`) |
| `implicit-default-http-client` | `IMPLICIT_DEFAULT_HTTP_CLIENT` | неявный HTTP-клиент через исходящий по умолчанию: нет ни `http_clients`, ни `route.default_http_client` | 1.14.0 | 1.16.0 | WARN | первое обращение к клиенту по умолчанию, обычно загрузка удалённого rule-set при старте (нет) |

Реальные строки 1.14.2 (выход `check`):

```
ERROR[0000] outbound DNS rule item is deprecated in sing-box 1.12.0 and will be removed in sing-box 1.14.0, checkout documentation for migration: https://sing-box.sagernet.org/migration/#migrate-outbound-dns-rule-items-to-domain-resolver
FATAL[0000] to continuing using this feature, set environment variable ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true

ERROR[0000] missing `route.default_domain_resolver` or `domain_resolver` in dial fields is deprecated in sing-box 1.12.0 and will be removed in sing-box 1.14.0, checkout documentation for migration: https://sing-box.sagernet.org/migration/#migrate-outbound-dns-rule-items-to-domain-resolver
FATAL[0000] to continuing using this feature, set environment variable ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true

ERROR[0000] legacy domain strategy options is deprecated in sing-box 1.12.0 and will be removed in sing-box 1.14.0, checkout documentation for migration: https://sing-box.sagernet.org/migration/#migrate-domain-strategy-options
FATAL[0000] to continuing using this feature, set environment variable ENABLE_DEPRECATED_LEGACY_DOMAIN_STRATEGY_OPTIONS=true

WARN[0000] `independent_cache` DNS option is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, checkout documentation for migration: https://sing-box.sagernet.org/migration/#migrate-independent-dns-cache
WARN[0000] `store_rdrc` cache file option is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, checkout documentation for migration: https://sing-box.sagernet.org/migration/#migrate-store-rdrc
WARN[0000] Legacy `rule_set_ip_cidr_accept_empty` DNS rule item is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, checkout documentation for migration: https://sing-box.sagernet.org/migration/#migrate-address-filter-fields-to-response-matching
```

1.14.2 пишет «will be removed in sing-box 1.14.0», хотя сама уже 1.14.2: три возможности 1.12 в коде не удалены. Они по-прежнему работают, но по умолчанию фатальны.

Ловушка `MISSING_DOMAIN_RESOLVER`: исходящий `direct` всегда считается «адресатом-доменом». Поэтому любой конфиг с двумя и более DNS-серверами и `direct` без `detour` падает, если не задан `route.default_domain_resolver` или `domain_resolver` у самого `direct` (проверено: два DNS-сервера и один `direct` дают FATAL). С одним DNS-сервером или без `dns.servers` заметка не срабатывает. Конфиг с двумя DNS-серверами и вообще без `outbounds` `check` проходит (проверено). По коду при запуске неявный `direct` создаётся в `Start` менеджера исходящих (`adapter/outbound/manager.go`, `defaultOutboundFallback`, заданный в `box.go`), его диалер проходит тот же `NewDNSQueryOptions`, и запуск должен завершиться той же фатальной заметкой (запуском не проверялось).

Переключатели прошлых версий. В строках бинарника 1.13.12 есть `LEGACY_DNS_SERVERS`, `LEGACY_DNS_FAKEIP_OPTIONS` и три переменные с удалением в 1.14.0 из таблицы выше. В 1.13.x все пять были фатальными по умолчанию. В 1.14.2 устаревшие DNS-серверы и `dns.fakeip` удалены жёстко, и эти две переменные ничего не дают (проверено: `ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true` не снимает ошибку). Имена переключателей 1.11–1.12 (для возможностей с удалением в 1.13) в этом исходнике не сохранились и не проверялись. Для 1.14.2 они бессмысленны: сами возможности удалены.

Исходники: experimental/deprecated/constants.go, common/dialer/dialer.go, route/rule/rule_item_outbound.go, route/rule/rule_dns.go, dns/router.go, experimental/cachefile/cache.go, common/tls/std_server.go, route/rule/rule_set_remote.go, common/httpclient/manager.go, box.go.

## Жёстко удалённые возможности: сообщения 1.14.2

Все строки проверены `check` 1.14.2, если не сказано иное. `<f>` — путь к конфигу, номера в `[N]` — индексы в конфиге.

| Что в конфиге | Устарело → удалено | Стадия | Сообщение 1.14.2 |
|---|---|---|---|
| исходящий `"type": "dns"` | 1.11 → 1.13 | декодирование | `decode config at <f>: outbounds[1]: dns outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead` |
| исходящий `"type": "wireguard"` только с `type`/`tag` | 1.11 → 1.13 | создание | `initialize outbound[0]: WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead` |
| исходящий `"type": "wireguard"` с любым настоящим полем | 1.11 → 1.13 | декодирование | `decode config at <f>: outbounds[0].server: json: unknown field "server"`: у заглушки нет полей, поэтому понятное сообщение не выводится |
| `"type": "shadowsocksr"` (входящий или исходящий) | 1.5 → 1.6 | создание | `initialize outbound[0]: ShadowsocksR is deprecated and removed in sing-box 1.6.0` (для входящего — `initialize inbound[0]: …`) |
| listen-поля `sniff`, `sniff_override_destination`, `sniff_timeout`, `domain_strategy`, `udp_disable_domain_unmapping` в любом входящем, кроме tun | 1.11 → 1.13 | декодирование | `decode config at <f>: inbounds[0]: legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-legacy-inbound-fields-to-rule-actions` |
| те же поля во входящем `tun` | 1.11 → 1.13 | создание | `initialize inbound[0]: legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, checkout migration: …` |
| tun `inet4_address`, `inet6_address`, `inet4_route_address`, `inet6_route_address`, `inet4_route_exclude_address`, `inet6_route_exclude_address` | 1.10 → 1.12 | создание | `initialize inbound[0]: legacy tun address fields are deprecated in sing-box 1.10.0 and removed in sing-box 1.12.0` |
| tun `"gso": true` | 1.11 → 1.12 (по коду) | создание | `initialize inbound[0]: GSO option in tun is deprecated in sing-box 1.11.0 and removed in sing-box 1.12.0` |
| direct `override_address` / `override_port` | 1.11 → 1.13 | декодирование | `decode config at <f>: outbounds[0]: destination override fields in direct outbound are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use route options instead` |
| direct `proxy_protocol` (не 0) | → 1.6 | создание | `initialize outbound[0]: Proxy Protocol is deprecated and removed in sing-box 1.6.0` |
| DNS-сервер старого формата (без `type` или `"type": "legacy"`, например `"address": "tls://1.1.1.1"`, `"rcode://refused"`) | 1.12 → 1.14 | декодирование | `decode config at <f>: dns.servers[0]: legacy DNS server formats are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats` |
| `dns.fakeip` с любым значением, даже `{}` | 1.12 → 1.14 | декодирование | `decode config at <f>: dns: legacy DNS fakeip options are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats` |
| правило маршрутизации `geoip` / `source_geoip` | 1.8 → 1.12 | создание | `initialize router: parse rule[0]: geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0` |
| правило маршрутизации `geosite` | 1.8 → 1.12 | создание | `initialize router: parse rule[0]: geosite database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0` |
| DNS-правило `geosite` / `geoip` / `source_geoip` | 1.8 → 1.12 | создание | `initialize dns router: parse dns rule[0]: geosite database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0` (для geoip — `geoip database …`) |
| `rule_set_ipcidr_match_source` в правиле маршрутизации вместе с непустым `rule_set` | 1.10 → 1.11 | создание | `initialize router: parse rule[0]: rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0` |
| `rule_set_ipcidr_match_source` в DNS-правиле вместе с непустым `rule_set` | 1.10 → 1.11 | создание | `initialize dns router: parse dns rule[0]: rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0` |
| clash_api `cache_file`, `cache_id`, `store_mode`, `store_selected`, `store_fakeip` | 1.8 | создание | `create clash-server: cache_file and related fields in Clash API is deprecated in sing-box 1.8.0, use experimental.cache_file instead.` |
| `tls.ech.pq_signature_schemes_enabled` / `tls.ech.dynamic_record_sizing_disabled` = `true` (входящий и исходящий) | 1.12 → 1.13 | создание | `initialize outbound[0]: legacy ECH options are deprecated in sing-box 1.12.0 and removed in sing-box 1.13.0` |

Наполовину переведённые DNS-серверы (`type` уже есть, а поля старые) отвергаются как неизвестные поля: `decode config at <f>: dns.servers[0].address: json: unknown field "address"`. То же для `address_resolver`, `address_strategy`, `strategy`, `client_subnet` (проверено для всех пяти). Сервер нового формата с доменом в `server`, без `detour` и без `domain_resolver` даёт `initialize DNS server[0]: missing domain resolver for domain server address`. Это не заметка устаревания, а обычная ловушка при переводе.

Фатальные сочетания DNS-правил в 1.14 (legacy-режим DNS — см. [dns.md](dns.md)). Поля нового режима (`ip_version`, `query_type`, `match_response`, `response_*`, действия `evaluate`/`respond`, `race`, `speculative`, `disable_optimistic_cache`, а также rule-set с `query_type`) несовместимы в одном конфиге со старыми адресными полями и со `strategy` в действиях. Всё это ловит `check`:

```
FATAL[0000] initialize dns router: validate dns rule[1]: Response Match Fields (ip_cidr, ip_is_private, ip_accept_any, response_rcode, response_answer, response_ns, response_extra) require match_response to be enabled
FATAL[0000] initialize dns router: Legacy `strategy` DNS rule action option is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, checkout documentation for migration: https://sing-box.sagernet.org/migration/#migrate-dns-rule-action-strategy-to-rule-items
FATAL[0000] initialize dns router: validate dns rule[1]: Legacy Address Filter Fields in DNS rules is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, checkout documentation for migration: https://sing-box.sagernet.org/migration/#migrate-address-filter-fields-to-response-matching
```

Первая строка возникает при `query_type` в одном правиле и `ip_cidr` в другом, вторая — при `query_type` и `strategy`, третья — при `query_type` и `rule_set`, содержащем только `ip_cidr`. `rule_set_ip_cidr_accept_empty` вне legacy-режима по коду тоже даёт ошибку с текстом своей заметки (не прогонялось).

Исходники: option/outbound.go, option/inbound.go, option/direct.go, option/dns.go, option/tun.go, option/tls.go, include/registry.go, protocol/tun/inbound.go, protocol/direct/outbound.go, route/rule/rule_default.go, route/rule/rule_dns.go, experimental/clashapi/server.go, common/tls/ech.go, dns/router.go, dns/transport_dialer.go.

## Принимается молча или падает только при старте

`check` делает `box.New` и закрывает экземпляр, `Start` не вызывается ([cli.md](cli.md)). Поэтому для всего ниже `check` 1.14.2 завершается с кодом 0 (проверено).

Молча принимается, без эффекта или с тихим переносом:

- исходящий `"type": "block"` работает: в 1.11.10 его вернули из устаревших, потому что для него нет замены внутри selector. В 1.14.2 он принимается и в правилах, и в `selector`. В правилах предпочтительнее `"action": "reject"`;
- `route.geoip` и `route.geosite` (объекты с полями `path`, `download_url`, `download_detour`) декодируются и ни на что не влияют;
- tun `endpoint_independent_nat` игнорируется;
- поля настройки Hysteria v1 (`recv_window_conn`, `recv_window`, `recv_window_client`, `max_conn_client`, `disable_mtu_discovery`) переносятся в QUIC-поля, если те не заданы. Предупреждения нет: заметки в коде для них не существует;
- `domain_strategy` в dial-полях при IP-адресе сервера или при заданном `detour` (и без `domain_resolver`) не даёт ни предупреждения, ни эффекта;
- `experimental.cache_file.store_rdrc` без `cache_file.enabled: true` молча не действует, `rdrc_timeout` имеет смысл только вместе со `store_rdrc`;
- `rule_set_ipcidr_match_source` (в правиле маршрутизации и в DNS-правиле) без `rule_set` в том же правиле: ключ разбирается и молча игнорируется, ошибка — только при непустом `rule_set` (проверено);
- поля DNS-правила `server`, `disable_cache`, `rewrite_ttl`, `client_subnet` без `action` и поле `outbound` правила маршрутизации без `action` не устарели на деле: это поля действия по умолчанию `route`, и они работают без сообщений.

Предупреждения, видимые только при запуске (1.14.2):

- `legacy-dns-address-filter` и `legacy-dns-rule-strategy`: DNS-правила с `ip_cidr`/`ip_is_private`/`ip_accept_any` без `match_response` или со `strategy` в действии;
- `legacy-rule-set-download-detour`;
- `implicit-default-http-client`.

Падает только при запуске (по коду):

- listen-поля `proxy_protocol` / `proxy_protocol_accept_no_header` дают ошибку `Proxy Protocol is deprecated and removed in sing-box 1.6.0` при открытии TCP-слушателя;
- удалённый rule-set одновременно с `download_detour` и `http_client` даёт `create rule-set http client: http_client is conflict with deprecated download_detour field`. Проверка происходит в `StartContext` каждого удалённого rule-set, наличие кэша не спасает;
- `detour` на «пустой» `direct` (без собственных dial-настроек) в dial-полях DNS-сервера или `http_client` даёт `detour to an empty direct outbound makes no sense`. В старых DNS-серверах часто стоял `"detour": "direct"`: при переносе это поле надо просто убрать. У старого `download_detour` такой проверки нет (`DisableEmptyDirectCheck`), поэтому буквальный перенос `"download_detour": "direct"` в `"http_client": {"detour": "direct"}` ломает запуск, когда копии набора в `cache.db` нет и он скачивается при старте (с копией ломаются только фоновые обновления: `detour` проверяется при первом соединении через него, `common/dialer/detour.go`). Для прямой загрузки нужен `http_client` без `detour`.

Исходники: include/registry.go, option/route.go, option/tun.go, protocol/hysteria/quic.go, common/dialer/dialer.go, common/dialer/detour.go, common/listener/listener_tcp.go, route/rule/rule_set_remote.go, common/httpclient/client.go, common/httpclient/manager.go, box.go, cmd/sing-box/cmd_check.go.

## Изменения по версиям

### 1.8.0

- Появились rule-set (`route.rule_set`, пункт правил `rule_set`), команды `sing-box geoip`, `geosite`, `rule-set` (в том числе для перевода баз `.db` в rule-set) и вложенные логические правила.
- GeoIP и Geosite объявлены устаревшими и удалены в 1.12: `geoip`, `source_geoip`, `geosite` в правилах маршрутизации и DNS, `route.geoip`, `route.geosite`. `geoip: private` заменён отдельными пунктами `ip_is_private` / `source_ip_is_private`.
- Кэш из Clash API перенесён в `experimental.cache_file` (`enabled`, `path`, `cache_id`, `store_fakeip`). Выбор selector и режим Clash сохраняются автоматически, если `cache_file.enabled`. Старые поля Clash API в 1.14.2 дают ошибку.
- Смысл: внутренние DNS-запросы пропускают DNS-правила с сервером fakeip, а сервер по умолчанию больше не может быть fakeip.
- TUN: удалён стек LWIP (остались `system`, `gvisor`, `mixed`).

Исходники: option/route.go, option/experimental.go, experimental/clashapi/server.go, route/rule/rule_default.go.

### 1.9.0

- `domain_suffix` поменял смысл. Значение без ведущей точки теперь совпадает с самим доменом и его поддоменами (`(domain|.+\.domain)`); раньше это был буквальный суффикс, и `ample.com` совпадал с `example.com`. С ведущей точкой поведение прежнее.
- **Windows:** `process_path` сравнивается с Win32-путём (`C:\folder\program.exe`), а не с путём устройства (`\Device\HarddiskVolumeN\…`). Правила, написанные под путь устройства, перестали совпадать.
- В DNS-правилах появились адресные фильтры `ip_cidr` и `ip_is_private` (в 1.14 они названы Legacy Address Filter Fields и устарели), `client_subnet` и кэш отвергнутых ответов RDRC (в 1.14 `store_rdrc` устарел). В DNS-правила добавлен недостающий `rule_set_ipcidr_match_source`.

### 1.10.0

- Адресные поля TUN объединены (удаление в 1.12): `inet4_address` и `inet6_address` вошли в `address`, `inet4_route_address` и `inet6_route_address` — в `route_address`, `inet4_route_exclude_address` и `inet6_route_exclude_address` — в `route_exclude_address`.
- `rule_set_ipcidr_match_source` переименован в `rule_set_ip_cidr_match_source` в правилах маршрутизации и DNS. Старое имя удалено в 1.11.
- Появился тип rule-set `inline`, и он стал типом по умолчанию: rule-set без `type` считается встроенным.
- Появился `rule_set_ip_cidr_accept_empty` (устарел в 1.14), разрешены висячие запятые в JSON конфига.
- uTLS: часть старых отпечатков chrome удалена, вместо них используется `chrome`.
- Формат rule-set версии 2. Добавлен `auto_redirect` (только Linux).

Исходники: option/tun.go, option/rule.go, option/rule_dns.go, constant/rule.go.

### 1.11.0

- Появились действия правил (`action`): в маршрутизации — `route`, `route-options`, `direct`, `reject`, `hijack-dns`, `sniff`, `resolve`; в DNS — `route`, `route-options`, `reject`. Устарели (удаление в 1.13):
  - специальные исходящие `block` и `dns` (заменяются на `reject` и `hijack-dns`); `block` в 1.11.10 вернули из устаревших, в 1.14.2 он работает;
  - listen-поля `sniff`, `sniff_override_destination`, `sniff_timeout`, `domain_strategy`, `udp_disable_domain_unmapping` (заменяются действиями);
  - `override_address` и `override_port` в исходящем `direct` (заменяются опциями маршрута);
  - исходящий `wireguard` (заменяется конечной точкой `endpoints[]`, `"type": "wireguard"`);
  - tun `gso`: больше не работает, удалён (по коду — в 1.12).
- Поля DNS-правила `server`, `disable_cache`, `rewrite_ttl`, `client_subnet` стали полями действия `route`. Старые DNS-правила продолжают работать.
- Смысл: со стеком `gvisor` при неудачном соединении исходящего клиент получает TCP RST (соединение не устанавливается). У сервера Hysteria2 при заданных `up_mbps`/`down_mbps` `ignore_client_bandwidth` запрещает клиентам BBR. GSO для WireGuard включается автоматически.
- Добавлены `udp_timeout` в опциях маршрута, мультисетевой dial (`network_strategy` и др.), `dns.cache_capacity`, команда `rule-set merge`.

Исходники: option/rule_action.go, option/inbound.go, option/direct.go, include/registry.go, protocol/tun/inbound.go.

### 1.12.0

- DNS-серверы переписаны: новый формат с `type` (`local`, `tcp`, `udp`, `tls`, `https`, `quic`, `h3`, `dhcp`, `fakeip`, `hosts`, `tailscale`, `resolved`), а бывший `rcode://` стал действием `predefined`. Старый формат и `dns.fakeip` устарели и удалены жёстко в 1.14.
- Появились `domain_resolver` (dial-поля) и `route.default_domain_resolver`. Устарели поле DNS-правила `outbound`, работа без резолвера (`missing-domain-resolver`) и `domain_strategy` в dial-полях. Удаление всех трёх было назначено на 1.14.0, поэтому в 1.13.x и 1.14.2 они фатальны по умолчанию.
- ECH переведён на реализацию stdlib: `pq_signature_schemes_enabled` и `dynamic_record_sizing_disabled` устарели и ни на что не влияют, в 1.13 они стали ошибкой. Тег сборки `with_ech` больше не нужен.
- Удалены (ошибка): GeoIP/Geosite, старые адресные поля TUN, tun `gso` (по тексту кода).
- В действиях DNS-правил появились `strategy` и `predefined`. `strategy` снова устарела в 1.14, хотя пример миграции 1.12 («Servers with strategy») переносит `strategy` сервера именно в DNS-правило. Надёжнее использовать `dns.strategy` или `domain_resolver.strategy`.
- Также добавлены фрагментация TLS, раздел `certificate`, AnyTLS, Tailscale, сервисы DERP, resolved, SSM API, поля `bind_interface`, `routing_mark`, `reuse_addr` в listen-полях.

Исходники: option/dns.go, option/outbound.go, option/rule_dns.go, common/dialer/dialer.go, common/tls/ech.go.

### 1.13.0

- Удалены (ошибка) устаревшие возможности 1.11: исходящий `dns`, listen-поля sniff и прочие, переопределение адреса в `direct`, исходящий `wireguard`, старые поля ECH. `block` оставлен.
- Смысл: начальный период TCP keep-alive по умолчанию сокращён с 10 до 5 минут (`TCPKeepAliveInitial`). DNS-сервер `local` на Apple и Linux использует системный резолвер (выключается `prefer_go`); для Windows changelog изменений не называет.
- Добавлен исходящий NaiveProxy. **Windows:** рядом с `sing-box.exe` или в `PATH` нужен `libcronet.dll`.
- **Windows:** начали работать правила `wifi_ssid`/`wifi_bssid` (раньше состояние Wi-Fi было только в графических клиентах).
- Добавлены ICMP-прокси (`network: icmp` в правилах), uTLS 1.8.2 (документация предупреждает против uTLS для обхода цензуры), формат rule-set версии 4. Для сборки нужен Go 1.24 или новее.

Исходники: constant/timeout.go, option/outbound.go, include/registry.go.

### 1.14.0 (1.14.1 и 1.14.2 — только исправления)

- Удалены жёстко старые форматы DNS-серверов и `dns.fakeip`. Остальные три устаревшие возможности 1.12 (DNS-правило `outbound`, работа без резолвера, `domain_strategy` в dial-полях) в коде не удалены: они работают, но фатальны без `ENABLE_DEPRECATED_…`. Пункт changelog «Remove Deprecated Features by agreement»: в коде 1.14.2 следы удаления именно в 1.14 есть только у старых DNS-серверов и `dns.fakeip`.
- Новые устаревшие возможности (удаление в 1.16):
  - `download_detour` удалённого rule-set заменяется на `http_client`;
  - неявный HTTP-клиент заменяется явными `http_clients` и `route.default_http_client`;
  - встроенный `tls.acme` заменяется на `certificate_provider` / `certificate_providers`;
  - `strategy` в DNS-действиях;
  - `rule_set_ip_cidr_accept_empty`;
  - Legacy Address Filter Fields, замена — `evaluate` + `match_response`;
  - `independent_cache`: поле достаточно удалить, кэш теперь всегда разделён по транспорту;
  - `store_rdrc` заменяется на `store_dns`;
  - поля Hysteria v1 заменяются QUIC-полями (без заметки в коде).
- Изменения смысла:
  - `ip_version` и `query_type` в DNS-правилах (и `query_type` в подключённых rule-set) теперь действуют и на внутренние разрешения имён без явного сервера (например, действие `resolve` без `server`). Раньше там они молча игнорировались. Смешивать их со старыми DNS-полями нельзя, это ошибка (сообщения выше).
  - DNS-правило со ссылкой на rule-set, где есть только `ip_cidr`, без `match_response` отвергается, если legacy-режим DNS выключен (проверено).
  - Сопоставление rule-set исправлено. «Слияние» полей rule-set с полями ссылающегося правила теперь только для rule-set из ровно одного правила `default` без `invert`. Любой другой rule-set совпадает как отдельный пункт: достаточно совпадения любого из его правил.
  - **Windows:** TUN `dns_mode` (с 1.14; `disabled` / `native` / `hijack`, по умолчанию `hijack`) теперь задаёт DNS на уровне интерфейса, а при `strict_route` ставит фильтры WFP для перехвата DNS. До 1.14 DNS интерфейса и брандмауэр не трогались. Подробно — в [inbounds.md](inbounds.md).
  - Клиент Hysteria2 по умолчанию имитирует QUIC-рукопожатие Chrome. Серверы с сертификатом Ed25519 перестают соединяться, помогает `disable_chrome_parrot: true` (с 1.14).
  - DNS-сервер `local` на платформах, кроме Apple (в том числе на Windows), отправляет запросы к `*.local.` и link-local обратным зонам через mDNS.
  - `tag` rule-set может быть списком (с подстановкой `{tag}`), появился `initial_path`; `format` сохраняет комментарии. Формат rule-set версии 5, для сборки нужен Go 1.25 или новее.
- **Windows**, новое: TLS-движок `windows` (Schannel, сборка 17763+), исходящий `bridge` через WinDivert, TLS spoof (нужны права администратора, ARM64 не поддерживается).

Исходники: option/dns.go, dns/router.go, experimental/deprecated/constants.go, option/rule_set.go, option/tls.go, option/hysteria.go, option/hysteria2.go, protocol/hysteria2/outbound.go, option/tun.go.

### 1.15.0-alpha (прогноз, не проверено)

Исходников 1.15 здесь нет. Выводы сделаны из механизма устаревания 1.14.2:

- В 1.15.x все заметки с удалением в 1.16.0 станут надвигающимися, то есть ERROR + FATAL без `ENABLE_DEPRECATED_…`. Четыре из них сообщаются только в `Start` (`LEGACY_DNS_ADDRESS_FILTER`, `LEGACY_DNS_RULE_STRATEGY`, `LEGACY_RULE_SET_DOWNLOAD_DETOUR`, `IMPLICIT_DEFAULT_HTTP_CLIENT`). Если это не изменят, `check` пройдёт, а `run` завершится сразу после запуска.
- Заметки с удалением в 1.14.0 не могут остаться в стабильном 1.15.0: `Impending` там паникует. Следует ждать жёсткого удаления DNS-правила `outbound`, работы без резолвера и `domain_strategy` в dial-полях.
- Для полей Hysteria v1 заметки нет. Их удаление в 1.16, вероятно, проявится как `unknown field`.

## Устаревшие поля по типам

Все поля с пометкой `schema:"omit"` в `option/*.go` версии 1.14.2, а также удалённые типы и старый формат DNS-сервера. Актуальные поля тех же структур описаны в файлах, указанных в заголовках. Во всех таблицах `DomainStrategy` — строка: `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` (пустая строка означает «как есть»).

### Listen-поля входящих (ListenOptions, см. shared.md)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `sniff` | bool | false | Устарело в 1.11, удалено в 1.13: ошибка декодирования. Замена — правило `{"inbound": "<tag>", "action": "sniff"}` раньше остальных |
| `sniff_override_destination` | bool | false | То же. Прямой замены нет: действие `sniff` адрес назначения не подменяет (внутренний флаг `OverrideDestination` в 1.14.2 ничем не выставляется) |
| `sniff_timeout` | duration | — | То же. Замена — `timeout` действия `sniff` (по умолчанию 300ms) |
| `domain_strategy` | string (DomainStrategy) | "" | То же. Замена — действие `resolve` со `strategy` |
| `udp_disable_domain_unmapping` | bool | false | То же. Замена — `udp_disable_domain_unmapping` в действии `route` / `route-options` |
| `proxy_protocol` | bool | false | Удалено в 1.6. Ошибка только при старте TCP-слушателя, `check` её не видит |
| `proxy_protocol_accept_no_header` | bool | false | То же |

### TUN (TunInboundOptions, см. inbounds.md)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `inet4_address` | string\|[string] (IPv4-префикс) | — | Устарело в 1.10, удалено в 1.12: ошибка при создании. Замена `address` (с 1.10) |
| `inet6_address` | string\|[string] (IPv6-префикс) | — | То же, замена `address` |
| `inet4_route_address` | string\|[string] (префикс) | — | То же, замена `route_address` (с 1.10) |
| `inet6_route_address` | string\|[string] (префикс) | — | То же, замена `route_address` |
| `inet4_route_exclude_address` | string\|[string] (префикс) | — | То же, замена `route_exclude_address` (с 1.10) |
| `inet6_route_exclude_address` | string\|[string] (префикс) | — | То же, замена `route_exclude_address` |
| `gso` | bool | false | Устарело в 1.11, по коду удалено в 1.12. `true` даёт ошибку при создании. Удалить |
| `endpoint_independent_nat` | bool | false | Не действует с 1.11, молча принимается. С 1.14 для этого есть `udp_mapping` / `udp_filtering` |
| `sniff`, `sniff_override_destination`, `sniff_timeout`, `domain_strategy`, `udp_disable_domain_unmapping` | как в listen-полях | — | Встроены в tun напрямую. Ошибка при создании (`initialize inbound[N]`), а не при декодировании |

### Dial-поля (DialerOptions, см. shared.md)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `domain_strategy` | string (DomainStrategy) | "" | Устарело в 1.12, удаление назначено на 1.14. ERROR + FATAL (`LEGACY_DOMAIN_STRATEGY_OPTIONS`), только если адрес сервера — домен и у исходящего нет `detour` (или есть `domain_resolver` без своей `strategy`). Иначе молча не действует. Замена — `domain_resolver: {"server": "<dns-tag>", "strategy": "…"}` (с 1.12) |
| отсутствие `domain_resolver` | tag → DNS-сервер | — | При двух и более DNS-серверах, без `route.default_domain_resolver`, при домене в адресе назначения и без `detour` — ERROR + FATAL (`MISSING_DOMAIN_RESOLVER`). `direct` всегда считается доменом. Замена — `route.default_domain_resolver` (с 1.12) или `domain_resolver` у исходящего |

### Исходящий direct (см. outbounds.md)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `override_address` | string | — | Устарело в 1.11, удалено в 1.13: ошибка декодирования. Замена — `override_address` в действии `route` / `route-options` |
| `override_port` | int | 0 | То же, замена — `override_port` там же |
| `proxy_protocol` | int (0–255) | 0 | Удалено в 1.6. Ненулевое значение даёт ошибку при создании |

### Удалённые и сохранённые типы входящих и исходящих

| Тип | Статус в 1.14.2 | Замена и детали |
|---|---|---|
| исходящий `dns` | удалён в 1.13, ошибка декодирования | правило `{"protocol": "dns", "action": "hijack-dns"}` после `{"action": "sniff"}` |
| исходящий `block` | **работает** (снова не устаревший с 1.11.10) | в правилах — `"action": "reject"`; в selector замены нет |
| исходящий `wireguard` | удалён в 1.13; ошибка при создании или `unknown field` | `endpoints[]` с `"type": "wireguard"`, соответствие полей — в [таблице миграции](#таблица-миграции-было--стало) |
| входящий и исходящий `shadowsocksr` | удалён в 1.6; ошибка при создании | замены нет. Поля заглушки исходящего всё ещё декодируются: dial-поля, `server`, `server_port`, `method`, `password`, `obfs`, `obfs_param`, `protocol`, `protocol_param`, `network`; входящий декодируется как shadowsocks |

### Hysteria v1 (см. inbounds.md, outbounds.md)

Поля устарели в 1.14, удаление по changelog — в 1.16. Предупреждения нет. Старое значение используется, только если соответствующее QUIC-поле не задано. Соответствие ниже взято из кода и расходится с документацией, см. [Расхождения](#расхождения-документации-и-кода).

| Поле | Где | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|---|
| `recv_window_conn` | входящий | int (байты) | — | подставляется в `connection_receive_window` |
| `recv_window_client` | входящий | int (байты) | — | подставляется в `stream_receive_window` |
| `max_conn_client` | входящий | int | — | подставляется в `max_concurrent_streams` |
| `disable_mtu_discovery` | входящий | bool | false | подставляется в `disable_path_mtu_discovery` |
| `recv_window_conn` | исходящий | int (байты) | — | подставляется в `connection_receive_window` |
| `recv_window` | исходящий | int (байты) | — | подставляется в `stream_receive_window` |
| `disable_mtu_discovery` | исходящий | bool | false | подставляется в `disable_path_mtu_discovery` |

### TLS (см. shared.md)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `acme` (входящий TLS) | object | — | Устарело в 1.14, удаление в 1.16. При непустом `domain` — WARN `INLINE_ACME_OPTIONS`. Вместе с `certificate_provider` даёт ошибку `certificate_provider and acme are mutually exclusive`. Замена — `certificate_provider` (с 1.14): объект с `"type": "acme"` или тег из `certificate_providers[]`. Большинство полей переносится без изменений. Серверная функция, клиенту tray-sing-box не нужна |
| `acme.domain` | string\|[string] | — | домены сертификата; пустой список — ACME не запускается |
| `acme.data_directory` | string | хранилище certmagic по умолчанию | каталог данных (`$VAR` раскрываются) |
| `acme.default_server_name` | string | — | имя для ClientHello без SNI |
| `acme.email` | string | — | почта учётной записи |
| `acme.provider` | string | `letsencrypt` | `letsencrypt`, `zerossl` или URL `https://…`; другое — ошибка |
| `acme.disable_http_challenge` | bool | false | отключить HTTP-01 |
| `acme.disable_tls_alpn_challenge` | bool | false | отключить TLS-ALPN-01 |
| `acme.alternative_http_port` | int | `0` (порт 80) | другой порт для HTTP-01 |
| `acme.alternative_tls_port` | int | `0` (порт 443) | другой порт для TLS-ALPN-01 |
| `acme.external_account` | object `{key_id, mac_key}` | — | EAB |
| `acme.dns01_challenge` | object | — | DNS-01 (`provider`: `alidns`, `cloudflare`, `acmedns`), см. [shared.md](shared.md) |
| `acme.profile` | string | — | с 1.14; профиль ACME (для IP-сертификатов Let's Encrypt подставляется `shortlived`) |
| `ech.pq_signature_schemes_enabled` | bool | false | Входящий и исходящий. Устарело в 1.12, удалено в 1.13. `true` даёт ошибку при создании |
| `ech.dynamic_record_sizing_disabled` | bool | false | То же |

### DNS (см. dns.md)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `dns.fakeip` | object `{enabled, inet4_range, inet6_range}` | — | Устарело в 1.12, удалено в 1.14: любое значение даёт ошибку декодирования. Замена — сервер `{"type": "fakeip", "inet4_range": …, "inet6_range": …}` |
| `dns.independent_cache` | bool | false | Устарело в 1.14, удаление в 1.16, WARN. Удалить |
| `dns.servers[]` старого формата | object | — | Нет `type` или `"type": "legacy"` — ошибка декодирования (1.12 → 1.14). Поля старого формата: `tag`, `address` (`local`, `tcp://`, `udp://` или IP, `tls://`, `https://…/dns-query`, `quic://`, `h3://…`, `rcode://…`, `dhcp://auto` / `dhcp://<iface>`, `fakeip`), `address_resolver`, `address_strategy`, `strategy`, `detour`, `client_subnet`. В сервере нового формата любое из них, кроме `tag` и `detour`, даёт `unknown field` |

### DNS-правила и действия (см. dns.md)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `outbound` | string\|[string] (tag → outbound или `any`) | — | Устарело в 1.12, удаление назначено на 1.14: ERROR + FATAL (`OUTBOUND_DNS_RULE_ITEM`). Замена — `domain_resolver` / `route.default_domain_resolver` |
| `geosite` | string\|[string] | — | Удалено в 1.12: ошибка при создании. Замена — `rule_set` |
| `geoip` | string\|[string] | — | То же |
| `source_geoip` | string\|[string] | — | То же |
| `rule_set_ipcidr_match_source` | bool | false | Удалено в 1.11: ошибка при непустом `rule_set` в правиле, без него молча игнорируется. Замена — `rule_set_ip_cidr_match_source` |
| `rule_set_ip_cidr_accept_empty` | bool | false | Устарело в 1.14, удаление в 1.16. В legacy-режиме — WARN при создании, иначе ошибка. Замена — `evaluate` + `match_response` |
| `ip_cidr`, `ip_is_private`, `ip_accept_any` без `match_response` | string\|[string] / bool / bool | — | Legacy Address Filter Fields. Сами поля остаются (с `match_response` это поля ответа), устарело их использование без `match_response`: WARN при старте, ошибка в сочетании с полями нового режима. Замена — `{"action": "evaluate", …}` и затем правило с `"match_response": true` |
| `strategy` в действиях `route`, `evaluate`, `route-options` | string (DomainStrategy) | "" | Устарело в 1.14, удаление в 1.16: WARN при старте, ошибка в сочетании с полями нового режима. Замена — `dns.strategy` или `domain_resolver.strategy`; раздела миграции в документации нет |

### Маршрутизация и rule-set (см. route.md)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `route.geoip` | object | — | Молча принимается, не действует. Поля: `path` (string), `download_url` (string), `download_detour` (tag → outbound). Удалить |
| `route.geosite` | object | — | То же, те же три поля |
| `route.rules[].geoip` | string\|[string] | — | Удалено в 1.12: ошибка при создании |
| `route.rules[].source_geoip` | string\|[string] | — | То же |
| `route.rules[].geosite` | string\|[string] | — | То же |
| `route.rules[].rule_set_ipcidr_match_source` | bool | false | Удалено в 1.11: ошибка при непустом `rule_set` в правиле, без него молча игнорируется. Замена — `rule_set_ip_cidr_match_source` (с 1.10) |
| `route.rule_set[].download_detour` (remote) | tag → outbound | — | Устарело в 1.14, удаление в 1.16: WARN при старте. Вместе с `http_client` — ошибка при старте. Замена — `http_client` (с 1.14): объект или тег из `http_clients[]` |

### experimental (см. experimental.md)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `cache_file.store_rdrc` | bool | false | Устарело в 1.14, удаление в 1.16: WARN, только при `cache_file.enabled`. Замена — `store_dns` (с 1.14) |
| `cache_file.rdrc_timeout` | duration | 168h (7 дней) | Не помечено устаревшим, но действует только со `store_rdrc` |
| `clash_api.cache_file` | string | — | Ошибка с 1.8. Замена — `cache_file.enabled` + `cache_file.path` |
| `clash_api.cache_id` | string | — | То же, замена — `cache_file.cache_id` |
| `clash_api.store_mode` | bool | false | То же. С `cache_file.enabled` сохраняется автоматически |
| `clash_api.store_selected` | bool | false | То же, автоматически |
| `clash_api.store_fakeip` | bool | false | То же, замена — `cache_file.store_fakeip` |

Исходники: option/inbound.go, option/tun.go, option/outbound.go, option/direct.go, option/shadowsocksr.go, option/hysteria.go, option/tls.go, option/tls_acme.go, option/dns.go, option/rule_dns.go, option/rule_action.go, option/route.go, option/rule.go, option/rule_set.go, option/experimental.go, option/http.go, protocol/hysteria/quic.go, common/tls/acme.go, route/rule/rule_action.go.

## Таблица миграции «было → стало»

| Было | Стало | С версии |
|---|---|---|
| исходящий `block` + правило `"outbound": "block"` | правило `"action": "reject"` (сам `block` работает) | 1.11 |
| исходящий `dns` + правило `{"protocol": "dns", "outbound": "dns-out"}` | `{"action": "sniff"}`, затем `{"protocol": "dns", "action": "hijack-dns"}` | 1.11 |
| входящий `"sniff": true` | правило `{"inbound": "<tag>", "action": "sniff"}` в начале `route.rules` | 1.11 |
| входящий `sniff_timeout` | `timeout` в действии `sniff` | 1.11 |
| входящий `domain_strategy` | `{"inbound": "<tag>", "action": "resolve", "strategy": "…"}` | 1.11 |
| входящий `udp_disable_domain_unmapping` | то же поле в `route` / `route-options` | 1.11 |
| входящий `sniff_override_destination` | прямой замены нет | — |
| direct `override_address` / `override_port` | `{"action": "route-options", "override_address": …, "override_port": …}` (или в `route`) | 1.11 |
| исходящий `wireguard`: `server`, `server_port`, `local_address`, `private_key`, `peer_public_key`, `pre_shared_key`, `reserved`, `mtu`, `system_interface`, `interface_name`, `gso` | `endpoints[]` `"type": "wireguard"`: `peers[].address`, `peers[].port`, `address`, `private_key`, `peers[].public_key`, `peers[].pre_shared_key`, `peers[].reserved`, `mtu`, `system`, `name`; `gso` удалить; `peers[].allowed_ips` указать явно (например `0.0.0.0/0`, `::/0`) | 1.11 |
| tun `inet4_address` / `inet6_address` | `address` | 1.10 |
| tun `inet4_route_address` / `inet6_route_address` | `route_address` | 1.10 |
| tun `inet4_route_exclude_address` / `inet6_route_exclude_address` | `route_exclude_address` | 1.10 |
| tun `gso` | удалить | 1.11 |
| tun `endpoint_independent_nat` | удалить; при необходимости `udp_mapping` / `udp_filtering` | 1.14 |
| `"geoip": "private"` | `"ip_is_private": true` | 1.8 |
| `"geoip": "cn"` | `"rule_set": "geoip-cn"` + удалённый rule-set (`.srs`) | 1.8 |
| `"source_geoip": …` | `rule_set` + `"rule_set_ip_cidr_match_source": true` | 1.10 |
| `"geosite": …` | `rule_set` | 1.8 |
| `route.geoip` / `route.geosite` | удалить; для кэша rule-set — `experimental.cache_file.enabled: true` | 1.8 |
| `rule_set_ipcidr_match_source` | `rule_set_ip_cidr_match_source` | 1.10 |
| DNS `"address": "local"` | `"type": "local"` | 1.12 |
| `"address": "1.1.1.1"` или `udp://…` | `"type": "udp", "server": "1.1.1.1"` | 1.12 |
| `tcp://`, `tls://`, `quic://` | `"type": "tcp"` / `"tls"` / `"quic"` + `server` | 1.12 |
| `https://host/dns-query`, `h3://host/dns-query` | `"type": "https"` / `"h3"`, `"server": "host"` (путь по умолчанию `/dns-query`) | 1.12 |
| `dhcp://auto`, `dhcp://en0` | `"type": "dhcp"` (+ `"interface": "en0"`) | 1.12 |
| `"address": "fakeip"` + `dns.fakeip` | `"type": "fakeip"` с `inet4_range` / `inet6_range` в самом сервере | 1.12 |
| `rcode://refused` | DNS-правило `"action": "predefined", "rcode": "REFUSED"` | 1.12 |
| `address_resolver` | `domain_resolver`: обязателен, если `server` — домен и нет `detour` | 1.12 |
| `address_strategy` | `domain_resolver.strategy` | 1.12 |
| `strategy` сервера | `dns.strategy` (глобально); `strategy` DNS-правила устарела в 1.14 | 1.12 |
| `client_subnet` сервера | `client_subnet` действия DNS-правила или `dns.client_subnet` | 1.12 |
| `"detour": "direct"` у DNS-сервера (пустой direct) | удалить поле: `detour` на пустой direct — ошибка при старте | 1.12 |
| DNS-правило `{"outbound": "any", "server": "local"}` | `route.default_domain_resolver: "local"` или `domain_resolver` у исходящих | 1.12 |
| dial `domain_strategy` | `domain_resolver: {"server": …, "strategy": …}` | 1.12 |
| (ничего) при двух и более DNS-серверах | `route.default_domain_resolver` | 1.12 |
| DNS-правило `ip_cidr` / `ip_is_private` без `match_response` | `{"action": "evaluate", "server": …}`, затем `{"match_response": true, "ip_cidr": …, "action": "route", "server": …}` | 1.14 |
| `rule_set_ip_cidr_accept_empty` | `evaluate` + `match_response` | 1.14 |
| `strategy` в DNS-правиле | `dns.strategy` / `domain_resolver.strategy` | 1.14 |
| `dns.independent_cache` | удалить | 1.14 |
| `cache_file.store_rdrc` | `cache_file.store_dns` | 1.14 |
| `"download_detour": "proxy"` | `"http_client": {"detour": "proxy"}` или тег из `http_clients[]`; для прямой загрузки — `http_client` без `detour` | 1.14 |
| неявный клиент загрузки rule-set | `http_clients: [{"tag": …, …}]` + `route.default_http_client` (без него берётся первый из `http_clients`) | 1.14 |
| `tls.acme {…}` | `tls.certificate_provider {"type": "acme", …}` или `certificate_providers[]` + тег | 1.14 |
| clash_api `cache_file` / `cache_id` / `store_*` | `experimental.cache_file {enabled, path, cache_id, store_fakeip}` | 1.8 |
| ECH `pq_signature_schemes_enabled`, `dynamic_record_sizing_disabled` | удалить | 1.12 |
| Hysteria v1 `recv_window*`, `max_conn_client`, `disable_mtu_discovery` | QUIC-поля (`stream_receive_window`, `connection_receive_window`, `max_concurrent_streams`, `disable_path_mtu_discovery`) | 1.14 |

## Пример: конфиг времён 1.10 под 1.14.2

Исходный конфиг (сокращён): DNS-серверы старого формата, `"detour": "direct"` у локального сервера, DNS-правило `{"outbound": "any", "server": "local"}`, tun с `inet4_address` и `"sniff": true`, VLESS с доменом и `"domain_strategy": "prefer_ipv4"`, исходящие `direct`, `block`, `dns`, правила `{"protocol": "dns", "outbound": "dns-out"}` и `{"geoip": "private", "outbound": "direct"}`.

`check` сообщает об ошибках по одной, поэтому исправлять приходится по кругу. В этом примере порядок был таким:

1. `decode config at …: dns.servers[0]: legacy DNS server formats are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, …`. Исправление: серверы переведены в `"type": "tls"` и `"type": "udp"`, у `local` убран `"detour": "direct"`. Заодно удалены исходящий `dns` и правило `dns-out`.
2. `initialize router: parse rule[0]: geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0`. Исправление: `"ip_is_private": true`.
3. `ERROR … outbound DNS rule item …` + `FATAL … ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true`. Исправление: правило удалено.
4. `initialize inbound[0]: legacy tun address fields are deprecated …`. Исправление: `address`.
5. `initialize inbound[0]: legacy inbound fields are deprecated …`. Исправление: `sniff` убран из tun.
6. ERROR `missing route.default_domain_resolver or domain_resolver in dial fields …` + `FATAL … ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true` (в оригинале имена полей в обратных кавычках). Та же ошибка остаётся и после удаления `domain_strategy`, потому что её вызывает и `direct`. Исправление: `"route": {"default_domain_resolver": "local"}` и `"domain_resolver": {"server": "local", "strategy": "prefer_ipv4"}` у VLESS, правила `{"action": "sniff"}` и `{"protocol": "dns", "action": "hijack-dns"}`.
7. `check` завершается с кодом 0. `block` можно было оставить.

Наблюдаемый порядок: сначала ошибки декодирования (по порядку ключей в JSON), затем создание компонентов (правила маршрутизации, DNS-правила, входящие, исходящие). Порядок не документирован и может меняться.

## Что проверить перед обновлением sing-box

### Что ловит `check` новой версии

- неизвестные поля, включая наполовину переведённые DNS-серверы, поля заглушки `wireguard` и поля `address_resolver` / `address_strategy`;
- все жёстко удалённые возможности из [таблицы](#жёстко-удалённые-возможности-сообщения-1142), кроме listen-поля `proxy_protocol` (и `rule_set_ipcidr_match_source` в правиле без `rule_set` — он молча игнорируется);
- фатальные заметки с удалением в 1.14.0 (`OUTBOUND_DNS_RULE_ITEM`, `MISSING_DOMAIN_RESOLVER`, `LEGACY_DOMAIN_STRATEGY_OPTIONS`), если переменные не заданы;
- несовместимые сочетания старых и новых DNS-полей;
- DNS-сервер нового формата с доменом без `domain_resolver`;
- WARN-заметки `independent_cache`, `store_rdrc` (при `cache_file.enabled`), `rule_set_ip_cidr_accept_empty` и `tls.acme`.

### Чего `check` не ловит

- WARN-заметки, которые сообщаются только при старте: старые адресные поля DNS, `strategy` в DNS-правиле, `download_detour`, неявный HTTP-клиент. В 1.15 они, вероятно, станут фатальными, но только при старте;
- listen-поля `proxy_protocol` / `proxy_protocol_accept_no_header`;
- `download_detour` вместе с `http_client`;
- `detour` на пустой `direct` у DNS-сервера или `http_client`;
- молча игнорируемые пережитки (`route.geoip`/`route.geosite`, `endpoint_independent_nat`, `domain_strategy` при `detour` или IP-адресе сервера, поля Hysteria v1) и изменения смысла: `domain_suffix` и `process_path` (1.9), сопоставление rule-set, `ip_version`/`query_type`, `dns_mode` TUN и имитация Chrome в Hysteria2 (1.14).

### Порядок действий

1. Скачать новый бинарник, ничего не заменяя, и выполнить `<новый sing-box> check -c config.json` в каталоге данных: относительные пути в конфиге разрешаются от рабочего каталога. Сначала без `ENABLE_DEPRECATED_*`, чтобы увидеть все надвигающиеся заметки, затем с тем окружением, в котором sing-box будет работать.
2. Исправлять и повторять `check`, пока код выхода не станет 0: ошибки выводятся по одной.
3. Прочитать строки WARN. Это то, что станет фатальным через одну минорную версию.
4. Поискать в конфиге ключи из списков «не ловит» (без учёта регистра): `proxy_protocol`; `download_detour` рядом с `http_client`; `"detour": "direct"` у DNS-серверов и `http_client`; `ip_cidr` / `ip_is_private` / `ip_accept_any` и `strategy` в `dns.rules` без `match_response`; удалённые rule-set без `http_clients`.
5. Для узлов Hysteria2 с сертификатом Ed25519 добавить `disable_chrome_parrot: true`.
6. **Windows:** при tun учесть, что с 1.14 по умолчанию `dns_mode: hijack` меняет DNS интерфейса, а при `strict_route` ставит фильтры WFP. Правила с `process_path` писать в Win32-форме.
7. Если после замены sing-box не стартует, вернуть прежний бинарник (`.old`) и разобрать строку FATAL.

### Для tray-sing-box

- Обновление в приложении (`domain.UpdateService` → `updater`) проверяет, что скачанный бинарник запускается и сообщает ожидаемую версию, а затем (с коммита `aeb1a7c`) запускает им `check` текущего config.json с тем же окружением (`process.SingBoxEnv`) и рабочим каталогом данных, до остановки VPN. Если новая версия конфиг отвергает, а установленная принимает, обновление отменяется с сообщением sing-box, загрузка удаляется. Если конфиг отвергают обе версии, обновление идёт, только когда VPN и так не работает. Новая версия, которая установилась, но не запустилась, откатывается на `.old` (вместе с библиотеками), и запускается прежняя; намерение пользователя не меняется. Чего это не ловит: всё, что `check` не видит (раздел выше), — WARN-заметки, видимые только при старте, `download_detour` вместе с `http_client`, `detour` на пустой `direct`. Откат срабатывает, только если `Start` процесса вернул ошибку в пределах `StartGraceMs` (1,5 с); падение позже — дело монитора перезапусков, а строка FATAL окажется в `sing-box-console.log`.
- `process.SingBoxEnv` передаёт sing-box переменные `ENABLE_DEPRECATED_*` из окружения приложения (имя приводится к верхнему регистру, значение к `true`/`false`). Поэтому переключатель пользователя действует и на `check` страницы настроек, и на VPN. Он лишь снимает FATAL: предупреждение продолжает попадать в stderr, то есть в `sing-box-console.log`, а не в файл `log.output`.

Исходники (проекта): internal/domain/update_service.go, internal/infrastructure/updater/updater.go, internal/infrastructure/process/env_windows.go.

## Расхождения документации и кода

Во всех случаях верным считается код 1.14.2.

1. `docs/deprecated.md` пишет, что GSO в TUN удалён в 1.13.0, а сообщение кода — «removed in sing-box 1.12.0». В 1.14.2 это ошибка в обоих случаях.
2. `docs/configuration/dns/index.md` обещает удалить `independent_cache` в 1.14.0, а заметка в коде и `deprecated.md` называют 1.16.0.
3. Hysteria v1: документация сопоставляет `recv_window_conn` со `stream_receive_window`, а `recv_window` / `recv_window_client` с `connection_receive_window`. Код (`protocol/hysteria/quic.go`) делает наоборот. Заметки устаревания для этих полей в коде нет, и `deprecated.md` их не упоминает: об устаревании говорят только changelog и страницы полей.
4. Ссылки на миграцию в заметках кода ведут на несуществующие якоря. `#migrate-domain-strategy-options`: раздел называется «Migrate outbound domain strategy option to domain resolver». `#migrate-dns-rule-action-strategy-to-rule-items`: такого раздела нет вообще. Changelog 1.11 ссылается на отсутствующий `#migrate-legacy-dns-route-options-to-rule-actions`.
5. Документация (`dns/rule.md`, `shared/dial.md`) говорит, что DNS-правило `outbound` и dial `domain_strategy` удаляются в 1.14.0, а changelog 1.14.0 — «Remove Deprecated Features». На деле в 1.14.2 удалены только старые DNS-серверы и `dns.fakeip`. Три возможности 1.12 работают, но фатальны без `ENABLE_DEPRECATED_*`.
6. `deprecated.md` относит к Legacy Address Filter Fields только `ip_cidr` и `ip_is_private`. Код добавляет к ним `ip_accept_any` (`defaultRuleNeedsLegacyDNSModeFromAddressFilter`).
7. Комментарий в `option/rule_dns.go` утверждает, что `rule_set_ip_cidr_accept_empty` «removed in sing-box 1.11.0». На деле поле устарело в 1.14 и работает.
8. `dns/rule.md` помечает `server`, `disable_cache`, `rewrite_ttl`, `client_subnet` как «Deprecated in sing-box 1.11.0». Это просто поля действия по умолчанию `route`: changelog 1.11 прямо снимает с них статус устаревших, код принимает их без сообщений.
9. Пример миграции 1.12 «Servers with strategy» переносит `strategy` в DNS-правило, которое сам sing-box 1.14 объявляет устаревшим.
10. Переменные `ENABLE_DEPRECATED_*` нигде в `docs/` не описаны.
11. Страницы `outbound/dns.md`, `outbound/wireguard.md`, `outbound/direct.md`, `shared/listen.md`, `inbound/tun.md`, `dns/rule.md` до сих пор пишут «will be removed in 1.12.0/1.13.0» в будущем времени, хотя удаление уже произошло.
12. В `experimental/clash-api.md` раздел `store_fakeip` называет поле `store_selected`.
13. Для `sniff_override_destination` документация не даёт замены, и в коде её нет.

Неясно или не проверялось:

- имена переключателей 1.11–1.12;
- с какой версии `detour` на пустой `direct` стал ошибкой;
- поведение 1.15 (раздел выше — прогноз по механизму 1.14.2);
- все проверки «только при старте» не запускались (`run` и сеть запрещены): они выведены из кода (WARN `tls.acme` проверен — он виден уже на `check`);
- конфиг с двумя DNS-серверами без `outbounds` проходит `check`, а при запуске не проверялся (по коду — та же фатальная заметка).

Исходники: docs/deprecated.md, docs/migration.md, docs/changelog.md, docs/configuration/dns/index.md, docs/configuration/dns/rule.md, docs/configuration/inbound/hysteria.md, docs/configuration/outbound/hysteria.md, docs/configuration/experimental/clash-api.md, protocol/hysteria/quic.go, experimental/deprecated/constants.go, dns/router.go, option/rule_dns.go.
