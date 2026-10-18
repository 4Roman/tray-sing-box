# Конфигурация sing-box 1.14.2: файл, верхний уровень и жизненный цикл

Справочник по конфигу sing-box **1.14.2** как целому: ключи верхнего уровня, правила разбора JSON (строгость, регистр ключей, числа, списки, длительности), пространства имён тегов, малые секции верхнего уровня (`log`, `ntp`, `certificate`, `certificate_providers`, `http_clients`, `network_namespaces`) и жизненный цикл экземпляра: что проверяет `box.New` (а значит, `sing-box check`), что всплывает только при старте и что ломает лишь отдельные соединения.

Сверено с исходниками v1.14.2 (ревизия `af6e64c`) и библиотекой `github.com/sagernet/sing` той версии, что указана в `go.mod` (`v0.9.6-0.20260922013354-87c33f17688f`: JSON-декодер, `badoption`, NTP). Помеченное «проверено» запускалось через `sing-box check` / `sing-box format` на официальной сборке `sing-box-1.14.2-windows-amd64`. Где документация расходится с кодом, прав код; расхождения собраны в конце.

Смежные файлы: команды и загрузка файлов (`-c`, `-C`, `-D`, слияние, комментарии, `$schema`) — [cli.md](cli.md); поля подключения, TLS, HTTP/2 и QUIC — [shared.md](shared.md); `dns` — [dns.md](dns.md); `route` (включая `default_http_client`, `default_domain_resolver`, rule-set) — [route.md](route.md); `inbounds` — [inbounds.md](inbounds.md); `outbounds` и `endpoints` — [outbounds.md](outbounds.md); `experimental` и `services` — [experimental.md](experimental.md); поля поставщиков сертификатов (`certificate_providers`, `tls.certificate_provider`) — [shared.md](shared.md#провайдеры-сертификатов-certificate_provider); устаревшее и переменные `ENABLE_DEPRECATED_*` — [deprecations.md](deprecations.md).

Обозначения типов: `string`, `int`, `bool`, `object`, `[object]`; `string|[string]` — поле `badoption.Listable` (одно значение или массив); `duration` — строка длительности (см. [Длительности](#длительности-duration)); `size` — объём памяти: число байт или строка вида `"8 MB"` ([shared.md](shared.md#условные-обозначения)); `-> outbound`, `-> dns server`, `-> http_client` и т. п. — строка-тег, ссылка на элемент другого списка. «check» — `sing-box check`.

## Верхний уровень конфига

Корень конфига — объект со строгим набором ключей: любой другой ключ — ошибка разбора (`json: unknown field`). Все ключи необязательны; пустой объект `{}` проходит check (проверено), а при запуске sing-box сам добавит исходящий `direct` и DNS-сервер `local` (по коду, см. [Объекты по умолчанию](#объекты-по-умолчанию)).

| Ключ | Тип | С версии | Назначение | Где описано |
|---|---|---|---|---|
| `$schema` | string | 1.14 | URI JSON Schema для редактора, на работу не влияет. Не строка (например, число) — ошибка разбора | [cli.md](cli.md#ключ-schema-и-команда-schema) |
| `log` | object | — | журнал сервиса | [log](#log) |
| `dns` | object | — | DNS-серверы, DNS-правила, FakeIP | [dns.md](dns.md) |
| `ntp` | object | — | встроенный NTP-клиент | [ntp](#ntp) |
| `certificate` | object | 1.12 | доверенные корневые сертификаты для всего экземпляра | [certificate](#certificate) |
| `certificate_providers` | [object] | 1.14 | общие поставщики серверных сертификатов (ACME и др.) | [certificate_providers](#certificate_providers), поля — [shared.md](shared.md#провайдеры-сертификатов-certificate_provider) |
| `http_clients` | [object] | 1.14 | общие HTTP-клиенты для собственных запросов sing-box | [http_clients](#http_clients) |
| `network_namespaces` | [object] | 1.14 | сетевые пространства имён Linux | [network_namespaces](#network_namespaces) |
| `endpoints` | [object] | 1.11 | эндпоинты (wireguard, tailscale, openvpn, openconnect): одновременно входящие и исходящие | [outbounds.md](outbounds.md), [inbounds.md](inbounds.md) |
| `inbounds` | [object] | — | входящие | [inbounds.md](inbounds.md) |
| `outbounds` | [object] | — | исходящие и группы | [outbounds.md](outbounds.md) |
| `route` | object | — | маршрутизация, rule-set, умолчания для dial | [route.md](route.md) |
| `services` | [object] | 1.12 | службы (api, derp, resolved, ssm-api и др.) | [experimental.md](experimental.md#раздел-services) |
| `experimental` | object | — | cache_file, clash_api, v2ray_api, debug | [experimental.md](experimental.md) |

Порядок ключей в файле ни на что не влияет. Порядок элементов внутри списков влияет: теги по умолчанию берутся из позиции, первый исходящий становится исходящим по умолчанию, первый DNS-сервер — сервером по умолчанию, первый элемент `http_clients` — клиентом по умолчанию для rule-set.

Исходники: option/options.go (`_Options`, `UnmarshalJSONContext`, `checkOptions`), docs/configuration/index.md.

## Разбор JSON

Конфиг читается функцией `json.UnmarshalExtendedContext` библиотеки `sing` (форк `encoding/json` из Go). Корневой объект разбирается с `DisallowUnknownFields`; флаг действует на все вложенные структуры, у которых нет собственного метода разбора. Когда файлов несколько (`-c` несколько раз, `-C`), каждый разбирается как самостоятельный конфиг, а затем их тексты сливаются и результат разбирается ещё раз — правила слияния см. в [cli.md](cli.md#слияние-нескольких-файлов).

### Синтаксис

Допускаются комментарии `//`, `/* */`, `#` и висячие запятые; UTF-8 BOM, одинарные кавычки, ключи без кавычек и второй документ после первого — нет. Полная таблица (проверено) — в [cli.md](cli.md#синтаксис-файла-json-с-комментариями). Синтаксическая ошибка сообщается с номером строки и столбца: `… row 1, column 39`.

### Строгость: неизвестные поля

- Неизвестный ключ почти везде — ошибка разбора с путём: `decode config at <файл>: log.foo: json: unknown field "foo"` (проверено).
- **Исключения** — типы с собственным `UnmarshalJSON`, который внутри вызывает обычный `json.Unmarshal` без строгого режима: для них лишние ключи молча отбрасываются. В зоне этого файла так устроен **`certificate`**: `{"certificate": {"foo": 1}}` проходит check, а `format` выдаёт `{}` (проверено). Другой известный пример — правило маршрутизации с `"action": "reject"` (см. [cli.md](cli.md#сопоставление-ключей-и-неизвестные-поля)).
- Полиморфные объекты со списком «общих» полей (`type`, `tag` и др.) разбираются в два прохода: сначала общая часть без строгости, затем из текста вырезаются общие ключи **в точном написании**, а остаток разбирается строго в структуру конкретного типа. Так устроены элементы `inbounds`, `outbounds`, `endpoints`, `services`, `certificate_providers`, `network_namespaces`, DNS-серверы, правила и rule-set, а также `http_clients` при `version` 2 и 3.

Исходники: option/options.go, option/certificate.go (`UnmarshalJSON`), библиотека sing: common/json/badjson/merge_objects.go (`UnmarshallExcludedContext`).

### Регистр ключей

Проверено на бинарнике 1.14.2:

- Имена полей сопоставляются **без учёта регистра**: декодер сначала ищет точное имя, затем — имя после простого свёртывания Unicode. `{"LOG": {"Level": "info", "TimeStamp": true}}` проходит, `format` печатает его в нижнем регистре; `"Server"`, `"SERVER_PORT"`, `"Store"` работают как `server`, `server_port`, `store`. Свёртывание включает KELVIN SIGN (U+212A) = `k` и LONG S (U+017F) = `s`: ключ `"networ\u212a"` (JSON-экранирование; последний символ — U+212A) принят как `network`.
- **Исключение 1 — общие ключи двухпроходных объектов** (`type`, `tag` и т. п.): написанные не строчными, они распознаются на первом проходе, но не вырезаются и на втором становятся неизвестным полем. `{"Type":"direct"}` и `{"type":"direct","TAG":"a"}` в `outbounds` — ошибка `unknown field` (проверено). Так устроены элементы `inbounds`, `outbounds`, `endpoints`, `services`, `certificate_providers`, `network_namespaces`, DNS-серверы и rule-set (`type`, `tag`, у rule-set ещё `format`), а также V2Ray-транспорт и `obfs`/`masquerade` у hysteria2. В правилах маршрутизации и DNS «головными» оказываются и ключи условий (`"Domain"`, `"Invert"`) и `action`: результат зависит от действия правила — подробно в [route.md](route.md#регистр-ключей-в-разделе-route) и [dns.md](dns.md#ключи-и-неизвестные-поля-внутри-dns).
- **Исключение 2 — `http_clients` и встроенные HTTP-клиенты при `version` 2 (по умолчанию) и 3**: общими здесь считаются *все* базовые поля клиента (`tag`, `engine`, `version`, `disable_version_fallback`, `headers`, `tls` и все dial-поля), поэтому `{"tag":"a","Detour":"x"}` — ошибка `unknown field "Detour"`, а при `"version": 1` тот же ключ принят (проверено). Регистр полей HTTP/2 и QUIC (`Idle_Timeout`) не важен.
- Ключи словарей (`headers`, `servers` у ssm-api и т. п.) — это данные, они не свёртываются. Значения тегов и ссылки на теги сравниваются **точно, с учётом регистра**: `route.final: "Proxy"` не найдёт исходящий `proxy`.
- JSON Schema (`$schema`) строже рантайма: она чувствительна к регистру и запрещает лишние ключи (в том числе в `certificate`), поэтому редактор подсветит то, что sing-box примет.

Исходники: библиотека sing: common/json/internal/contextjson/decode.go (`byExactName`, `byFoldedName`), common/json/internal/contextjson/fold.go.

### Повторяющиеся ключи

Повтор ключа в одном объекте не ошибка. У скаляра побеждает последнее значение, в том числе при разном регистре (`{"level":"bogus","Level":"info"}` проходит, обратный порядок — ошибка уровня; проверено). Повтор списка заменяет список целиком, а не дополняет: два ключа `outbounds` дают только второй массив (проверено `format`). Повтор объекта, напротив, его не заменяет: второй объект дописывается в уже разобранный поле за полем, как в `encoding/json` Go (`{"log":{"level":"bogus"},"Log":{"timestamp":true}}` даёт ошибку уровня `bogus`, `format` показывает оба поля; проверено). Это отличается от слияния нескольких файлов, где массивы складываются.

### Числа, строки, bool

- Целые поля принимают только целый JSON-литерал в диапазоне типа: `-1` и `70000` для порта — ошибка `cannot unmarshal number … of type uint16`; `0x7b` и `0123` — синтаксическая ошибка (проверено).
- В полях, которые разбираются в один проход (`log`, `ntp`, корень `http_clients` и т. п.), дробная или экспоненциальная запись целого — ошибка: `"server_port": 123.0` и `1.23e2` в `ntp` отвергаются (проверено).
- В двухпроходных объектах (элементы `inbounds`, `outbounds` и др.) типовая часть перед строгим разбором проходит через промежуточное дерево, где числа хранятся как `float64`. Поэтому там `"listen_port": 2080.0` и `2e3` принимаются как 2080 и 2000 (проверено), а целые больше 2^53 теряют точность. Полагаться на это не стоит.
- Строка вместо числа или bool — ошибка (`"timestamp": "true"` отвергается, проверено). Исключения, где тип сам принимает строку (например, `routing_mark`), описаны у своих полей.

### Listable: значение или список

Поле типа `string|[string]` (Go: `badoption.Listable[T]`) принимает одно значение без скобок или массив; `null` и `[]` дают пустой список. Каждый вариант разбирается строго (лишние ключи во вложенных объектах — ошибка). При выводе (`format`) список из одного элемента записывается одиночным значением.

Исходники: библиотека sing: common/json/badoption/listable.go.

### Длительности (duration)

Длительность — **строка** в синтаксисе Go (`"300ms"`, `"1.5h"`, `"2h45m"`, знак допускается: `"-5s"`) с дополнительной единицей `d` = 24 часа (`"1d12h"` → `36h0m0s`). Единицы: `ns`, `us`/`µs`/`μs`, `ms`, `s`, `m`, `h`, `d`, только в нижнем регистре. Проверено:

| Значение | Результат |
|---|---|
| `"0"` | ноль (единственное число без единицы, которое принимается) |
| `"10"` | ошибка `missing unit in duration` |
| `"1D"`, `"5 m"` | ошибка `unknown unit` |
| `""` | ошибка `invalid duration ""` — пустую строку нельзя писать даже там, где поле необязательно |
| `30` (число) | ошибка `cannot unmarshal number … of type string` |

Что значит отрицательное или нулевое значение, решает конкретное поле (обычно «по умолчанию»).

Исходники: библиотека sing: common/json/badoption/duration.go, common/json/badoption/internal/my_time/format.go.

### null и пропуск ключа

`null` на месте объекта или списка равнозначен отсутствию ключа (`"log": null` проходит, проверено). `null` как элемент типизированного списка — это объект без `type`: `"outbounds": [null]` даёт `unknown outbound type: ` (проверено).

## Теги и пространства имён

Тег — строковое имя элемента списка, по которому на него ссылаются другие части конфига. Если `tag` не задан, во многих списках тегом становится **номер элемента в своём списке** в виде строки (`"0"`, `"1"`…), и на него можно сослаться как на обычный тег.

| Пространство | Элементы | Тег по умолчанию | Повтор тега |
|---|---|---|---|
| исходящие | `outbounds[]` **и** `endpoints[]` — одно общее пространство | номер в своём списке | ошибка разбора `duplicate outbound/endpoint tag` (check). Безымянный `outbounds[0]` и безымянный `endpoints[0]` оба получают `"0"` и конфликтуют (проверено) |
| входящие | `inbounds[]`; при поиске по тегу — ещё и `endpoints[]` | номер | ошибка `duplicate inbound tag` (check). Совпадение тега входящего и эндпоинта допустимо: поиск сначала находит входящий (проверено check; порядок — по коду) |
| DNS-серверы | `dns.servers[]` | номер | **не ошибка**: более поздний молча заменяет ранний (проверено check; `dns/transport_manager.go`, `Create`) |
| rule-set | `route.rule_set[]` | нет: тег обязателен (`missing tag`, ошибка разбора, проверено); у `local` и `remote` может быть списком — один rule-set под несколькими тегами, у `inline` — только один | ошибка `duplicate rule-set tag` при создании роутера (check, проверено) |
| службы | `services[]` | номер | не ошибка (check проходит, проверено), поздний заменяет ранний (по коду `adapter/service/manager.go`) |
| поставщики сертификатов | `certificate_providers[]` | номер | ошибка разбора `duplicate certificate provider tag` (check) |
| HTTP-клиенты | `http_clients[]` | нет: тег обязателен (`missing http client tag`) | ошибка разбора `duplicate http client tag` (check) |
| сетевые пространства | `network_namespaces[]` | нет: тег обязателен | на Linux — ошибка `network namespace: duplicated tag` при создании; на Windows непустой список отвергается целиком |

Пространства не пересекаются: исходящий и входящий, DNS-сервер и исходящий могут называться одинаково (проверено для входящего и исходящего).

Ссылки на тег проверяются в разное время — часть при создании экземпляра (их ловит check), часть только при запуске, часть — лишь при обработке соединения. Сводка — в разделе [Где всплывает ошибка](#где-всплывает-ошибка-check-запуск-отдельные-соединения).

Исходники: option/options.go (`checkInbounds`, `checkOutbounds`, `checkCertificateProviders`, `checkHTTPClients`), box.go (`New`: теги по номеру), adapter/outbound/manager.go, adapter/inbound/manager.go (`Get`), adapter/endpoint/manager.go, dns/transport_manager.go, route/router.go (`Initialize`), common/netns/manager_linux.go.

### Проверки checkOptions

После разбора каждого файла и после слияния выполняется `checkOptions`. Он проверяет только теги, не ссылки:

| Проверка | Сообщение |
|---|---|
| повтор тега среди `inbounds` (пустой тег заменяется номером) | `duplicate inbound tag: <тег>` |
| повтор тега среди `outbounds` и `endpoints` вместе (пустой — номер в своём списке) | `duplicate outbound/endpoint tag: <тег>` |
| повтор тега среди `certificate_providers` (пустой — номер) | `duplicate certificate provider tag: <тег>` |
| элемент `http_clients` без `tag` | `missing http client tag` |
| повтор тега среди `http_clients` | `duplicate http client tag: <тег>` |

Ошибка приходит с префиксом `decode config at <файл>: `.

Исходники: option/options.go (`checkOptions` и функции `check*`).

### Объекты по умолчанию

| Что | Как выбирается | Если нечего выбрать | Где |
|---|---|---|---|
| исходящий по умолчанию (куда идёт трафик без совпавшего правила) | `route.final`: исходящий, а если такого нет — эндпоинт с этим тегом; без `route.final` — **первый элемент `outbounds`** (эндпоинты не рассматриваются) | создаётся исходящий `direct` с тегом `direct`. Значит, конфиг из одного эндпоинта без `route.final` по умолчанию идёт напрямую, а не в эндпоинт (по коду) | adapter/outbound/manager.go (`Create`, `Start`) |
| DNS-сервер по умолчанию | `dns.final`, иначе первый элемент `dns.servers`; сервер `fakeip` по умолчанию быть не может (`default server cannot be fakeip`, check, проверено) | создаётся сервер типа `local` с тегом `local` | dns/transport_manager.go |
| HTTP-клиент по умолчанию для удалённых rule-set | `route.default_http_client`, иначе первый элемент `http_clients` | неявный клиент через исходящий по умолчанию (устарело в 1.14, удаление в 1.16, WARN при первом использовании) | common/httpclient/manager.go, box.go |

Резервные объекты создаются не в `box.New`, а на стадии инициализации при запуске (для HTTP-клиента — при первом обращении).

## log

Журнал самого сервиса. Сообщения, которые пишет командная строка до создания экземпляра и после его завершения (ошибки CLI, предупреждения об устаревании, `FATAL start service: …`), в этот журнал не попадают: они всегда идут в stderr (см. [cli.md](cli.md#куда-пишется-лог) и [deprecations.md](deprecations.md#куда-пишутся-сообщения)).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `disabled` | bool | `false` | Полностью отключить журнал экземпляра: создаётся пустой логгер, не пишется ничего, включая ошибки. При `true` значение `level` даже не разбирается (`"level":"bogus"` проходит check, проверено). |
| `level` | string | `trace` | Порог: `trace`, `debug`, `info`, `warn` (синоним `warning`), `error`, `fatal`, `panic`. Регистр важен: `"INFO"` — ошибка `create log factory: parse log level: unknown log level: INFO` (check, проверено). Пустая строка или отсутствие поля — уровень `trace`, то есть всё подряд. |
| `output` | string | `""` (stderr) | Куда писать. `""` и `"stderr"` — стандартный поток ошибок, `"stdout"` — стандартный вывод, любое другое значение — путь к файлу. Файл открывается при запуске (на дозапись, с созданием, режим 0644), не обрезается и не ротируется. Относительный путь — от рабочего каталога процесса (`-D`), каталоги не создаются: отсутствующая папка — ошибка запуска `start logger: open …`; check файл не открывает и такую ошибку не видит (проверено). При записи в файл консоль не используется. |
| `timestamp` | bool | `false` | Полная дата и время в начале каждой строки. |

Формат строки определяется парой `output`/`timestamp`:

| Вывод | `timestamp: false` | `timestamp: true` |
|---|---|---|
| консоль (stderr/stdout) | `INFO[0012] <тег>: <сообщение>` — в скобках секунды от создания экземпляра, минимум 4 цифры; уровень раскрашен ANSI-кодами | `+0300 2026-09-29 14:03:05 INFO <тег>: <сообщение>` (формат `-0700 2006-01-02 15:04:05`) |
| файл | `INFO <тег>: <сообщение>` — **без времени** | как в консоли с `timestamp`, без цвета |

- Цвет выключают только запись в файл и флаг `--disable-color` командной строки (он же выставляет внутреннее поле `DisableColor`, которого нет в JSON). Наличие терминала не проверяется: при перенаправлении stderr в файл ANSI-коды остаются.
- Сообщения, относящиеся к соединению, получают префикс `[<номер> <время жизни>]` (номер раскрашен).
- Тег источника: `router`, `dns`, `outbound/vless[proxy]`, `inbound/tun[tun-in]`, `ntp` и т. п.
- До открытия файла (всё, что пишется во время `box.New`) сообщения копятся в памяти и выводятся при запуске. У `check` запуска нет, поэтому эти сообщения теряются; напечатано будет только сообщение уровня `fatal` или `panic`, которое пишется сразу.
- Сообщение уровня `fatal` завершает процесс с кодом 1, уровня `panic` — вызывает панику.
- Если задан `experimental.clash_api.external_controller`, все сообщения, независимо от `level`, дополнительно отдаются подписчикам Clash API (`/logs`); уровень там фильтрует клиент ([experimental.md](experimental.md)).

Исходники: option/options.go (`LogOptions`), log/log.go (`New`), log/level.go (`ParseLevel`), log/format.go (`Formatter`), log/observable.go (`Start`, `Log`, `output`), log/nop.go, box.go (`New`, `preStart`), cmd/sing-box/cmd.go, cmd/sing-box/cmd_run.go (`create`).

## ntp

Встроенный NTP-клиент. Он **не меняет системные часы** (если не включён `write_to_system`), а вычисляет поправку, которой пользуется сам sing-box: время для проверки сертификатов TLS (в том числе uTLS и Reality), VMess, Shadowsocks 2022, TLS-проверок urltest, загрузок Clash API, Tailscale, ccm/ocm. Полезен там, где системное время неверно и не синхронизируется.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включить клиент. Остальные поля разбираются и при `false`: неверная длительность в `interval` — ошибка разбора (проверено). |
| `server` | string | `time.apple.com` | Адрес NTP-сервера (IP или имя). Документация называет поле обязательным, код подставляет `time.apple.com`. Но при пустом `server` и без `detour` клиент получает имя, не имея резолвера, и каждая синхронизация кончается ошибкой `domain not resolved` (по коду `common/dialer/default.go`; запуском не проверено) — указывайте сервер явно. |
| `server_port` | int | `123` | Порт; `0` — 123. |
| `interval` | duration | `30m` | Период синхронизации; `0` и отрицательные — 30 минут. |
| `write_to_system` | bool | `false` | После каждой успешной синхронизации записывать время в системные часы. Работает на Windows (`SetSystemTime`, нужны права администратора), Linux и macOS; на других платформах — ошибка в журнале. В документации не описано (есть только в JSON Schema). В CLI ограничений нет; графическая служба-демон sing-box может запретить поле своей политикой безопасности (тогда ошибка создания экземпляра). |
| dial-поля | — | — | `detour`, `domain_resolver`, `bind_interface`, `inet4_bind_address`, `inet6_bind_address`, `bind_address_no_port`, `protect_path`, `routing_mark`, `reuse_addr`, `netns`, `connect_timeout`, `tcp_fast_open`, `tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`, `udp_fragment`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, устаревшее `domain_strategy` — см. [shared.md](shared.md#поля-подключения-dial). NTP идёт по UDP. |

Поведение:

- Первая синхронизация — на стадии запуска внутренних служб; её неудача пишется в журнал (`initialize time: …`) и запуск **не останавливает**. Дальше — по таймеру, ошибки тоже только в журнал (`update time: …`). Тайм-аут одного обмена — 5 секунд.
- Если `server` — доменное имя, `detour` не задан, а DNS-серверов два и больше, нужен `domain_resolver` или `route.default_domain_resolver`; без них check завершается FATAL-заметкой `MISSING_DOMAIN_RESOLVER` (проверено; см. [deprecations.md](deprecations.md)). С `detour` имя разрешает исходящий, и требование не действует (проверено).
- `domain_resolver`, указывающий на несуществующий DNS-сервер, ловит check: `create NTP service: domain resolver not found` (проверено).
- `detour` на несуществующий исходящий check пропускает (проверено), и запуск тоже: такой `detour` проверяется только при попытке синхронизации, и ошибка остаётся в журнале (`outbound detour not found`). То же для `detour` на «пустой» `direct`.

Исходники: option/ntp.go, option/outbound.go (`ServerOptions`, `DialerOptions`), box.go (`New`: `ntpOptions`), common/tls/time_wrapper.go, adapter/security.go; библиотека sing: common/ntp/service.go, common/ntp/ntp.go, common/ntp/message.go, common/ntp/time_windows.go.

## certificate

С 1.12. Набор доверенных корневых сертификатов для исходящих TLS-соединений самого sing-box: клиентов TLS/uTLS/Reality в исходящих и DNS-серверах, HTTP-клиентов, urltest, загрузок Clash API, Tailscale, ccm/ocm. Сертификат, заданный в `tls.certificate`/`tls.certificate_path` конкретного исходящего, заменяет этот набор для него ([shared.md](shared.md#исходящий-tls-клиент)).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `store` | string | `system` | Базовый набор: `system` — хранилище ОС; `mozilla` — встроенный список Mozilla без китайских УЦ; `chrome` — встроенный Chrome Root Store без китайских УЦ (с 1.13); `none` — пустой набор. Регистр важен: `"System"` — ошибка `unknown certificate store: System` (check, проверено). |
| `certificate` | string\|[string] | — | Дополнительные сертификаты в PEM. Элементы списка склеиваются через перевод строки, поэтому можно писать и по сертификату на элемент, и по строке PEM на элемент. Неразбираемый PEM — ошибка check `initializing certificate store: invalid certificate PEM strings` (проверено). |
| `certificate_path` | string\|[string] | — | Файлы PEM. Читаются при создании экземпляра: отсутствующий файл — ошибка check (проверено). Файлы отслеживаются и перечитываются при изменении. |
| `certificate_directory_path` | string\|[string] | — | Каталоги с файлами PEM. Отсутствующий каталог молча пропускается (проверено), нечитаемые или не-PEM файлы в нём тоже; другая ошибка чтения каталога — ошибка. Отслеживаются и перечитываются. |

- При `mozilla`, `chrome` и `none` доверие ограничено этим набором плюс добавленными сертификатами. `none` без своих сертификатов делает любую проверку сертификата неудачной.
- Если секции нет или в ней только `store: system` без дополнительных сертификатов, объект хранилища не создаётся вовсе и TLS пользуется умолчанием Go (кроме Android, где хранилище создаётся всегда).
- Неизвестные ключи внутри `certificate` **молча отбрасываются** (см. [Строгость](#строгость-неизвестные-поля)); JSON Schema их запрещает.
- Относительные пути — от рабочего каталога процесса. Ошибка перечитывания после изменения файла пишется в журнал (`reload certificates`), прежний набор остаётся.

Windows: `system` означает проверку цепочки средствами Windows (CryptoAPI, `CertGetCertificateChain` с цепочкой текущего пользователя — так делает Go). Корневые сертификаты, которые добавлены в хранилище пользователя, от имени которого работает sing-box, тоже считаются доверенными; `mozilla`/`chrome` от хранилища Windows не зависят. Добавленные в `certificate` сертификаты при `system` проверяются вторым шагом, если проверка Windows не прошла (поведение `crypto/x509` Go для системного пула; в дереве sing-box не проверено).

Исходники: option/certificate.go, constant/certificate.go, common/certificate/store.go (`NewStore`, `update`), common/certificate/system_other.go, common/certificate/mozilla.go, common/certificate/chrome.go, adapter/certificate.go (`RootPoolFromContext`), common/tls/std_client.go, common/tls/utls_client.go, box.go (`New`).

## certificate_providers

С 1.14. Список общих поставщиков **серверных** сертификатов для входящего TLS. Элемент — объект `{type, tag, …поля типа}`; входящий TLS ссылается на него строкой-тегом в `tls.certificate_provider` или описывает поставщика там же встроенным объектом (с `type`, без `tag`). Элемент разбирается в два прохода, поэтому `type` и `tag` пишутся только строчными.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — | `acme` (build-тег `with_acme`), `cloudflare-origin-ca`, `tailscale` (build-тег `with_tailscale`); в официальной сборке для Windows есть все три. Неизвестный или пустой — ошибка разбора. Только строчными. |
| `tag` | string | номер элемента | Уникален (`duplicate certificate provider tag`, check). Только строчными. |
| поля типа | — | — | `acme`: `domain`, `data_directory`, `default_server_name`, `email`, `provider`, `account_key`, `disable_http_challenge`, `disable_tls_alpn_challenge`, `alternative_http_port`, `alternative_tls_port`, `external_account` (`key_id`, `mac_key`), `dns01_challenge`, `key_type`, `profile`, `http_client`. `cloudflare-origin-ca`: `domain`, `data_directory`, `api_token`, `origin_ca_key`, `request_type`, `requested_validity`, `http_client`. `tailscale`: `endpoint`. Типы, умолчания и ограничения — в [shared.md](shared.md#провайдеры-сертификатов-certificate_provider) (основное описание), DNS-01 — в [shared.md](shared.md#dns-01-dns01_challenge). |

Когда что проверяется: поля и ссылки поставщика (`http_client`, `endpoint`) — при создании (check): неизвестный тег `http_client` у `acme`/`cloudflare-origin-ca`, поставщик `tailscale` без эндпоинта (`initialize certificate provider[0]: endpoint not found`, проверено). Ссылку из `tls.certificate_provider` входящего на несуществующий тег check **пропускает** (проверено), а запуск входящего падает: `certificate provider not found`. Выпуск сертификата идёт после запуска и зависит от сети.

Исходники: option/certificate_provider.go, option/acme.go, option/tls_acme.go, option/origin_ca.go, option/tailscale.go (`TailscaleCertificateProviderOptions`), adapter/certificate/manager.go, adapter/certificate/registry.go, common/tls/std_server.go (`sharedCertificateProvider.Start`), service/acme/service.go, service/origin_ca/service.go, protocol/tailscale/certificate_provider.go, box.go.

## http_clients

С 1.14. Общие HTTP-клиенты, которыми sing-box делает **собственные** HTTP-запросы: загрузка удалённых rule-set, обращения ACME и Cloudflare Origin CA, `verify_client_url` у DERP, загрузка дашборда службы `api`, `realm` у hysteria2 (с 1.14 это единая замена прежних dial- и TLS-полей, которые у каждого из этих компонентов были свои). К трафику, который идёт через исходящие, клиенты отношения не имеют. Этот раздел — основное описание HTTP-клиента: и элемента списка `http_clients`, и встроенного объекта `http_client` у потребителей. Смысл вложенных блоков — в shared.md: [исходящий TLS](shared.md#исходящий-tls-клиент), [dial-поля](shared.md#поля-подключения-dial), [поля HTTP/2](shared.md#параметры-http2-http2-fields), [поля QUIC](shared.md#параметры-quic-quic-fields).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `tag` | string | — | Обязателен в элементе `http_clients` (`missing http client tag`), уникален. Во встроенном объекте не используется, см. ниже. |
| `engine` | string | `go` | `go` или `apple` (NSURLSession, только Apple-платформы; документация не советует его для нагруженных путей на iOS/tvOS). Значение проверяется, **только когда клиент создаётся**: `"apple"` и даже `"bogus"` проходят check (проверено); на Windows клиент с `apple` при создании падает (`Apple HTTP engine is not available on non-Apple platforms`), с неизвестным значением — `unknown HTTP engine`. Движок `apple` поддерживает только `headers`, `tls.server_name` (должен совпадать с хостом запроса), `tls.insecure`, версии TLS, `tls.certificate`/`certificate_path`, `tls.certificate_public_key_sha256` и dial-поля; `version`, `disable_version_fallback`, поля HTTP/2 и QUIC и прочие поля TLS он не поддерживает. |
| `version` | int | `2` | `1`, `2`, `3`; `0` значит 2. Другое — ошибка разбора `unknown HTTP version` (проверено). Только целый литерал: `2.0` — ошибка (проверено). Версия определяет, какие ещё поля допустимы. |
| `disable_version_fallback` | bool | `false` | Не откатываться на младшую версию (см. [ниже](#версии-и-откат)). |
| `headers` | object | — | Заголовки: имя → string\|[string]. Имена приводятся к каноническому виду HTTP; заголовок с тем же именем в запросе заменяется. `Host` не отправляется как заголовок, а становится хостом запроса. |
| `idle_timeout` | duration | `0` | Поле HTTP/2: при версии 2 настраивает HTTP/2 (уходит в тайм-аут ответа на PING), при версии 3 — QUIC-соединение HTTP/3 (запасной HTTP/2 тогда работает с умолчаниями). |
| `keep_alive_period` | duration | `0` | Поле HTTP/2 (версии 2 и 3, как выше): через сколько тишины слать PING / keep-alive. |
| `stream_receive_window` | size | по умолчанию библиотеки | Поле HTTP/2 (версии 2 и 3): окно приёма потока. |
| `connection_receive_window` | size | по умолчанию библиотеки | Поле HTTP/2 (версии 2 и 3): окно приёма соединения. |
| `max_concurrent_streams` | int | `0` | Поле HTTP/2 (версии 2 и 3): предел одновременных потоков. |
| `initial_packet_size` | int | по умолчанию quic-go | Только `version: 3`; при версии 2 — ошибка `unknown field` (проверено). |
| `disable_path_mtu_discovery` | bool | `false` | Только `version: 3`. |
| `tls` | object | — | [Исходящий TLS](shared.md#исходящий-tls-клиент). Для https TLS включён всегда, `enabled` роли не играет; пустой `server_name` берётся из URL. |
| dial-поля | — | — | `detour`, `domain_resolver`, `bind_interface`, `inet4_bind_address`, `inet6_bind_address`, `bind_address_no_port`, `protect_path`, `routing_mark`, `reuse_addr`, `netns`, `connect_timeout`, `tcp_fast_open`, `tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`, `udp_fragment`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay` (для версии 3 — ещё и задержка запасной попытки HTTP/2, по умолчанию 300ms), устаревшее `domain_strategy` — [shared.md](shared.md#поля-подключения-dial). |

При `version: 1` поля HTTP/2 и QUIC — ошибка `unknown field` (проверено). Регистр ключей — см. [Исключение 2](#регистр-ключей).

**Без `detour` клиент подключается напрямую** (системный dialer с учётом `bind_interface` и т. п.), минуя маршрутизацию и `route.final`. Это касается и элементов `http_clients`, и встроенных объектов. Через исходящий по умолчанию ходит только неявный клиент, который создаётся, когда `http_clients` нет вовсе (см. [Клиент по умолчанию](#клиент-по-умолчанию-для-rule-set)).

Если адрес назначения — доменное имя, а `detour` не задан, имя разрешает DNS sing-box: нужен `domain_resolver` или `route.default_domain_resolver`, иначе при двух и более DNS-серверах — заметка `MISSING_DOMAIN_RESOLVER` (для клиента из `http_clients` — при его создании, то есть при запуске).

### Версии и откат

| `version` | `disable_version_fallback: false` | `true` |
|---|---|---|
| `1` | HTTP/1.1 | HTTP/1.1 |
| `2` | ALPN предлагает `h2` и `http/1.1`; если сервер выбрал HTTP/1.1, хост запоминается и дальше обслуживается по HTTP/1.1 | только HTTP/2 |
| `3` | HTTP/3 наперегонки с HTTP/2 (HTTP/2 стартует через `fallback_delay`, по умолчанию 300ms); хост с неудачным HTTP/3 помечается «сломанным» на 5 минут, при повторах срок удваивается до 48 часов | только HTTP/3 |

Запросы по `http://` и запросы с WebSocket-апгрейдом всегда идут по HTTP/1.1.

### Ссылка на клиент: тег или объект

Поле `http_client` у потребителей (`route.rule_set[].http_client`, `acme`, `cloudflare-origin-ca`, `services[api].dashboard`, `realm` у hysteria2, `verify_client_url` у DERP) принимает:

- **строку** — тег элемента `http_clients`; все ссылки на один тег делят один экземпляр клиента (одни соединения);
- **объект** — встроенный клиент с теми же полями, кроме `tag`; для каждого места создаётся свой экземпляр. Ключ `tag` внутри встроенного объекта **молча отбрасывается**: `{"tag": "x"}` — не ссылка на `x`, а пустой встроенный клиент (проверено check; по коду `HTTPClientOptions.UnmarshalJSON`). Пустой объект у rule-set равнозначен отсутствию поля.

Число или другой тип — ошибка разбора (проверено). Когда проверяется ссылка на несуществующий тег: у `acme`, `cloudflare-origin-ca` и `realm` hysteria2 клиент создаётся в конструкторе, так что ошибку ловит check (проверено для поставщика `acme` — `create ACME provider http client: http_client not found` — и для `realm` — `create realm http client: http_client not found`); у rule-set и дашборда службы `api` — только при запуске (`http_client not found`; для rule-set проверено, что check проходит).

### Клиент по умолчанию для rule-set

`route.default_http_client` (string -> http_client, с 1.14; описан в [route.md](route.md)) выбирает клиента для удалённых rule-set без собственного `http_client`. Больше его никто не использует.

| Конфиг | Клиент удалённых rule-set без `http_client` |
|---|---|
| задан `route.default_http_client` | этот клиент. Несуществующий тег check пропускает (проверено), а запуск падает: `resolve default http client: http_client not found` — даже если удалённых rule-set нет |
| `default_http_client` пуст, `http_clients` непуст | **первый** элемент `http_clients`. Он создаётся при запуске всегда, поэтому ошибка в нём (например, `engine: apple` на Windows) роняет запуск, даже если он никому не нужен |
| `http_clients` нет или пуст | неявный клиент через исходящий по умолчанию. Устарело в 1.14 (заметка `IMPLICIT_DEFAULT_HTTP_CLIENT`, удаление в 1.16), при первом использовании — WARN; check этого не покажет |
| у rule-set задан устаревший `download_detour` (и нет `http_client`) | отдельный клиент через этот исходящий; `download_detour` вместе с `http_client` — ошибка запуска |

Остальные элементы `http_clients` создаются лениво, при первой ссылке; ошибки в неиспользуемом элементе (кроме первого) не проявляются никогда.

Исходники: option/http.go (`HTTP2Options`, `QUICOptions`, `_HTTPClientOptions`, `HTTPClient`, `HTTPClientOptions`, `unmarshalHTTPClientVersionOptions`), option/options.go (`checkHTTPClients`), option/route.go (`DefaultHTTPClient`), option/rule_set.go, option/acme.go, option/origin_ca.go, option/api.go, option/hysteria2.go, option/tailscale.go (поля `http_client` потребителей), common/httpclient/manager.go (`NewManager`, `Start`, `ResolveTransport`, `resolveShared`, `DefaultTransport`), common/httpclient/client.go (`NewTransport`, `newTransport`), common/httpclient/http2_config.go, common/httpclient/http2_fallback_transport.go, common/httpclient/http3_transport.go, common/httpclient/helpers.go, common/httpclient/apple_transport_stub.go, route/rule/rule_set_remote.go (`resolveTransport`), box.go, experimental/deprecated/constants.go (`OptionImplicitDefaultHTTPClient`, `OptionLegacyRuleSetDownloadDetour`).

## network_namespaces

С 1.14, **только Linux**. Именованные сетевые пространства имён, на которые по тегу ссылаются поля `netns` у TUN, в listen-полях и в dial-полях (вместо тега там можно написать имя или путь пространства напрямую). Элемент разбирается в два прохода (`type`, `tag` — только строчными).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | `default` | `default` — подключиться к существующему пространству; `unshare` — создать новое. Другое — ошибка разбора `unknown network namespace type` (проверено). |
| `tag` | string | — | Обязателен (на Linux — `network namespace: missing tag`), уникален. |
| `path` | string | — | Только `default`, обязателен (`missing path`). Имя (ищется как `/run/netns/<имя>`) или абсолютный путь; существование проверяется при запуске. |
| `pid_file` | string | `""` | Только `unshare`: куда записать PID процесса-держателя пространства (удаляется при остановке). Держатель — сам sing-box, запущенный скрытой командой `netns-holder`; поэтому `unshare` работает только в `sing-box run`, а без root требует разрешённых непривилегированных user namespaces. |

**Windows**: любой непустой `network_namespaces` — ошибка check `network namespaces are only supported on Linux` (проверено; пустой список допустим). Поле `netns` в dial/listen-полях check пропускает (проверено для исходящего `direct`), но на Windows каждое подключение или прослушивание с ним завершится ошибкой `get netns …` — библиотека пространств имён вне Linux не реализована (по коду; запуском не проверено).

Исходники: option/netns.go, constant/netns.go, common/netns/manager_linux.go, common/netns/manager_stub.go, common/listener/listener.go (`ListenNetworkNamespace`), cmd/sing-box/cmd_run.go (`create`: аргументы держателя), docs/configuration/network-namespace/*.md.

## Жизненный цикл: box.New и Start

Экземпляр живёт в три шага: **разбор** конфига (`option.Options`: JSON + `checkOptions`), **создание** (`box.New`) и **запуск** (`Box.Start`). `sing-box check` выполняет первые два шага и сразу закрывает экземпляр (`Close`), ничего не запуская. `sing-box run` выполняет все три; ошибка запуска закрывает то, что успело запуститься, и завершает процесс: `FATAL start service: …`, код 1. Часть задач запуска (открытие журнала, старт каждого исходящего и DNS-сервера, стадии DNS-маршрутизатора, маршрутизатора и сетевого менеджера, создание TUN) идёт под наблюдением `taskmonitor`: дольше 10 секунд (`C.StartTimeout`) — предупреждение `… take too much time to finish!` в журнале, без прерывания; при закрытии менеджеров тот же монитор срабатывает через 5 секунд (`C.StopTimeout`). Прочие стадии без монитора лишь пишут на уровне trace, что ещё идут (через секунду).

### box.New: что создаётся и проверяется

По порядку (всё это видит check):

1. `experimental.debug`: устаревший `oom_killer` — ошибка.
2. Журнал: разбор `log.level` (кроме `disabled`). Файл `log.output` не открывается.
3. Хранилище сертификатов (если `certificate` не по умолчанию): `store`, PEM, чтение `certificate_path` и каталогов.
4. Менеджер сетевых пространств: на Windows — отказ при непустом списке; на Linux — теги и `path`.
5. Менеджеры исходящих (запоминается тег `route.final`), DNS-серверов (`dns.final`), входящих, эндпоинтов, служб, поставщиков сертификатов; DNS-маршрутизатор; менеджер сети (платформенные ограничения `route`: `auto_detect_interface`, `default_interface`, `default_mark` и т. п.); менеджер HTTP-клиентов (только запоминает определения — ни один клиент не создаётся).
6. Маршрутизатор: разбор правил `route.rules` (теги rule-set и исходящих в правилах **не** проверяются); создание rule-set: повтор тега, чтение и разбор локальных файлов, разбор встроенных; удалённые не загружаются.
7. При `clash_api` или службе `api` — учёт трафика и режимы Clash.
8. DNS-серверы по порядку: построение dialer'ов (сервер с доменным адресом без `domain_resolver` — ошибка; `domain_resolver` DNS-сервера на этом шаге не ищется), запрет `fakeip` по умолчанию и второго `fakeip`; повтор тега — замена.
9. DNS-правила: разбор, **поиск rule-set по тегу** (отсутствующий — ошибка).
10. Эндпоинты, затем входящие (у TUN — поиск rule-set для `route_address_set`/`route_exclude_address_set`), затем службы, затем исходящие (dialer'ы: поиск `domain_resolver` и `route.default_domain_resolver`, заметка `MISSING_DOMAIN_RESOLVER`; у групп — непустой список), затем поставщики сертификатов (их `http_client`, `endpoint`). Встроенные HTTP-клиенты hysteria2 `realm`, `acme`, `cloudflare-origin-ca` создаются здесь же.
11. Регистрируются резервные объекты (исходящий `direct`, DNS `local`, неявный HTTP-клиент) — создаются они позже.
12. Объекты `cache_file` (файл не открывается), сервер Clash API (порт не слушается), `v2ray_api`, NTP-клиент (строится dialer: `domain_resolver`).

Заметки устаревания, которые возникают на этих шагах, check показывает (WARN или ERROR+FATAL, см. [deprecations.md](deprecations.md)).

### Стадии запуска (StartState*)

`Start` проходит по компонентам стадиями `Initialize` → `Start` → `PostStart` → `Started` (в журнале уровня trace: `initialize`, `start`, `post-start`, `finish-start`). Первая часть оформлена как `PreStart` (её отдельно вызывают графические клиенты), остальное — продолжение.

| Шаг | Стадия | Компоненты | Что происходит и что может упасть |
|---|---|---|---|
| 1 | — | журнал | открытие файла `log.output`, вывод накопленных сообщений (`start logger: …`) |
| 2 | — | debug | параметры рантайма Go; отладочный HTTP-сервер `experimental.debug.listen` |
| 3 | Initialize | внутренние службы | открытие `cache.db`; на Linux — проверка и создание сетевых пространств |
| 4 | Initialize | сеть, DNS-серверы, DNS-маршрутизатор, соединения, маршрутизатор, исходящие, входящие, эндпоинты, службы, поставщики | `dns.final` должен существовать (иначе `default DNS server not found`), без DNS-серверов создаётся `local`; `route.final` должен быть исходящим или эндпоинтом (иначе `default outbound not found`), без исходящих создаётся `direct`; поиск соседей |
| 5 | Start | исходящие (с эндпоинтами) | запуск в порядке зависимостей (`detour`, участники групп): нет зависимости — `dependency[X] not found for outbound[Y]`, кольцо — `circular outbound dependency`; `selector` проверяет участников и `default` |
| 6 | Start | DNS-серверы | запуск в порядке зависимостей по `domain_resolver`: нет — `dependency[X] not found for server[Y]`, кольцо — `circular server dependency`; проверка `detour` UDP/TCP/TLS/QUIC/HTTPS/H3-серверов: `outbound detour not found`, `detour to an empty direct outbound makes no sense` |
| 7 | Start | сеть, соединения | мониторы интерфейсов и т. п. |
| 8 | Start | HTTP-клиенты | клиент по умолчанию для rule-set (`route.default_http_client` или первый `http_clients`) находится и создаётся |
| 9 | Start | маршрутизатор | загрузка rule-set (до 5 параллельно, первая ошибка прерывает): удалённые — из `cache.db`, иначе скачиваются; поиск процессов для правил `process_*` |
| 10 | Start | DNS-маршрутизатор | DNS-правила пересобираются и запускаются; часть заметок устаревания DNS |
| 11 | Start | внутренние службы | наблюдение за файлами сертификатов, первая синхронизация NTP (ошибка — только в журнал), очистка кэша |
| 12 | Start | поставщики сертификатов, затем входящие и службы (эндпоинты уже запущены на шаге 5) | поставщики начинают выпуск; входящие начинают слушать порты, TUN создаёт интерфейс; входящий TLS ищет `certificate_provider` по тегу |
| 13 | PostStart | все менеджеры, затем внутренние службы | правила маршрутизации находят rule-set и `preferred_by` по тегам (`initialize rule[i]: rule-set not found`); запускается периодическое обновление rule-set |
| 14 | Started | все менеджеры, затем внутренние службы | маршрутизатор освобождает исходные данные rule-set; Clash API начинает слушать `external_controller` — занятый порт роняет запуск на самом последнем шаге |

После шага 14 в журнале: `sing-box started (<секунды>s)`.

### Остановка

`Close` закрывает компоненты в порядке: отладочный сервер, службы, входящие, поставщики сертификатов, эндпоинты, исходящие, маршрутизатор, соединения, DNS-маршрутизатор, DNS-серверы, сеть, HTTP-клиенты, внутренние службы (кэш, Clash API, NTP…), журнал. Повторный вызов возвращает `os.ErrClosed`. Сигнал во время запуска прерывает его; если остановка не укладывается в 10 секунд, CLI завершает процесс сообщением `sing-box did not close!` ([cli.md](cli.md#сигналы-перезагрузка-и-остановка)).

Исходники: box.go (`New`, `PreStart`, `Start`, `preStart`, `start`, `Close`), adapter/lifecycle.go (`StartStage`, `Start`, `StartNamed`), adapter/lifecycle_legacy.go (`LegacyStart`), debug.go (`checkDebugOptions`), common/taskmonitor/monitor.go, constant/timeout.go (`StartTimeout`, `StopTimeout`, `FatalStopTimeout`), cmd/sing-box/cmd_check.go, cmd/sing-box/cmd_run.go (`create`, `closeMonitor`).

## Где всплывает ошибка: check, запуск, отдельные соединения

Три класса: **check** — ловит `sing-box check` (разбор или `box.New`); **запуск** — check проходит, `sing-box run` падает (для tray-sing-box: VPN не поднимается при каждой попытке); **соединение** — запуск проходит, ломаются отдельные соединения, запросы или фоновые операции, а в журнале появляются ошибки. «Проверено» — результат check получен на бинарнике 1.14.2; класс «запуск» и «соединение» установлен по коду (команду `run` в этой работе не запускали).

### Ловит check

| Ситуация | Сообщение (суть) | Где в коде | Проверено |
|---|---|---|---|
| Синтаксис JSON, BOM, число в кавычках, bool строкой | `decode config at …: …` | cmd/sing-box/cmd_run.go `readConfigAt` | да |
| Неизвестный ключ (кроме нестрогих типов, например `certificate`) | `json: unknown field` | option/options.go `UnmarshalJSONContext` | да |
| `Type`/`Tag` не строчными в двухпроходном объекте; базовый ключ `http_clients` не строчными при версии 2/3 | `unknown field "Type"` | библиотека sing badjson `UnmarshallExcludedContext` | да |
| Пустой или неизвестный `type` у inbound/outbound/…; `null` в списке | `unknown outbound type: …` | option/outbound.go и аналоги | да |
| Повтор тега inbound, outbound/endpoint, certificate provider, http client; http client без тега | `duplicate … tag` | option/options.go `checkOptions` | да |
| Неизвестная версия HTTP-клиента; поля HTTP/2/QUIC не той версии | `unknown HTTP version`, `unknown field` | option/http.go `unmarshalHTTPClientVersionOptions` | да |
| Неверная длительность, число вне диапазона типа | `invalid duration`, `cannot unmarshal number` | библиотека sing badoption, contextjson | да |
| `log.level` не из списка (при `disabled: false`) | `create log factory: parse log level` | log/log.go `New` | да |
| `certificate`: неизвестный `store`, битый PEM, нет файла `certificate_path` | `unknown certificate store`, `initializing certificate store: …` | common/certificate/store.go `NewStore` | да |
| Непустой `network_namespaces` на Windows | `network namespaces are only supported on Linux` | common/netns/manager_stub.go `NewManager` | да |
| Повтор тега rule-set; нет локального файла rule-set | `initialize router: …` | route/router.go `Initialize` | да |
| DNS-сервер с доменным адресом без `domain_resolver` и без `detour` (`route.default_domain_resolver` и число серверов не важны) | `missing domain resolver for domain server address` | common/dialer/dialer.go `NewWithOptions`, dns/transport_dialer.go | да |
| `fakeip` как DNS по умолчанию (`dns.final` или первым в списке); второй `fakeip` | `default server cannot be fakeip`, `multiple fakeip server are not supported` | dns/transport_manager.go `Create` | да |
| DNS-правило ссылается на несуществующий rule-set | `initialize dns router: dns rule[i]: rule-set not found` | dns/router.go `Initialize` | да |
| `route_address_set`/`route_exclude_address_set` TUN — нет такого rule-set | `parse route_address_set: rule-set not found` | protocol/tun/inbound.go | да (первое) |
| `domain_resolver` исходящего или NTP — нет такого DNS-сервера; `route.default_domain_resolver` не существует **и используется** | `domain resolver not found`, `default domain resolver not found` | common/dialer/dialer.go `NewDNSQueryOptions` | да |
| Имя назначения без `domain_resolver` при ≥ 2 DNS-серверах и без `route.default_domain_resolver` — в том числе у **любого исходящего `direct`** и у NTP без `detour` (при одном DNS-сервере требования нет) | ERROR + `FATAL … ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true` | common/dialer/dialer.go `NewDNSQueryOptions`, experimental/deprecated | да |
| `selector`/`urltest` с пустым `outbounds` | `initialize outbound[i]: missing tags` | protocol/group/selector.go `NewSelector` | да |
| Поставщик `tailscale` без эндпоинта; `http_client` поставщика `acme`/`cloudflare-origin-ca` не найден | `initialize certificate provider[i]: …` | protocol/tailscale/certificate_provider.go, common/httpclient/manager.go `ResolveTransport` | да (первое) |
| `experimental.debug.oom_killer` | `legacy oom_killer in debug options is removed` | debug.go `checkDebugOptions` | нет |
| Служба `ssm-api` с `"servers": {}` | **паника**, код выхода 2 (ошибка в sing-box) | service/ssmapi/server.go `NewService` | да |

### Падает только при запуске

| Ситуация | Сообщение (суть) | Где в коде | check |
|---|---|---|---|
| Каталог для `log.output` не существует или нет прав | `start logger: open …` | log/observable.go `defaultFactory.Start` | проходит, проверено |
| `dns.final` — нет такого DNS-сервера | `default DNS server not found` | dns/transport_manager.go `Start` (Initialize) | проходит, проверено |
| `route.final` — нет ни исходящего, ни эндпоинта с таким тегом (в том числе тег входящего) | `default outbound not found` | adapter/outbound/manager.go `Start` (Initialize) | проходит, проверено |
| `detour` или участник группы — несуществующий исходящий; кольцо из `detour`/групп (даже у исходящих, через которые не идёт трафик) | `dependency[X] not found for outbound[Y]`, `circular outbound dependency` | adapter/outbound/manager.go `startOutbounds` | проходит, проверено |
| `default` у `selector` не входит в его `outbounds` — **если** в `cache.db` нет сохранённого выбора существующего участника (с ним `default` не проверяется) | `default outbound not found` | protocol/group/selector.go `Start` | проходит, проверено |
| `detour` DNS-сервера — нет такого исходящего или это `direct` без настроек | `outbound detour not found`, `detour to an empty direct outbound makes no sense` | common/dialer/detour.go `InitializeDetour` из dns/transport/*.go `Start` | проходит, проверено |
| `domain_resolver` DNS-сервера — нет такого сервера или кольцо | `dependency[X] not found for server[Y]`, `circular server dependency` | dns/transport_manager.go `startTransports` | проходит, проверено |
| `route.default_http_client` — нет такого клиента (даже без удалённых rule-set); первый элемент `http_clients` не создаётся (`engine: apple` на Windows, неизвестный `engine`, версия 3 с uTLS) | `resolve default http client: …` | common/httpclient/manager.go `Start` | проходит, проверено |
| Клиент из `http_clients`, который создаётся при запуске (по умолчанию для rule-set, по ссылке из rule-set или дашборда), без `detour` и `domain_resolver`, когда DNS-серверов два и больше и нет `route.default_domain_resolver` | ERROR + `FATAL … ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true` — процесс завершается | common/httpclient/client.go `NewTransport` → common/dialer/dialer.go `NewDNSQueryOptions` | проходит, проверено |
| Удалённый rule-set: `http_client` с несуществующим тегом — **независимо от кэша**; `http_client` вместе с `download_detour` (`http_client is conflict with deprecated download_detour field`) | `initialize rule-set[i]: create rule-set http client: …` | route/rule/rule_set_remote.go `StartContext`, `resolveTransport` | проходит, проверено (оба случая) |
| Удалённый rule-set без сохранённой копии в `cache.db` (или с копией, скачанной с другого `url`) и без читаемого `initial_path`, а загрузка не удалась (`download_detour`/`detour` клиента на несуществующий исходящий, сеть, код ответа). Нечитаемый `initial_path` — только предупреждение `load initial rule-set from …`, затем попытка загрузки | `initialize rule-set[i]: initial rule-set: …` | route/rule/rule_set_remote.go `StartContext`, `fetch` | проходит, проверено |
| Правило маршрутизации ссылается на несуществующий rule-set; `preferred_by` — на несуществующий исходящий | `initialize rule[i]: rule-set not found` / `outbound not found` | route/router.go `Start` (PostStart), route/rule/rule_item_rule_set.go, route/rule/rule_item_preferred_by.go | проходит, проверено (rule-set) |
| `tls.certificate_provider` входящего — нет такого поставщика | `certificate provider not found` | common/tls/std_server.go `sharedCertificateProvider.Start` | проходит, проверено |
| Занятый порт входящего, ошибка создания TUN | ошибка входящего | protocol/*/inbound.go `Start` | проходит |
| `cache.db` занят другим процессом | ошибка примерно через 10 с | experimental/cachefile/cache.go `Start` (Initialize) | проходит ([experimental.md](experimental.md)) |
| `clash_api.external_controller` занят или неверен | `external controller listen error` (последний шаг) | experimental/clashapi/server.go `Start` (Started) | проходит ([experimental.md](experimental.md)) |
| Linux: `path` пространства имён не существует | `network namespace[<тег>]: …` | common/netns/manager_linux.go `Start` | — |

### Ломает только отдельные соединения и фоновые операции

| Ситуация | Что происходит | Где в коде | check |
|---|---|---|---|
| Действие `route` правила ссылается на несуществующий исходящий | каждое соединение, попавшее в правило, закрывается: `outbound not found` | route/route.go `routeConnection`, `routePacketConnection` | проходит, проверено |
| Исходящий правила не поддерживает TCP или UDP соединения | `TCP is not supported by outbound` и аналог | route/route.go | — |
| Действие `resolve` ссылается на несуществующий DNS-сервер | соединение: `DNS server not found` | route/route.go `actionResolve` | — |
| DNS-правило ссылается на несуществующий DNS-сервер | правило пропускается при каждом запросе, в журнале `transport not found` | dns/router.go | проходит, проверено |
| `ntp.detour` — нет такого исходящего или «пустой» `direct`; сервер недоступен | синхронизация не происходит, ошибки `initialize time` / `update time` в журнале, запуск продолжается | библиотека sing common/ntp/service.go `update` | проходит, проверено |
| `detour` HTTP-клиента (у ACME, дашборда и т. п.) на несуществующий исходящий | неудачен каждый запрос этого клиента | common/dialer/detour.go `DetourDialer.init` | проходит, проверено (для `http_clients`) |
| Удалённый rule-set с копией в `cache.db`, загрузка не удаётся | запуск идёт на старой копии, ошибки обновления в журнале (`fetch rule-set …`) | route/rule/rule_set_remote.go `updateOnce` | проходит |
| `netns` в dial/listen-полях на Windows | каждое подключение/прослушивание с ним — `get netns …` | common/listener/listener.go `ListenNetworkNamespace` | проходит, проверено (check) |
| `clash_api.external_ui_download_detour` на несуществующий исходящий | ошибка загрузки интерфейса в журнале | experimental/clashapi/server_resources.go | проходит ([experimental.md](experimental.md)) |

Исходники: файлы и функции в колонке «Где в коде»; сверх того box.go, cmd/sing-box/cmd_check.go, experimental/deprecated/stderr.go.

## Windows

- `log.output`: относительный путь — от рабочего каталога процесса. В JSON обратную косую черту надо удваивать (`"C:\\data\\box.log"`); прямая `/` тоже работает. Файл не ротируется; пока sing-box работает, файл открыт им (переименовать его, скорее всего, не удастся — так Go открывает файлы на Windows; не проверено для этого файла). При выводе в консоль, перенаправленную в файл, ANSI-коды цвета остаются, если не передан `--disable-color`.
- `ntp.write_to_system`: процесс с правами администратора переводит системные часы Windows.
- `certificate.store: system` — хранилище Windows через проверку цепочки текущего пользователя; `mozilla`/`chrome` от него не зависят.
- `network_namespaces` — только Linux (ошибка check при непустом списке); `netns` в dial/listen-полях на Windows ломает соединения.
- `http_clients[].engine: apple` на Windows падает при создании клиента.
- Особенности `route` (`auto_detect_interface`, `default_interface`, поиск процессов), TUN, redirect/tproxy, `auto_redirect` — в [route.md](route.md) и [inbounds.md](inbounds.md).

Исходники: log/log.go, log/format.go, common/certificate/store.go, common/netns/manager_stub.go, common/httpclient/apple_transport_stub.go; библиотека sing: common/ntp/time_windows.go, common/ntp/syscall_windows.go.

## Заметки для tray-sing-box

- **Проверка зависимостей приложения** (`internal/infrastructure/configfile/dependency.go`) повторяет то, что sing-box ловит только при запуске: `detour`/участники групп и их кольца; `route.final`; `rule_set` и `preferred_by` правил маршрутизации (и вложенных в логические); `download_detour` удалённого rule-set и `detour` его встроенного `http_client`; `http_client` rule-set по тегу и `route.default_http_client` (тег должен быть в `http_clients`); `detour` того элемента `http_clients`, через который rule-set действительно скачивается (по тегу или как клиент по умолчанию); `detour` DNS-серверов; `ntp.detour` при `ntp.enabled`. Уточнение по коду: несуществующий **`ntp.detour` запуск не роняет** — NTP ищет исходящий только при синхронизации, ошибка остаётся в журнале. Проверка приложения тут строже, чем нужно (вреда нет). Чего она не покрывает из таблицы [«Падает только при запуске»](#падает-только-при-запуске): `dns.final`; `detour` DNS-сервера на `direct` без настроек; `domain_resolver` DNS-сервера (нет/кольцо); `default` у `selector` вне участников (это отдельная проверка редактора, `checkSelectorDefaults`); создание первого элемента `http_clients` (`engine: apple`, версия 3 с uTLS) и `http_client` вместе с `download_detour`; `tls.certificate_provider`; удалённый rule-set без копии в кэше при недоступной загрузке (сеть, код ответа); занятые порты и создание TUN.
- `check` в 1.14.2 **отвергает** конфиг, где есть исходящий `direct` (или любой исходящий с доменным адресом сервера) и два и более DNS-серверов без `route.default_domain_resolver`/`domain_resolver` (заметка `MISSING_DOMAIN_RESOLVER`, проверено). Это важно для импорта: добавление второго DNS-сервера может сделать прежде рабочий конфиг непроходимым.
- Guard приложения (`configfile/guard.go`) не даёт добавить через приложение секции вне списка `allowedSections` (из этого файла — `certificate_providers`, `network_namespaces`, `services`, а также `$schema`), ключи `*_path`/`*_directory` (в том числе `certificate_path`, `certificate_directory_path`), `log.output`, `ntp.write_to_system: true`. Для этого файла это правильно: `certificate_path` читается повышенным процессом, `write_to_system` меняет часы Windows. Секция `http_clients` разрешена (с коммита «Config guard: shared HTTP clients allowed»): в 1.16 неявный HTTP-клиент для удалённых rule-set уберут, и конфигам с удалёнными rule-set понадобятся `http_clients`/`route.default_http_client`; ключи с путями внутри неё guard проверяет так же, как везде. Помнить: без `detour` такой клиент ходит **напрямую**, мимо VPN.
- Неизвестные ключи внутри `certificate` sing-box молча отбрасывает, а свёртка регистра в guard и проверке зависимостей совпадает с рантаймом для обычных полей (для «головных» ключей и базовых ключей `http_clients` при версии 2/3 sing-box сам отвергает другой регистр).
- Журнал: без `log.output` всё идёт в stderr, то есть в `sing-box-console.log`, с ANSI-кодами (приложение не передаёт `--disable-color`, коды вырезает при показе). С `log.output` строки в файле **без времени**, пока не задан `log.timestamp: true`. Уровень по умолчанию — `trace`.
- `sing-box check` приложения (`singboxcheck`) видит только класс «check»; всё из двух следующих таблиц проявится лишь при реальном запуске.

## Расхождения документации и кода

- `log.level`: документация не называет значение по умолчанию; в коде пустой уровень — `trace`. Синоним `warning` в документации не упомянут (есть в JSON Schema).
- `log.output`: особые значения `stdout` и `stderr` не документированы; не сказано, что каталог не создаётся и что в файле без `timestamp` нет времени вовсе.
- `log.disabled`: документация — «нет вывода после старта»; в коде журнал экземпляра не пишет ничего с момента создания, а `level` при этом не проверяется.
- `ntp.server`: документация — обязательное поле; код подставляет `time.apple.com` (но без `detour` такое имя не разрешается, см. [ntp](#ntp); по коду, не запуском).
- `ntp.write_to_system`: в документации нет, в коде и JSON Schema есть.
- `certificate`: неизвестные ключи рантайм молча отбрасывает, JSON Schema (`additionalProperties: false`) их запрещает. Что отсутствующий `certificate_directory_path` игнорируется, а отсутствующий `certificate_path` — ошибка, документация не говорит.
- `http_clients`: документация перечисляет `version: 0` в структуре, не говоря, что это 2; не сказано, что `engine` проверяется только при создании клиента, что `tag` во встроенном объекте отбрасывается и что клиент без `detour` ходит напрямую (последнее следует лишь из changelog для ACME и др.). Что первый элемент `http_clients` создаётся при запуске всегда, документация тоже не говорит.
- `network_namespaces`: «только Linux» в документации есть, но не сказано, что на других ОС конфиг с непустым списком не проходит check.
- Общий вопрос строгости: документация нигде не описывает, что ключи сопоставляются без учёта регистра, а числа в двухпроходных объектах проходят через `float64`.
- Не проверено запуском (команда `run` в этой работе не выполнялась): весь класс «запуск» и «соединение» установлен чтением кода; поведение NTP с пустым `server`; двухшаговая проверка сертификатов при `store: system` с добавленными сертификатами на Windows (логика `crypto/x509`, вне дерева sing-box); можно ли переименовать открытый sing-box файл `log.output` на Windows.

Исходники: option/options.go, option/certificate.go, option/ntp.go, option/http.go, option/netns.go, log/log.go, docs/configuration/log/index.md, docs/configuration/ntp/index.md, docs/configuration/certificate/index.md, docs/configuration/shared/http-client.md, docs/configuration/network-namespace/index.md, docs/schema.json.
