package ui

// Menu strings in Russian
const (
	StatusStopped      = "Остановлен"
	StatusRunning      = "Запущен"
	StatusRunningNoNet = "Запущен (нет связи)"
	StatusStarting     = "Запускается…"
	StatusTooltip      = "Текущий статус VPN"

	ActionStart   = "Включить"
	ActionStop    = "Выключить"
	ActionTooltip = "Включить/выключить VPN"

	AutostartTitle      = "Автозапуск"
	AutostartTooltip    = "Автозапуск при старте Windows"
	AutostartErrorTitle = "Ошибка автозапуска"

	SettingsTitle   = "Настройки"
	SettingsTooltip = "Открыть настройки sing-box в браузере"

	UpdateTitle        = "Обновить sing-box"
	UpdateTooltip      = "Скачать последний релиз sing-box с GitHub"
	UpdateDoneTitle    = "Обновление sing-box"
	UpdateErrorTitle   = "Ошибка обновления"
	UpdateUpToDate     = "Обновление не требуется: установлена версия %s, последний релиз %s"
	UpdateInstalled    = "sing-box обновлён: %s → %s"
	UpdateFreshInstall = "Установлен sing-box %s"
	UpdateRestarted    = ", VPN перезапущен"

	ImportClipboardTitle   = "Импорт из буфера обмена"
	ImportClipboardTooltip = "Импортировать сервер из ссылки в буфере обмена"
	ImportQRTitle          = "Импорт QR с экрана"
	ImportQRTooltip        = "Найти QR-код на экране и импортировать сервер"

	SubsUpdateTitle     = "Обновить подписки"
	SubsUpdateTooltip   = "Скачать заново все сохранённые подписки"
	SubsUpdateDoneTitle = "Обновление подписок"
	SubsAddedTitle      = "Подписка добавлена"
	SubsErrorTitle      = "Ошибка подписки"
	SubsNoneMsg         = "Нет сохранённых подписок.\n\nЧтобы добавить подписку, скопируйте её URL и выберите «Импорт из буфера обмена», либо откройте «Настройки»."
	SubsLineOK          = "%s — серверов: %d"
	SubsLineAdded       = ", новых: %d"
	SubsLineRemoved     = ", удалено: %d"
	SubsLineError       = "%s — ошибка: %v"
	SubsRestartedSuffix = "\n\nVPN перезапущен"

	DPITitle           = "Обход DPI (zapret)"
	DPITooltip         = "Подключаться к VPN-серверу через zapret в Docker для обхода DPI"
	DPIDoneTitle       = "Обход DPI"
	DPIErrorTitle      = "Ошибка обхода DPI"
	DPIEnabledMsg      = "Обход DPI включён: сервер «%s» подключается через zapret"
	DPIDisabledMsg     = "Обход DPI выключен"
	DPIRestartedSuffix = ", VPN перезапущен"

	AppUpdateTitle        = "Обновить приложение"
	AppUpdateTooltip      = "Проверить, есть ли новая версия Sing-Box VPN Tray Manager, и установить её"
	AppUpdateDoneTitle    = "Обновление приложения"
	AppUpdateErrorTitle   = "Ошибка обновления приложения"
	AppUpdateUpToDate     = "Обновление не требуется: установлена версия %s, последний релиз %s"
	AppUpdateInstalledMsg = "Установлена версия %s (была %s). Перезапустить приложение сейчас? VPN при этом не прерывается."
	AppUpdateAvailableMsg = "Доступна версия %s (установлена %s).\n\n%s\n\nОбновить сейчас? VPN при этом не прерывается."

	AlreadyRunningTitle = "Sing-Box VPN"
	AlreadyRunningMsg   = "Приложение уже запущено — иконка находится в области уведомлений (возможно, среди скрытых значков)."

	VPNErrorTitle = "Ошибка VPN"
	// Appended to the "auto-restart gave up" error; "yes" records the stop
	VPNGiveUpQuestion = "\n\nВыключить VPN, чтобы приложение больше не пыталось его запустить (в том числе при следующем входе в Windows)?"

	ImportSuccessTitle     = "Импорт выполнен"
	ImportErrorTitle       = "Ошибка импорта"
	ImportSuccessRestarted = "Сервер «%s» импортирован, VPN перезапущен"
	ImportSuccessAdded     = "Сервер «%s» импортирован"
	ImportManyRestarted    = "Импортировано серверов: %d, VPN перезапущен\n\n%s"
	ImportManyAdded        = "Импортировано серверов: %d\n\n%s"

	QuitTitle   = "Выход"
	QuitTooltip = "Выйти из программы"

	TrayTitle   = "4R VPN"
	TrayTooltip = "Sing-Box VPN Manager"
)
