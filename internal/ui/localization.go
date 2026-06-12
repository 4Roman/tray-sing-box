package ui

// Menu strings in Russian
const (
	StatusStopped = "Остановлен"
	StatusRunning = "Запущен"
	StatusTooltip = "Текущий статус VPN"

	ActionStart   = "Включить"
	ActionStop    = "Выключить"
	ActionTooltip = "Включить/выключить VPN"

	AutostartTitle   = "Автозапуск"
	AutostartTooltip = "Автозапуск при старте Windows"

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

	DPITitle           = "Обход DPI (zapret)"
	DPITooltip         = "Подключаться к VPN-серверу через zapret в Docker для обхода DPI"
	DPIDoneTitle       = "Обход DPI"
	DPIErrorTitle      = "Ошибка обхода DPI"
	DPIEnabledMsg      = "Обход DPI включён: сервер «%s» подключается через zapret"
	DPIDisabledMsg     = "Обход DPI выключен"
	DPIRestartedSuffix = ", VPN перезапущен"

	VPNErrorTitle = "Ошибка VPN"

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
