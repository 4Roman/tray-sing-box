package ui

import (
	"github.com/getlantern/systray"

	"tray-sing-box/internal/domain"
)

// TrayUI manages the system tray interface
type TrayUI struct {
	statusItem          *systray.MenuItem
	toggleItem          *systray.MenuItem
	importClipboardItem *systray.MenuItem
	importQRItem        *systray.MenuItem
	settingsItem        *systray.MenuItem
	updateItem          *systray.MenuItem
	dpiItem             *systray.MenuItem
	autostartItem       *systray.MenuItem
	quitItem            *systray.MenuItem

	// Channels for events
	ToggleCh          chan bool
	ImportClipboardCh chan bool
	ImportQRCh        chan bool
	SettingsCh        chan bool
	UpdateCh          chan bool
	DPICh             chan bool
	AutostartCh       chan bool
	QuitCh            chan bool
}

// New creates a new tray UI instance
func New(trayIcon []byte) *TrayUI {
	ui := &TrayUI{
		ToggleCh:          make(chan bool),
		ImportClipboardCh: make(chan bool),
		ImportQRCh:        make(chan bool),
		SettingsCh:        make(chan bool),
		UpdateCh:          make(chan bool),
		DPICh:             make(chan bool),
		AutostartCh:       make(chan bool),
		QuitCh:            make(chan bool),
	}

	// Set the application icon (.ico only on Windows; skip if loading failed)
	if len(trayIcon) > 0 {
		systray.SetIcon(trayIcon)
	}
	systray.SetTitle(TrayTitle)
	systray.SetTooltip(TrayTooltip)

	// Create menu items
	ui.statusItem = systray.AddMenuItem(StatusStopped, StatusTooltip)

	systray.AddSeparator()

	ui.toggleItem = systray.AddMenuItem(ActionStart, ActionTooltip)

	systray.AddSeparator()

	ui.importClipboardItem = systray.AddMenuItem(ImportClipboardTitle, ImportClipboardTooltip)
	ui.importQRItem = systray.AddMenuItem(ImportQRTitle, ImportQRTooltip)
	ui.settingsItem = systray.AddMenuItem(SettingsTitle, SettingsTooltip)
	ui.updateItem = systray.AddMenuItem(UpdateTitle, UpdateTooltip)

	systray.AddSeparator()

	ui.dpiItem = systray.AddMenuItemCheckbox(DPITitle, DPITooltip, false)
	ui.autostartItem = systray.AddMenuItemCheckbox(AutostartTitle, AutostartTooltip, false)

	systray.AddSeparator()

	ui.quitItem = systray.AddMenuItem(QuitTitle, QuitTooltip)

	// Start event listeners
	go ui.listenEvents()

	return ui
}

// listenEvents listens for menu item clicks
func (t *TrayUI) listenEvents() {
	for {
		select {
		case <-t.toggleItem.ClickedCh:
			t.ToggleCh <- true
		case <-t.importClipboardItem.ClickedCh:
			t.ImportClipboardCh <- true
		case <-t.importQRItem.ClickedCh:
			t.ImportQRCh <- true
		case <-t.settingsItem.ClickedCh:
			t.SettingsCh <- true
		case <-t.updateItem.ClickedCh:
			t.UpdateCh <- true
		case <-t.dpiItem.ClickedCh:
			t.DPICh <- true
		case <-t.autostartItem.ClickedCh:
			t.AutostartCh <- true
		case <-t.quitItem.ClickedCh:
			t.QuitCh <- true
			return
		}
	}
}

// UpdateStatus updates the VPN status display
func (t *TrayUI) UpdateStatus(status domain.VPNStatus) {
	if status.IsRunning() {
		t.statusItem.SetTitle(StatusRunning)
		t.toggleItem.SetTitle(ActionStop)
	} else {
		t.statusItem.SetTitle(StatusStopped)
		t.toggleItem.SetTitle(ActionStart)
	}
}

// UpdateDPI updates the DPI-bypass checkbox
func (t *TrayUI) UpdateDPI(enabled bool) {
	if enabled {
		t.dpiItem.Check()
	} else {
		t.dpiItem.Uncheck()
	}
}

// UpdateAutostart updates the autostart checkbox
func (t *TrayUI) UpdateAutostart(enabled bool) {
	if enabled {
		t.autostartItem.Check()
	} else {
		t.autostartItem.Uncheck()
	}
}
