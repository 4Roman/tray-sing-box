package ui

import (
	"sync"

	"github.com/getlantern/systray"

	"tray-sing-box/internal/domain"
)

// TrayUI manages the system tray interface
type TrayUI struct {
	// mu guards the displayed state: Update* are called from several
	// goroutines (event loop, import/update handlers, connectivity loop)
	mu sync.Mutex

	iconOn      []byte // tray.ico — VPN running
	iconOff     []byte // tray-off.ico — VPN stopped (grayscale)
	iconRunning bool   // which icon is currently shown
	running     bool   // last shown VPN state
	offerStop   bool   // the toggle item currently reads "stop"

	autostartShown bool // state of the autostart checkbox
	connBad        bool // a connectivity verdict exists and it is negative

	statusItem          *systray.MenuItem
	toggleItem          *systray.MenuItem
	importClipboardItem *systray.MenuItem
	importQRItem        *systray.MenuItem
	subsUpdateItem      *systray.MenuItem
	settingsItem        *systray.MenuItem
	updateItem          *systray.MenuItem
	appUpdateItem       *systray.MenuItem
	dpiItem             *systray.MenuItem
	autostartItem       *systray.MenuItem
	quitItem            *systray.MenuItem

	// Channels for events. ToggleCh carries the state the user asked for
	// (true = start): the opposite of what the menu showed when it was
	// clicked. A blind "toggle" would do the reverse of what the user saw
	// whenever the display is stale (startup restore, a crash not yet noticed).
	// AutostartCh works the same way (true = enable).
	ToggleCh          chan bool
	ImportClipboardCh chan bool
	ImportQRCh        chan bool
	SubsUpdateCh      chan bool
	SettingsCh        chan bool
	UpdateCh          chan bool
	AppUpdateCh       chan bool
	DPICh             chan bool
	AutostartCh       chan bool
	QuitCh            chan bool
}

// New creates a new tray UI instance. iconOn is shown while the VPN is
// running, iconOff while it is stopped; either may be nil (that state then
// keeps whatever icon is already set).
func New(iconOn, iconOff []byte) *TrayUI {
	ui := &TrayUI{
		iconOn:            iconOn,
		iconOff:           iconOff,
		ToggleCh:          make(chan bool),
		ImportClipboardCh: make(chan bool),
		ImportQRCh:        make(chan bool),
		SubsUpdateCh:      make(chan bool),
		SettingsCh:        make(chan bool),
		UpdateCh:          make(chan bool),
		AppUpdateCh:       make(chan bool),
		DPICh:             make(chan bool),
		AutostartCh:       make(chan bool),
		QuitCh:            make(chan bool),
	}

	// Set the application icon (.ico only on Windows; skip if loading failed).
	// The VPN state is unknown yet, start with the "stopped" icon —
	// UpdateStatus corrects it right after the state is restored.
	if len(iconOff) > 0 {
		systray.SetIcon(iconOff)
	} else if len(iconOn) > 0 {
		systray.SetIcon(iconOn)
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
	ui.subsUpdateItem = systray.AddMenuItem(SubsUpdateTitle, SubsUpdateTooltip)
	ui.settingsItem = systray.AddMenuItem(SettingsTitle, SettingsTooltip)
	ui.updateItem = systray.AddMenuItem(UpdateTitle, UpdateTooltip)
	ui.appUpdateItem = systray.AddMenuItem(AppUpdateTitle, AppUpdateTooltip)

	systray.AddSeparator()

	ui.dpiItem = systray.AddMenuItemCheckbox(DPITitle, DPITooltip, false)
	ui.autostartItem = systray.AddMenuItemCheckbox(AutostartTitle, AutostartTooltip, false)
	// The real state arrives asynchronously (UpdateAutostart). Until then the
	// unchecked box would be a lie, and a click meant to enable autostart
	// would delete an existing task.
	ui.autostartItem.Disable()

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
			t.mu.Lock()
			wantRunning := !t.offerStop
			t.mu.Unlock()
			t.ToggleCh <- wantRunning
		case <-t.importClipboardItem.ClickedCh:
			t.ImportClipboardCh <- true
		case <-t.importQRItem.ClickedCh:
			t.ImportQRCh <- true
		case <-t.subsUpdateItem.ClickedCh:
			t.SubsUpdateCh <- true
		case <-t.settingsItem.ClickedCh:
			t.SettingsCh <- true
		case <-t.updateItem.ClickedCh:
			t.UpdateCh <- true
		case <-t.appUpdateItem.ClickedCh:
			t.AppUpdateCh <- true
		case <-t.dpiItem.ClickedCh:
			t.DPICh <- true
		case <-t.autostartItem.ClickedCh:
			// The state the user asked for, and no further clicks until the
			// app has applied it (UpdateAutostart re-enables the item)
			t.mu.Lock()
			wantEnabled := !t.autostartShown
			t.mu.Unlock()
			t.autostartItem.Disable()
			t.AutostartCh <- wantEnabled
		case <-t.quitItem.ClickedCh:
			t.QuitCh <- true
			return
		}
	}
}

// UpdateStatus updates the VPN status display: menu item texts and the tray
// icon (color = running, grayscale = stopped). The icon is only re-set when
// the state actually changes — systray.SetIcon writes a temp file each call.
func (t *TrayUI) UpdateStatus(status domain.VPNStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.running = status.IsRunning()
	// While the app is still bringing the VPN up the toggle offers "stop":
	// that is how the user calls the attempts off
	t.offerStop = t.running || status.IsStarting()

	if t.running {
		t.renderRunningTitle()
		if !t.iconRunning && len(t.iconOn) > 0 {
			systray.SetIcon(t.iconOn)
			t.iconRunning = true
		}
	} else {
		if status.IsStarting() {
			t.statusItem.SetTitle(StatusStarting)
		} else {
			t.statusItem.SetTitle(StatusStopped)
		}
		if t.iconRunning && len(t.iconOff) > 0 {
			systray.SetIcon(t.iconOff)
			t.iconRunning = false
		}
	}

	if t.offerStop {
		t.toggleItem.SetTitle(ActionStop)
	} else {
		t.toggleItem.SetTitle(ActionStart)
	}
}

// HideAppUpdate removes the "update the application" item (self-update is
// not configured in this build)
func (t *TrayUI) HideAppUpdate() {
	t.appUpdateItem.Hide()
}

// UpdateConnectivity reflects the latest connectivity verdict in the status
// text; bad = a verdict exists and traffic does not flow
func (t *TrayUI) UpdateConnectivity(bad bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connBad == bad {
		return
	}
	t.connBad = bad
	if t.running {
		t.renderRunningTitle()
	}
}

func (t *TrayUI) renderRunningTitle() {
	if t.connBad {
		t.statusItem.SetTitle(StatusRunningNoNet)
	} else {
		t.statusItem.SetTitle(StatusRunning)
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
	t.mu.Lock()
	t.autostartShown = enabled
	t.mu.Unlock()

	if enabled {
		t.autostartItem.Check()
	} else {
		t.autostartItem.Uncheck()
	}
	t.autostartItem.Enable()
}
