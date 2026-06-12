package app

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/getlantern/systray"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/ui"
)

// AutostartManager interface for managing autostart
type AutostartManager interface {
	IsEnabled() bool
	Enable() error
	Disable() error
}

// TextSource produces text to import an outbound from (clipboard, screen QR)
type TextSource func() (string, error)

// ImportSources groups the available outbound import sources
type ImportSources struct {
	Clipboard TextSource
	ScreenQR  TextSource
}

// SettingsOpener opens the settings interface
type SettingsOpener interface {
	Open() error
}

// Application coordinates all components
type Application struct {
	vpnService       *domain.VPNService
	importService    *domain.ImportService
	updateService    *domain.UpdateService
	dpiService       *domain.DPIBypassService
	importSources    ImportSources
	settingsUI       SettingsOpener
	autostartManager AutostartManager
	trayUI           *ui.TrayUI

	// opMu serializes long-running operations (import, binary update) so
	// they cannot interleave config and binary modifications
	opMu sync.Mutex
}

// New creates a new application instance
func New(vpnService *domain.VPNService, importService *domain.ImportService, updateService *domain.UpdateService, dpiService *domain.DPIBypassService, importSources ImportSources, settingsUI SettingsOpener, autostartManager AutostartManager) *Application {
	return &Application{
		vpnService:       vpnService,
		importService:    importService,
		updateService:    updateService,
		dpiService:       dpiService,
		importSources:    importSources,
		settingsUI:       settingsUI,
		autostartManager: autostartManager,
	}
}

// OnReady is called when the system tray is ready
func (a *Application) OnReady(trayIcon []byte) {
	// Initialize tray UI
	a.trayUI = ui.New(trayIcon)

	// Update autostart checkbox. If autostart is enabled, re-register the
	// scheduled task so an entry created by an older version is refreshed
	// with the current task definition and exe path.
	autostartEnabled := a.autostartManager.IsEnabled()
	if autostartEnabled {
		if err := a.autostartManager.Enable(); err != nil {
			log.Printf("Warning: failed to refresh autostart task: %v", err)
		}
	}
	a.trayUI.UpdateAutostart(autostartEnabled)

	// Restore last VPN state
	if err := a.vpnService.RestoreLastState(); err != nil {
		log.Printf("Warning: failed to restore VPN state: %v", err)
	}

	// Update UI with current status
	a.trayUI.UpdateStatus(a.vpnService.GetStatus())

	// Reflect the DPI-bypass state in the checkbox. Docker inspect can take a
	// few hundred ms, so do it off the tray-startup path.
	if a.dpiService != nil {
		go func() {
			status, err := a.dpiService.Status()
			if err != nil {
				log.Printf("Warning: failed to read DPI bypass status: %v", err)
				return
			}
			a.trayUI.UpdateDPI(status.ChainActive)
		}()
	}

	// Start monitoring
	a.vpnService.StartMonitoring()

	// Start event loop
	go a.eventLoop()
}

// OnExit is called when the application is about to exit
func (a *Application) OnExit() {
	// The stored VPN state is the user's intent, saved on every explicit
	// Start/Stop. It must not be overwritten here: during Windows shutdown
	// sing-box is killed before this app exits, so saving the observed state
	// would record "stopped" and break auto-start restore on next boot.
	log.Println("Application exiting")
}

// eventLoop handles UI events
func (a *Application) eventLoop() {
	for {
		select {
		case <-a.trayUI.ToggleCh:
			a.handleToggleVPN()
		case <-a.trayUI.ImportClipboardCh:
			go a.handleImport(a.importSources.Clipboard)
		case <-a.trayUI.ImportQRCh:
			go a.handleImport(a.importSources.ScreenQR)
		case <-a.trayUI.SettingsCh:
			go a.handleOpenSettings()
		case <-a.trayUI.UpdateCh:
			go a.handleUpdate()
		case <-a.trayUI.DPICh:
			go a.handleToggleDPI()
		case <-a.trayUI.AutostartCh:
			a.handleToggleAutostart()
		case <-a.trayUI.QuitCh:
			systray.Quit()
			return
		case status := <-a.vpnService.StatusChangeCh():
			a.trayUI.UpdateStatus(status)
		}
	}
}

// handleToggleVPN handles VPN toggle action
func (a *Application) handleToggleVPN() {
	if err := a.vpnService.Toggle(); err != nil {
		log.Printf("Error toggling VPN: %v", err)
		// Popup from a goroutine: it blocks until dismissed and must not
		// freeze the event loop
		go ui.ShowError(ui.VPNErrorTitle, err.Error())
		return
	}

	// Update UI immediately
	a.trayUI.UpdateStatus(a.vpnService.GetStatus())
}

// handleOpenSettings opens the settings web interface in the browser
func (a *Application) handleOpenSettings() {
	if a.settingsUI == nil {
		return
	}
	if err := a.settingsUI.Open(); err != nil {
		log.Printf("Failed to open settings: %v", err)
		ui.ShowError(ui.VPNErrorTitle, err.Error())
	}
}

// handleImport imports an outbound from the given text source and reports
// the result to the user. Runs outside the event loop: the message box
// blocks until dismissed and must not freeze menu handling.
func (a *Application) handleImport(source TextSource) {
	a.opMu.Lock()
	defer a.opMu.Unlock()

	if source == nil {
		return
	}

	text, err := source()
	if err != nil {
		log.Printf("Import: failed to read source: %v", err)
		ui.ShowError(ui.ImportErrorTitle, err.Error())
		return
	}

	result, err := a.importService.ImportFromText(text)
	if err != nil {
		log.Printf("Import failed: %v", err)
		ui.ShowError(ui.ImportErrorTitle, err.Error())
		return
	}

	a.trayUI.UpdateStatus(a.vpnService.GetStatus())

	ui.ShowInfo(ui.ImportSuccessTitle, importMessage(result))
}

// importMessage formats the popup text for a finished import
func importMessage(result *domain.ImportResult) string {
	if len(result.Tags) == 1 {
		if result.Restarted {
			return fmt.Sprintf(ui.ImportSuccessRestarted, result.Tags[0])
		}
		return fmt.Sprintf(ui.ImportSuccessAdded, result.Tags[0])
	}
	list := strings.Join(result.Tags, "\n")
	if result.Restarted {
		return fmt.Sprintf(ui.ImportManyRestarted, len(result.Tags), list)
	}
	return fmt.Sprintf(ui.ImportManyAdded, len(result.Tags), list)
}

// handleUpdate downloads and installs the latest sing-box release.
// Runs outside the event loop: the download takes a while and the message
// box blocks until dismissed.
func (a *Application) handleUpdate() {
	a.opMu.Lock()
	defer a.opMu.Unlock()

	result, err := a.updateService.Update()
	if err != nil {
		log.Printf("Update failed: %v", err)
		ui.ShowError(ui.UpdateErrorTitle, err.Error())
		return
	}

	a.trayUI.UpdateStatus(a.vpnService.GetStatus())
	ui.ShowInfo(ui.UpdateDoneTitle, updateMessage(result))
}

// updateMessage formats the popup text for a finished update check
func updateMessage(result *domain.UpdateResult) string {
	if !result.Updated {
		return fmt.Sprintf(ui.UpdateUpToDate, result.CurrentVersion, result.LatestVersion)
	}
	message := fmt.Sprintf(ui.UpdateInstalled, result.CurrentVersion, result.LatestVersion)
	if result.CurrentVersion == "" {
		message = fmt.Sprintf(ui.UpdateFreshInstall, result.LatestVersion)
	}
	if result.Restarted {
		message += ui.UpdateRestarted
	}
	return message
}

// handleToggleDPI toggles the zapret DPI-bypass chain on the active server.
// Runs outside the event loop: starting the container can take a while (image
// pull) and the result message box blocks until dismissed.
func (a *Application) handleToggleDPI() {
	a.opMu.Lock()
	defer a.opMu.Unlock()

	if a.dpiService == nil {
		return
	}

	status, err := a.dpiService.ToggleChain()
	if err != nil {
		log.Printf("DPI bypass toggle failed: %v", err)
		ui.ShowError(ui.DPIErrorTitle, err.Error())
		// Re-sync the checkbox with the real state after a failed toggle
		if s, sErr := a.dpiService.Status(); sErr == nil {
			a.trayUI.UpdateDPI(s.ChainActive)
		}
		return
	}

	a.trayUI.UpdateDPI(status.ChainActive)
	a.trayUI.UpdateStatus(a.vpnService.GetStatus())
	ui.ShowInfo(ui.DPIDoneTitle, dpiMessage(status))
}

// dpiMessage formats the popup text for a finished DPI-bypass toggle
func dpiMessage(status *domain.DPIBypassStatus) string {
	var message string
	if status.ChainActive {
		message = fmt.Sprintf(ui.DPIEnabledMsg, status.ChainTarget)
	} else {
		message = ui.DPIDisabledMsg
	}
	if status.Restarted {
		message += ui.DPIRestartedSuffix
	}
	return message
}

// handleToggleAutostart handles autostart toggle action
func (a *Application) handleToggleAutostart() {
	if a.autostartManager.IsEnabled() {
		if err := a.autostartManager.Disable(); err != nil {
			log.Printf("Error disabling autostart: %v", err)
			return
		}
		a.trayUI.UpdateAutostart(false)
	} else {
		if err := a.autostartManager.Enable(); err != nil {
			log.Printf("Error enabling autostart: %v", err)
			return
		}
		a.trayUI.UpdateAutostart(true)
	}
}
