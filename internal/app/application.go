package app

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/systray"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/process"
	"tray-sing-box/internal/ui"
)

// AutostartManager interface for managing autostart
type AutostartManager interface {
	IsEnabled() bool
	Enable() error
	Disable() error
	// RefreshIfOutdated re-registers an enabled autostart entry that belongs
	// to this exe but was created by an older version
	RefreshIfOutdated() error
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
	vpnService          *domain.VPNService
	importService       *domain.ImportService
	updateService       *domain.UpdateService
	appUpdate           *domain.AppUpdateService // nil: self-update not configured
	dpiService          *domain.DPIBypassService
	subscriptionService *domain.SubscriptionService
	connectivity        *domain.ConnectivityService
	importSources       ImportSources
	settingsUI          SettingsOpener
	autostartManager    AutostartManager
	trayUI              *ui.TrayUI

	// opMu serializes long-running operations (import, binary update) so
	// they cannot interleave config and binary modifications. Shared with
	// the web UI, see OpLock.
	opMu sync.Mutex

	// trayReady is set once systray.Run has called OnReady: before that
	// systray.Quit is a no-op that would also swallow every later Quit
	trayReady atomic.Bool

	// toggleReq hands the state the user asked for to toggleWorker. One slot,
	// latest wins: starting/stopping sing-box takes seconds, and doing it on
	// the event loop froze the whole menu meanwhile (systray silently drops
	// the clicks nobody is ready to receive).
	toggleReq chan bool

	// autostartMu serializes the start-time autostart refresh with the
	// user's checkbox clicks
	autostartMu sync.Mutex
}

// New creates a new application instance
func New(vpnService *domain.VPNService, importService *domain.ImportService, updateService *domain.UpdateService, dpiService *domain.DPIBypassService, subscriptionService *domain.SubscriptionService, connectivity *domain.ConnectivityService, importSources ImportSources, settingsUI SettingsOpener, autostartManager AutostartManager) *Application {
	return &Application{
		vpnService:          vpnService,
		importService:       importService,
		updateService:       updateService,
		dpiService:          dpiService,
		subscriptionService: subscriptionService,
		connectivity:        connectivity,
		importSources:       importSources,
		settingsUI:          settingsUI,
		autostartManager:    autostartManager,
		toggleReq:           make(chan bool, 1),
	}
}

// SetAppUpdater enables self-update of the application (before OnReady)
func (a *Application) SetAppUpdater(svc *domain.AppUpdateService) {
	a.appUpdate = svc
}

// OpLock is the mutex that serializes the long operations. The web UI takes
// the same one for every handler that changes the config or the binary: a
// config save from the browser and a binary update from the tray must not
// interleave. Result popups are shown after it is released (runLocked).
func (a *Application) OpLock() *sync.Mutex {
	return &a.opMu
}

// StartBackground restores the last VPN state and starts the crash monitor.
// Called from main before the tray exists: bringing the VPN up at boot must
// not wait for the shell (WaitForExplorer can take minutes) and must not
// depend on the tray icon being created at all.
func (a *Application) StartBackground() {
	// `tray-sing-box.exe --quit` (the installer before replacing the exe).
	// Listening from here, not from OnReady: at logon the tray may be minutes
	// away (WaitForExplorer), and an installer asking meanwhile must not be
	// told "no instance" while this one holds the mutex and the exe.
	if err := process.WatchQuitRequest(a.RequestQuit); err != nil {
		log.Printf("Warning: quit requests from other processes will not work: %v", err)
	}

	// Surface an exhausted auto-restart loop to the user (popup from a
	// goroutine: it blocks until dismissed and must not stall the monitor).
	// Set before the monitor goroutine exists — it reads the field unlocked.
	//
	// The popup offers to turn the VPN off: while sing-box cannot start the
	// menu only shows "start", so without it the user could never record
	// "stopped" and the whole retry loop + popup would repeat on every boot.
	a.vpnService.OnAutoRestartFailed = func(err error) {
		go func() {
			if !ui.AskErrorYesNo(ui.VPNErrorTitle, err.Error()+ui.VPNGiveUpQuestion) {
				return
			}
			// The popup may have been sitting there for hours
			if a.vpnService.GetStatus().IsRunning() {
				return
			}
			if err := a.vpnService.Stop(); err != nil {
				log.Printf("Failed to turn the VPN off after the auto-restart gave up: %v", err)
			}
		}()
	}

	go func() {
		// Strictly restore first, monitor second: running together they
		// would both start sing-box and burn the auto-restart budget on
		// ordinary boot-time start failures. A failed restore is not final —
		// the intent still says "running", so the monitor keeps trying with a
		// backoff and reports through OnAutoRestartFailed.
		if err := a.vpnService.RestoreLastState(); err != nil {
			log.Printf("Warning: failed to restore VPN state: %v", err)
		}
		a.vpnService.StartMonitoring()
	}()

	// Heal an autostart task registered by an older version. Also independent
	// of the tray: if the icon never comes up, the next logon must still use
	// the current task definition. schtasks is slow right after logon, hence
	// the goroutine.
	go func() {
		a.autostartMu.Lock()
		defer a.autostartMu.Unlock()
		if err := a.autostartManager.RefreshIfOutdated(); err != nil {
			log.Printf("Warning: failed to refresh autostart task: %v", err)
		}
	}()
}

// OnReady is called when the system tray is ready
func (a *Application) OnReady(trayIcon, trayIconOff []byte) {
	a.trayReady.Store(true)

	// Initialize tray UI
	a.trayUI = ui.New(trayIcon, trayIconOff)

	// Handle menu clicks from the very start: the state restore may still be
	// running in the background (see StartBackground)
	go a.toggleWorker()
	go a.eventLoop()

	// Update UI with current status
	a.trayUI.UpdateStatus(a.vpnService.GetStatus())

	// Autostart checkbox (disabled until this sets it). Under autostartMu, so
	// it waits for a task refresh that StartBackground may still be running.
	go func() {
		a.autostartMu.Lock()
		defer a.autostartMu.Unlock()
		a.trayUI.UpdateAutostart(a.autostartManager.IsEnabled())
	}()

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

	// Periodic subscription auto-refresh
	if a.subscriptionService != nil {
		go a.subscriptionLoop()
	}

	// Periodic connectivity verification while the VPN runs
	if a.connectivity != nil {
		go a.connectivityLoop()
	}

	// Self-update: menu item only when configured, plus a daily check
	if a.appUpdate == nil {
		a.trayUI.HideAppUpdate()
	} else {
		go a.appUpdateLoop()
	}
}

// appUpdateLoop checks for a new release of the application shortly after
// start and then daily. A development build is never nagged (it has no
// comparable version); a release build gets one yes/no popup per version.
func (a *Application) appUpdateLoop() {
	if !domain.IsReleaseVersion(config.Version) {
		return
	}
	time.Sleep(config.AppUpdateStartupDelay * time.Second)
	offered := ""
	for {
		result, err := a.appUpdate.Check()
		if err != nil {
			log.Printf("App update check failed: %v", err)
		} else if result.Available && result.LatestVersion != offered {
			offered = result.LatestVersion
			log.Printf("App update available: %s (running %s)", result.LatestVersion, result.CurrentVersion)
			if ui.AskYesNo(ui.AppUpdateDoneTitle, fmt.Sprintf(ui.AppUpdateAvailableMsg, ui.ShowVersion(result.LatestVersion), ui.ShowVersion(result.CurrentVersion), ui.PlainNotes(result.Notes))) {
				a.handleAppUpdate()
			}
		}
		time.Sleep(config.AppUpdateCheckHours * time.Hour)
	}
}

// handleAppUpdate installs the latest release of the application and, with
// the user's consent, relaunches into it. Runs outside the event loop.
func (a *Application) handleAppUpdate() {
	if a.appUpdate == nil {
		return
	}

	var installed *domain.AppUpdateResult
	a.runLocked(func() popup {
		result, err := a.appUpdate.Update()
		if err != nil {
			log.Printf("App update failed: %v", err)
			return errorPopup(ui.AppUpdateErrorTitle, err)
		}
		if !result.Installed {
			return infoPopup(ui.AppUpdateDoneTitle, fmt.Sprintf(ui.AppUpdateUpToDate, ui.ShowVersion(result.CurrentVersion), ui.ShowVersion(result.LatestVersion)))
		}
		installed = result
		return nil
	})
	if installed == nil {
		return
	}

	// The exe on disk is the new version; it takes over once this process
	// exits. sing-box is not touched — the new instance adopts it.
	if ui.AskYesNo(ui.AppUpdateDoneTitle, fmt.Sprintf(ui.AppUpdateInstalledMsg, ui.ShowVersion(installed.LatestVersion), ui.ShowVersion(installed.CurrentVersion))) {
		a.RelaunchAfterUpdate()
	}
}

// RequestQuit exits the application once a running long operation (save,
// binary swap) has finished rather than dying halfway; off the caller's
// goroutine, so the event loop keeps serving meanwhile. Used by the tray
// "Выход" item and by another process (`--quit`, the installer). sing-box
// keeps running by design.
func (a *Application) RequestQuit() {
	go func() {
		a.opMu.Lock()
		if !a.trayReady.Load() {
			// main is still waiting for the shell (or has not reached
			// systray.Run): leave directly. Nothing that must not be cut
			// short runs before the tray — long operations start from the
			// tray or from the web UI it opens; a sing-box being started by
			// the restore keeps running and is adopted by the next instance.
			log.Println("Quitting before the tray is up")
			os.Exit(0)
		}
		log.Println("Quitting")
		systray.Quit()
	}()
}

// RelaunchAfterUpdate starts the installed version and quits this one. It
// waits for a running long operation first: main returning would kill a
// sing-box binary swap or a config save halfway (neither is atomic) and the
// new instance would then find a truncated sing-box.exe or config.json. The
// lock is released only by the process exit, so nothing new can start.
func (a *Application) RelaunchAfterUpdate() {
	a.opMu.Lock()
	if err := a.appUpdate.Relaunch(); err != nil {
		a.opMu.Unlock()
		log.Printf("App update: %v", err)
		go ui.ShowError(ui.AppUpdateErrorTitle, err.Error())
		return
	}
	log.Printf("App update: relaunching into the new version")
	systray.Quit()
}

// subscriptionLoop refreshes the saved subscriptions shortly after start and
// then on a fixed interval. Results are logged; a problem is shown once (see
// autoRefreshSubscriptions).
func (a *Application) subscriptionLoop() {
	time.Sleep(config.SubscriptionStartupDelay * time.Second)
	for {
		a.autoRefreshSubscriptions()
		time.Sleep(config.SubscriptionRefreshHours * time.Hour)
	}
}

// autoRefreshSubscriptions refreshes every subscription. A problem the user
// has not been told about yet (SubscriptionUpdate.NewProblem: a failure, or
// nodes left out, that differs from what the previous refresh found) gets
// one popup; the same problem again does not — an unattended refresh must
// not nag every few hours, but a subscription that silently stopped updating
// (one odd node refused, the provider's link gone) would leave the user on
// servers the provider has long rotated out.
func (a *Application) autoRefreshSubscriptions() {
	subs, err := a.subscriptionService.List()
	if err != nil {
		log.Printf("Subscription auto-refresh: failed to list: %v", err)
		return
	}
	if len(subs) == 0 {
		return
	}

	a.runLocked(func() popup {
		result, err := a.subscriptionService.UpdateAll()
		if err != nil {
			log.Printf("Subscription auto-refresh failed: %v", err)
		}
		if result != nil {
			for _, u := range result.Updates {
				if u.Err != nil {
					log.Printf("Subscription auto-refresh: %s: %v", domain.RedactURL(u.URL), u.Err)
				}
			}
		}
		if a.trayUI != nil {
			a.trayUI.UpdateStatus(a.vpnService.GetStatus())
		}
		report := autoRefreshText(result, err)
		if report == "" {
			return nil
		}
		// From a goroutine: the loop must not wait for the popup to be
		// dismissed (it may sit there for hours)
		return func() { go ui.ShowError(ui.SubsAutoTitle, report) }
	})
}

// autoRefreshText is the popup text of an unattended refresh, "" for none. A
// refresh that failed recorded nothing and reports nothing (the next one
// tries again). One after which only the VPN restart failed has recorded its
// new problems as reported: they are shown now or never.
func autoRefreshText(result *domain.SubscriptionResult, err error) string {
	if !result.Applied(err) {
		return ""
	}
	return ui.AutoRefreshReport(result)
}

// connectivityLoop periodically verifies traffic flows while the VPN runs
// and reflects the verdict in the tray status text
func (a *Application) connectivityLoop() {
	time.Sleep(config.ConnectivityStartupDelay * time.Second)
	for {
		status := a.connectivity.Check()
		a.trayUI.UpdateConnectivity(status.Checked && !status.OK)
		time.Sleep(config.ConnectivityCheckInterval * time.Second)
	}
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
		case wantRunning := <-a.trayUI.ToggleCh:
			// Replace a request the worker has not picked up yet. This loop
			// is the only sender, so the send below never blocks.
			select {
			case <-a.toggleReq:
			default:
			}
			a.toggleReq <- wantRunning
		case <-a.trayUI.ImportClipboardCh:
			go a.handleImport(a.importSources.Clipboard)
		case <-a.trayUI.ImportQRCh:
			go a.handleImport(a.importSources.ScreenQR)
		case <-a.trayUI.SubsUpdateCh:
			go a.handleUpdateSubscriptions()
		case <-a.trayUI.SettingsCh:
			go a.handleOpenSettings()
		case <-a.trayUI.UpdateCh:
			go a.handleUpdate()
		case <-a.trayUI.AppUpdateCh:
			go a.handleAppUpdate()
		case <-a.trayUI.DPICh:
			go a.handleToggleDPI()
		case wantEnabled := <-a.trayUI.AutostartCh:
			// schtasks takes a while; serialized by autostartMu
			go a.handleToggleAutostart(wantEnabled)
		case <-a.trayUI.QuitCh:
			a.RequestQuit()
			return
		case <-a.vpnService.StatusChangeCh():
			// A wake-up, not a value: the channel keeps one notification
			// and drops the rest, so the payload may be stale
			a.trayUI.UpdateStatus(a.vpnService.GetStatus())
		}
	}
}

// toggleWorker applies the user's start/stop requests one at a time, off the
// event loop
func (a *Application) toggleWorker() {
	for wantRunning := range a.toggleReq {
		a.handleToggleVPN(wantRunning)
	}
}

// handleToggleVPN starts or stops the VPN as the user asked. Both are
// idempotent, so a click on a stale menu never does the opposite.
func (a *Application) handleToggleVPN(wantRunning bool) {
	action := a.vpnService.Stop
	if wantRunning {
		action = a.vpnService.Start
	}
	if err := action(); err != nil {
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
	if source == nil {
		return
	}

	a.runLocked(func() popup {
		text, err := source()
		if err != nil {
			log.Printf("Import: failed to read source: %v", err)
			return errorPopup(ui.ImportErrorTitle, err)
		}

		// A bare http(s) URL is a subscription, not a share link: register it
		// so it can be refreshed later instead of importing its nodes one-off
		if a.subscriptionService != nil && domain.IsSubscriptionURL(text) {
			result, err := a.subscriptionService.Add(text)
			if err != nil {
				log.Printf("Subscription add failed: %v", err)
			}
			a.trayUI.UpdateStatus(a.vpnService.GetStatus())
			return subscriptionPopup(ui.SubsAddedTitle, result, err)
		}

		result, err := a.importService.ImportFromText(text)
		if err != nil {
			log.Printf("Import failed: %v", err)
			return errorPopup(ui.ImportErrorTitle, err)
		}

		a.trayUI.UpdateStatus(a.vpnService.GetStatus())
		return infoPopup(ui.ImportSuccessTitle, ui.ImportMessage(result))
	})
}

// popup shows the result of a long operation; nil means nothing to show
type popup func()

func errorPopup(title string, err error) popup {
	return func() { ui.ShowError(title, err.Error()) }
}

func infoPopup(title, text string) popup {
	return func() { ui.ShowInfo(title, text) }
}

// runLocked runs a long operation under opMu and shows its result only AFTER
// the lock is released: a message box blocks until dismissed, and the lock is
// shared with the web UI — an unanswered popup must not hang every save and
// update made from the browser.
func (a *Application) runLocked(op func() popup) {
	a.opMu.Lock()
	show := op()
	a.opMu.Unlock()

	if show != nil {
		show()
	}
}

// handleUpdateSubscriptions refreshes all saved subscriptions on demand.
// Runs outside the event loop: downloads take a while and the message box
// blocks until dismissed.
func (a *Application) handleUpdateSubscriptions() {
	if a.subscriptionService == nil {
		return
	}

	a.runLocked(func() popup {
		subs, err := a.subscriptionService.List()
		if err == nil && len(subs) == 0 {
			return infoPopup(ui.SubsUpdateDoneTitle, ui.SubsNoneMsg)
		}

		result, err := a.subscriptionService.UpdateAll()
		if err != nil {
			log.Printf("Subscription update failed: %v", err)
		}

		a.trayUI.UpdateStatus(a.vpnService.GetStatus())
		return subscriptionPopup(ui.SubsUpdateDoneTitle, result, err)
	})
}

// subscriptionPopup shows the result of subscription work, or its error
func subscriptionPopup(title string, result *domain.SubscriptionResult, err error) popup {
	text, failed := subscriptionOutcome(result, err)
	if failed {
		return func() { ui.ShowError(ui.SubsErrorTitle, text) }
	}
	return infoPopup(title, text)
}

// subscriptionOutcome is the text the user is told after subscription work
// and whether it is an error. When only the VPN restart after it failed, the
// work was done — the nodes it left out are recorded as reported — and the
// error comes with its result.
func subscriptionOutcome(result *domain.SubscriptionResult, err error) (text string, failed bool) {
	if !result.Applied(err) {
		return err.Error(), true
	}
	return ui.SubscriptionMessage(result), err != nil
}

// handleUpdate downloads and installs the latest sing-box release.
// Runs outside the event loop: the download takes a while and the message
// box blocks until dismissed.
func (a *Application) handleUpdate() {
	a.runLocked(func() popup {
		result, err := a.updateService.Update()
		if err != nil {
			log.Printf("Update failed: %v", err)
			return errorPopup(ui.UpdateErrorTitle, err)
		}

		a.trayUI.UpdateStatus(a.vpnService.GetStatus())
		return infoPopup(ui.UpdateDoneTitle, updateMessage(result))
	})
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
	if a.dpiService == nil {
		return
	}

	a.runLocked(func() popup {
		status, err := a.dpiService.ToggleChain()
		if err != nil {
			log.Printf("DPI bypass toggle failed: %v", err)
			// Re-sync the checkbox with the real state after a failed toggle
			if s, sErr := a.dpiService.Status(); sErr == nil {
				a.trayUI.UpdateDPI(s.ChainActive)
			}
			return errorPopup(ui.DPIErrorTitle, err)
		}

		a.trayUI.UpdateDPI(status.ChainActive)
		a.trayUI.UpdateStatus(a.vpnService.GetStatus())
		return infoPopup(ui.DPIDoneTitle, dpiMessage(status))
	})
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

// handleToggleAutostart turns autostart on or off as the user asked (the
// opposite of what the checkbox showed when it was clicked — not a blind
// toggle of whatever the state happens to be by the time this runs). The tray
// disables the item on the click; the UpdateAutostart at the end re-enables
// it, so clicks cannot pile up while schtasks is running.
func (a *Application) handleToggleAutostart(wantEnabled bool) {
	a.autostartMu.Lock()
	defer a.autostartMu.Unlock()

	if a.autostartManager.IsEnabled() != wantEnabled {
		action := a.autostartManager.Disable
		if wantEnabled {
			action = a.autostartManager.Enable
		}
		if err := action(); err != nil {
			log.Printf("Error switching autostart (enable=%v): %v", wantEnabled, err)
			// From a goroutine: the popup blocks until dismissed
			go ui.ShowError(ui.AutostartErrorTitle, err.Error())
		}
	}

	// Always from the real state: also after an error, and when the task was
	// changed behind the app's back
	a.trayUI.UpdateAutostart(a.autostartManager.IsEnabled())
}
