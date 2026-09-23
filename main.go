package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"

	"tray-sing-box/assets"
	"tray-sing-box/internal/app"
	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/autostart"
	"tray-sing-box/internal/infrastructure/clipboard"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/connectivity"
	"tray-sing-box/internal/infrastructure/dpibypass"
	"tray-sing-box/internal/infrastructure/logger"
	"tray-sing-box/internal/infrastructure/logtail"
	"tray-sing-box/internal/infrastructure/migrate"
	"tray-sing-box/internal/infrastructure/paths"
	"tray-sing-box/internal/infrastructure/process"
	"tray-sing-box/internal/infrastructure/qr"
	"tray-sing-box/internal/infrastructure/selfupdate"
	"tray-sing-box/internal/infrastructure/sharelink"
	"tray-sing-box/internal/infrastructure/singboxcheck"
	"tray-sing-box/internal/infrastructure/storage"
	"tray-sing-box/internal/infrastructure/subscription"
	"tray-sing-box/internal/infrastructure/updater"
	"tray-sing-box/internal/ui"
	"tray-sing-box/internal/ui/webui"
)

var application *app.Application

func main() {
	// The elevated process loads system DLLs from System32 only: its PATH
	// carries the user's entries, some writable without elevation
	windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32)

	// A GUI-subsystem exe has no console, but the output is readable through
	// a pipe or a redirect (`tray-sing-box.exe --version | more`)
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(config.Version)
		return
	}
	// Started by the previous version right after a self-update: let it
	// finish first (single-instance mutex, log file, sing-box adoption)
	waitPID := uint32(0)
	mode := ""
	for _, arg := range os.Args[1:] {
		if v, ok := strings.CutPrefix(arg, "--wait-pid="); ok {
			if pid, err := strconv.ParseUint(v, 10, 32); err == nil {
				waitPID = uint32(pid)
			}
			continue
		}
		switch arg {
		case "--quit", "--quit-installation", "--migrate", "--enable-autostart", "--disable-autostart", "--uninstall-cleanup":
			mode = arg
		}
	}

	// Where the binaries and the data live (portable: everything next to the
	// exe; installed under Program Files: data in %ProgramData%\SingBoxTray)
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	layout := paths.Resolve(exePath)
	ensureWarning, ensureErr := layout.Ensure()

	// Initialize logger — in the data directory, unless it could not be
	// secured: then the log must not go there either (a user-controlled
	// directory would steer the elevated writes), Bin is admin-only
	logDir := layout.Data
	if ensureErr != nil {
		logDir = layout.Bin
	}
	loggerInstance, err := logger.New(logDir)
	if err != nil {
		log.Printf("Warning: failed to initialize logger: %v", err)
	}
	if loggerInstance != nil {
		defer loggerInstance.Close()
	}
	log.Printf("Version: %s", config.Version)
	if layout.Portable {
		log.Printf("Layout: portable, everything in %s", layout.Bin)
	} else {
		log.Printf("Layout: installed, binaries in %s, data in %s", layout.Bin, layout.Data)
	}
	if ensureWarning != "" {
		log.Printf("Warning: %s", ensureWarning)
	}
	if ensureErr != nil {
		log.Printf("ERROR: data directory %s unusable: %v", layout.Data, ensureErr)
	}
	if waitPID != 0 {
		log.Printf("Started after a self-update, waiting for the previous instance (PID %d) to exit", waitPID)
		if err := process.WaitForExit(waitPID, 30*time.Second); err != nil {
			log.Printf("Warning: %v", err)
		}
	}

	// Installer / uninstaller helpers: act on the running instance or the
	// system registration and exit, no tray
	if mode != "" {
		// The helper modes act on the task, the registry and processes;
		// only the takeover needs the data directory
		if ensureErr != nil && mode == "--migrate" {
			log.Printf("--migrate skipped: %v", ensureErr)
			os.Exit(1)
		}
		if err := runMode(mode, layout); err != nil {
			if errors.Is(err, errNoInstance) {
				// Not a failure: the installer reads it as "nothing was
				// running" (the mutex is in a private namespace, invisible
				// to its CheckForMutexes)
				os.Exit(exitNoInstance)
			}
			log.Printf("%s failed: %v", mode, err)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// The tray app belongs to an interactive user. As SYSTEM — a deployment
	// tool relaunching it after a silent upgrade — it would sit invisible in
	// session 0 holding the machine-wide single-instance mutex (the user's
	// own instance would then exit as "already running"), with SYSTEM's
	// empty VPN intent
	if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		log.Println("Running as SYSTEM: the tray app is not started for this account, exiting")
		return
	}

	// First run of an installed copy without the installer's `--migrate`
	// step (exe copied by hand): take over the portable installation the
	// autostart task points at. Before the mutex — a running old copy of
	// this rework holds it, and the takeover is what ends that copy.
	if ensureErr != nil {
		ui.ShowError(ui.VPNErrorTitle, fmt.Sprintf("Папка данных %s не может использоваться: %v", layout.Data, ensureErr))
		os.Exit(1)
	}
	takeOver(layout, true)

	// One instance only. Checked before the shell wait, so a manual launch
	// during boot is caught as well.
	if !process.AcquireSingleInstance() {
		log.Println("Another instance is already running, exiting")
		ui.ShowInfo(ui.AlreadyRunningTitle, ui.AlreadyRunningMsg)
		return
	}
	// Ties "the running instance" to this installation (--quit-installation)
	if err := process.MarkInstallation(layout.Bin); err != nil {
		log.Printf("Warning: %v", err)
	}

	// Task Scheduler may have launched us below normal priority, and sing-box
	// would inherit it — fix that before any child process is started
	process.NormalizePriority()

	// Initialize components
	processManager := process.New(layout.Bin, layout.Data)

	storageInstance := storage.New()

	autostartManager, err := autostart.New()
	if err != nil {
		log.Fatalf("Failed to create autostart manager: %v", err)
	}

	// Create VPN service
	vpnService := domain.NewVPNService(processManager, storageInstance)
	vpnService.SessionEnding = process.IsSessionEnding

	// Create outbound import service (share links from clipboard / screen QR)
	configEditor := configfile.New(layout.ConfigFile())
	configEditor.SetValidator(singboxcheck.NewValidator(layout.Bin, layout.Data))
	importService := domain.NewImportService(sharelink.Parser{}, configEditor, vpnService)
	importSources := app.ImportSources{
		Clipboard: clipboard.ReadText,
		ScreenQR:  qr.ScanScreen,
	}

	// sing-box binary updates from official GitHub releases
	updateService := domain.NewUpdateService(updater.New(layout.Bin, layout.Data), vpnService)

	// Connectivity verification: is traffic actually flowing through the VPN
	connectivityService := domain.NewConnectivityService(func(proxyURL string) error {
		return connectivity.Probe(proxyURL)
	}, configEditor, vpnService)

	// Proxy subscriptions: saved URLs refreshed on demand and on a timer
	subscriptionStore := subscription.NewStore(layout.Subscriptions())
	subscriptionService := domain.NewSubscriptionService(subscriptionStore, subscription.Fetch, sharelink.Parser{}, configEditor, vpnService)

	// DPI bypass: zapret running in a Docker container, chained into the config
	dpiManager := dpibypass.New()
	dpibypass.SetCLIConfigDir(filepath.Join(layout.Data, "docker-cli"))
	if params, err := os.ReadFile(layout.DPIParams()); err == nil {
		dpiManager.SetParams(strings.TrimSpace(string(params)))
	}
	dpiService := domain.NewDPIBypassService(dpiManager, configEditor, vpnService)

	// Settings web UI (opened from the tray menu)
	settingsService := domain.NewSettingsService(configEditor, vpnService)
	logReader := logtail.New(layout.Data)
	settingsUI := webui.New(settingsService, importService, updateService, dpiService, subscriptionService, connectivityService, webui.Sources{
		Clipboard: clipboard.ReadText,
		ScreenQR:  qr.ScanScreen,
	}, webui.LogAccess{
		Files: func() []webui.LogFile {
			var files []webui.LogFile
			for _, f := range logReader.Files() {
				files = append(files, webui.LogFile{ID: f.ID, Path: f.Path})
			}
			return files
		},
		Tail: logtail.Tail,
	})

	// Create application
	application = app.New(vpnService, importService, updateService, dpiService, subscriptionService, connectivityService, importSources, settingsUI, autostartManager)
	// One lock for the long operations of both entry points (tray + web UI)
	settingsUI.ShareOpLock(application.OpLock())

	// Self-update of this app from its GitHub releases (only when the
	// repository and the signing key are configured, see config)
	if appUpdater, err := selfupdate.New(exePath, config.AppUpdateRepo, config.AppUpdatePublicKey); err != nil {
		log.Printf("Self-update disabled: %v", err)
	} else {
		appUpdateService := domain.NewAppUpdateService(appUpdater, config.Version)
		application.SetAppUpdater(appUpdateService)
		settingsUI.SetAppUpdater(appUpdateService, application.RelaunchAfterUpdate)
	}

	// Restore the last VPN state and start the crash monitor right away: the
	// VPN must come up at boot without waiting for the shell or the tray icon
	application.StartBackground()

	// Wait for explorer.exe (system tray) to be ready
	process.WaitForExplorer()
	time.Sleep(2 * time.Second)

	// We run elevated: without this explorer.exe cannot tell us that the
	// taskbar was re-created, and the icon is lost after an explorer restart
	if err := process.AllowTaskbarCreated(); err != nil {
		log.Printf("Warning: tray icon will not survive an explorer.exe restart: %v", err)
	}

	// Run system tray
	systray.Run(onReady, onExit)
}

// takeOver runs the first-run takeover of a previous portable installation
// (see internal/infrastructure/migrate). carry: re-register the autostart
// task for this exe afterwards; otherwise the task is deleted and the
// installer registers it again if the user asked for autostart.
func takeOver(layout paths.Layout, carry bool) {
	if !migrate.Needed(layout) {
		return
	}
	am, err := autostart.New()
	if err != nil {
		log.Printf("Warning: takeover skipped: %v", err)
		return
	}
	report, err := migrate.TakeOver(layout, am, process.EndInstallation, carry)
	if err != nil {
		log.Printf("Warning: takeover incomplete: %v", err)
	}
	if report != nil {
		log.Printf("Took over %s: copied %v, kept existing %v, failed %v", report.From, report.Copied, report.Skipped, report.Failed)
	}
}

// errNoInstance: --quit found no running instance to ask (exit code
// exitNoInstance; 0 means an instance was running and has exited). Not 2:
// that is what the Go runtime exits with on a panic or a fatal error, and
// the installer must not read a crashed helper as "nothing was running".
var errNoInstance = errors.New("no running instance")

const exitNoInstance = 10

// runMode executes one of the command-line helper modes
func runMode(mode string, layout paths.Layout) error {
	switch mode {
	case "--quit", "--quit-installation":
		// --quit-installation (the uninstaller): only when the running
		// instance is this installation's — the quit event is machine-wide, and
		// a portable copy the user runs must survive the uninstall of an
		// unused installed one
		if mode == "--quit-installation" && !process.InstallationRunning(layout.Bin) {
			log.Println("--quit-installation: this installation's tray app is not running")
			return errNoInstance
		}
		// An instance that is still starting holds the mutex but has no
		// quit event yet: keep asking until it listens, or it is gone
		deadline := time.Now().Add(30 * time.Second)
		for {
			ok, err := process.RequestQuit()
			if err != nil {
				return err
			}
			if ok {
				break
			}
			if !process.InstanceRunning() {
				log.Println("--quit: no running instance")
				return errNoInstance
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("the running instance is starting up and did not accept the quit request")
			}
			time.Sleep(200 * time.Millisecond)
		}
		log.Println("--quit: instance asked to exit, waiting")
		if err := process.WaitForInstanceExit(30 * time.Second); err != nil {
			return err
		}
		// The mutex goes with the handle table, a moment before the image is
		// unmapped: give the exe file time to be released before the
		// installer replaces it
		time.Sleep(500 * time.Millisecond)
		return nil

	case "--migrate":
		// Installer, before it registers the autostart task: the takeover
		// must read the task while it still points at the old copy
		takeOver(layout, false)
		return nil

	case "--enable-autostart", "--disable-autostart":
		am, err := autostart.New()
		if err != nil {
			return err
		}
		if mode == "--enable-autostart" {
			return am.Enable()
		}
		return am.Disable()

	case "--uninstall-cleanup":
		// The VPN of this installation stops (the binaries are about to be
		// deleted), the autostart task and the stored intent go; the data
		// directory is the installer's business (it asks the user)
		if _, err := process.StopInstallation(layout.Bin); err != nil {
			log.Printf("Warning: %v", err)
		}
		// The stored intent is shared by every copy: it goes only when
		// autostart does not belong to another copy (which would then not
		// bring its VPN back at the next logon)
		otherCopy := ""
		if am, err := autostart.New(); err == nil {
			if am.OwnsTask() {
				if err := am.Disable(); err != nil {
					log.Printf("Warning: %v", err)
				}
			} else {
				otherCopy = am.RegisteredExe()
			}
		}
		if otherCopy != "" {
			log.Printf("Keeping the stored VPN state: autostart belongs to %s", otherCopy)
			return nil
		}
		if err := storage.New().Delete(); err != nil {
			log.Printf("Warning: %v", err)
		}
		return nil
	}
	return fmt.Errorf("unknown mode %s", mode)
}

func onReady() {
	// Must be real .ico files: on Windows systray loads icons via
	// LoadImageW(IMAGE_ICON, LR_LOADFROMFILE), which rejects PNG/JPEG bytes.
	trayIcon, err := loadIcon("tray.ico")
	if err != nil {
		log.Printf("Warning: failed to load tray icon: %v", err)
		trayIcon = nil // tray is created without an icon
	}
	trayIconOff, err := loadIcon("tray-off.ico")
	if err != nil {
		log.Printf("Warning: failed to load stopped-state tray icon: %v", err)
		trayIconOff = nil // status is still visible in the menu text
	}

	application.OnReady(trayIcon, trayIconOff)
}

func onExit() {
	application.OnExit()
}

// loadIcon returns the icon embedded into the exe. Only a build made without
// generating the icons first (plain `go build` on a fresh clone) has none —
// then the assets/icons directory next to the exe is tried.
func loadIcon(filename string) ([]byte, error) {
	if iconData, err := assets.Icon(filename); err == nil {
		return iconData, nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exeDir := filepath.Dir(exePath)

	// Load icon from assets/icons directory
	iconPath := filepath.Join(exeDir, "assets", "icons", filename)
	iconData, err := os.ReadFile(iconPath)
	if err != nil {
		return nil, err
	}

	return iconData, nil
}
