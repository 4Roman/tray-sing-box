package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getlantern/systray"

	"tray-sing-box/internal/app"
	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/autostart"
	"tray-sing-box/internal/infrastructure/clipboard"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/dpibypass"
	"tray-sing-box/internal/infrastructure/logger"
	"tray-sing-box/internal/infrastructure/logtail"
	"tray-sing-box/internal/infrastructure/process"
	"tray-sing-box/internal/infrastructure/qr"
	"tray-sing-box/internal/infrastructure/sharelink"
	"tray-sing-box/internal/infrastructure/singboxcheck"
	"tray-sing-box/internal/infrastructure/storage"
	"tray-sing-box/internal/infrastructure/subscription"
	"tray-sing-box/internal/infrastructure/updater"
	"tray-sing-box/internal/ui/webui"
)

var application *app.Application

func main() {
	// Initialize logger
	loggerInstance, err := logger.New()
	if err != nil {
		log.Printf("Warning: failed to initialize logger: %v", err)
	}
	if loggerInstance != nil {
		defer loggerInstance.Close()
	}

	// Wait for explorer.exe (system tray) to be ready
	process.WaitForExplorer()
	time.Sleep(2 * time.Second)

	// Initialize components
	processManager, err := process.New()
	if err != nil {
		log.Fatalf("Failed to create process manager: %v", err)
	}

	storageInstance := storage.New()

	autostartManager, err := autostart.New()
	if err != nil {
		log.Fatalf("Failed to create autostart manager: %v", err)
	}

	// Create VPN service
	vpnService := domain.NewVPNService(processManager, storageInstance)

	// Create outbound import service (share links from clipboard / screen QR)
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)
	configEditor := configfile.New(filepath.Join(exeDir, config.SingBoxConfig))
	configEditor.SetValidator(singboxcheck.NewValidator(exeDir))
	importService := domain.NewImportService(sharelink.Parser{}, configEditor, vpnService)
	importSources := app.ImportSources{
		Clipboard: clipboard.ReadText,
		ScreenQR:  qr.ScanScreen,
	}

	// sing-box binary updates from official GitHub releases
	updateService := domain.NewUpdateService(updater.New(exeDir), vpnService)

	// Proxy subscriptions: saved URLs refreshed on demand and on a timer
	subscriptionStore := subscription.NewStore(filepath.Join(exeDir, config.SubscriptionsFileName))
	subscriptionService := domain.NewSubscriptionService(subscriptionStore, subscription.Fetch, sharelink.Parser{}, configEditor, vpnService)

	// DPI bypass: zapret running in a Docker container, chained into the config
	dpiManager := dpibypass.New()
	if params, err := os.ReadFile(filepath.Join(exeDir, "dpi-params.txt")); err == nil {
		dpiManager.SetParams(strings.TrimSpace(string(params)))
	}
	dpiService := domain.NewDPIBypassService(dpiManager, configEditor, vpnService)

	// Settings web UI (opened from the tray menu)
	settingsService := domain.NewSettingsService(configEditor, vpnService)
	logReader := logtail.New(exeDir)
	settingsUI := webui.New(settingsService, importService, updateService, dpiService, subscriptionService, webui.Sources{
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
	application = app.New(vpnService, importService, updateService, dpiService, subscriptionService, importSources, settingsUI, autostartManager)

	// Run system tray
	systray.Run(onReady, onExit)
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

// loadIcon loads an icon from assets/icons directory
func loadIcon(filename string) ([]byte, error) {
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
