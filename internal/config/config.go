package config

const (
	AppName       = "SingBoxTray"
	RegStateKey   = `Software\SingBoxTray`
	SingBoxExe    = "sing-box.exe"
	SingBoxConfig = "config.json"
	LogFileName   = "tray-sing-box.log"

	// Monitoring
	StatusCheckInterval = 2  // seconds
	ExplorerWaitTimeout = 60 // seconds

	// State restore at startup
	RestoreStartAttempts = 3 // how many times to try starting sing-box
	RestoreCheckDelay    = 3 // seconds to wait before verifying it survived
	RestoreRetryDelay    = 2 // seconds between attempts

	// Subscriptions
	SubscriptionsFileName    = "subscriptions.json" // next to the exe
	SubscriptionRefreshHours = 6                    // periodic auto-refresh interval
	SubscriptionStartupDelay = 60                   // seconds after start before the first auto-refresh

	// DPI bypass (zapret running in a Docker container)
	DPIImage         = "8hrsk/zapret-docker-proxy:latest"
	DPIContainerName = "singbox-dpi"
	DPIProxyHost     = "127.0.0.1"
	DPIProxyPort     = 3128
	DPIBypassTag     = "dpi-bypass" // reserved outbound tag in config.json
)
