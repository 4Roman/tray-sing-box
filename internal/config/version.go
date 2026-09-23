package config

// Version of the app, stamped at build time:
//
//	-ldflags "-X tray-sing-box/internal/config.Version=<git describe>"
//
// (the Makefile and CI do it). Printed by `tray-sing-box.exe --version` and
// logged at startup — the first thing to check when a deployed copy misbehaves
// is which build it actually is.
var Version = "dev"
