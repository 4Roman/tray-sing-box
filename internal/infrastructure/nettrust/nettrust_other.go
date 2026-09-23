//go:build !windows

package nettrust

import "crypto/tls"

func tlsConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }
