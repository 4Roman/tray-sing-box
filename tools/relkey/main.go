// relkey generates the ed25519 key pair that signs release manifests.
//
//	go run ./tools/relkey -out release-signing-key.txt
//
// It prints the PUBLIC key (paste it into internal/config/config.go as
// AppUpdatePublicKey) and writes the PRIVATE key to -out. Keep that file
// OFFLINE (a password manager, an encrypted drive) — never in the repo and
// never as a GitHub secret: CI must not be able to sign. The file name is
// git-ignored.
package main

import (
	"flag"
	"fmt"
	"os"

	"tray-sing-box/internal/infrastructure/selfupdate"
)

func main() {
	out := flag.String("out", "release-signing-key.txt", "file to write the private key to")
	flag.Parse()

	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists - refusing to overwrite a signing key\n", *out)
		os.Exit(1)
	}

	pub, priv, err := selfupdate.GenerateKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, []byte(priv+"\n"), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Public key (internal/config/config.go, AppUpdatePublicKey):\n%s\n\n", pub)
	fmt.Printf("Private key written to %s - keep it offline (never in the repo, never as a CI secret); it is needed to sign every release.\n", *out)
}
