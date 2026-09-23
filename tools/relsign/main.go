// relsign writes checksums.txt for the release assets and signs it.
//
//	RELEASE_SIGNING_KEY=<base64 private key> go run ./tools/relsign -dir dist
//
// Produces dist/checksums.txt (sha256sum format, one line per file in -dir)
// and dist/checksums.txt.sig (base64 ed25519 signature of the whole file).
// Run by the maintainer OFFLINE on the assets downloaded from the draft
// release that .github/workflows/release.yml built (CI never has the key).
// Without the key it writes the checksums only and exits with status 2.
package main

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/infrastructure/selfupdate"
)

func main() {
	dir := flag.String("dir", "dist", "directory with the release assets")
	keyEnv := flag.String("key-env", "RELEASE_SIGNING_KEY", "environment variable holding the base64 private key")
	flag.Parse()

	entries, err := os.ReadDir(*dir)
	if err != nil {
		fail(err)
	}
	sums := map[string]string{}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == selfupdate.ChecksumsFile || name == selfupdate.SignatureFile {
			continue
		}
		sum, err := selfupdate.FileSHA256(filepath.Join(*dir, name))
		if err != nil {
			fail(err)
		}
		sums[name] = sum
		names = append(names, name)
	}
	if len(names) == 0 {
		fail(fmt.Errorf("no assets in %s", *dir))
	}
	sort.Strings(names)

	manifest := selfupdate.FormatChecksums(sums, names)
	if err := os.WriteFile(filepath.Join(*dir, selfupdate.ChecksumsFile), manifest, 0644); err != nil {
		fail(err)
	}
	fmt.Print(string(manifest))

	encoded := os.Getenv(*keyEnv)
	if encoded == "" {
		fmt.Fprintf(os.Stderr, "%s is not set: checksums written but NOT signed - the app will refuse this release\n", *keyEnv)
		os.Exit(2)
	}
	priv, err := selfupdate.ParsePrivateKey(encoded)
	if err != nil {
		fail(err)
	}
	// A release signed with a key the app does not carry, or built from a
	// commit where self-update is not configured, would strand every client
	if strings.TrimSpace(config.AppUpdateRepo) == "" {
		fail(fmt.Errorf("config.AppUpdateRepo is empty: an exe built from this commit can never self-update"))
	}
	pub, err := selfupdate.ParsePublicKey(config.AppUpdatePublicKey)
	if err != nil {
		fail(fmt.Errorf("config.AppUpdatePublicKey: %w (self-update is disabled in this build)", err))
	}
	if !bytes.Equal(pub, priv.Public().(ed25519.PublicKey)) {
		fail(fmt.Errorf("%s is not the private half of config.AppUpdatePublicKey: every client would reject this release", *keyEnv))
	}
	sig := selfupdate.Sign(priv, manifest)
	if err := os.WriteFile(filepath.Join(*dir, selfupdate.SignatureFile), []byte(sig+"\n"), 0644); err != nil {
		fail(err)
	}
	fmt.Printf("signed: %s\n", selfupdate.SignatureFile)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
