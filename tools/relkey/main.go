// relkey generates the ed25519 key pair that signs release manifests.
//
//	go run ./tools/relkey -out <path outside the repository>
//
// It prints the PUBLIC key (paste it into internal/config/config.go as
// AppUpdatePublicKey) and writes the PRIVATE key to -out. Keep that file
// OFFLINE (a password manager, an encrypted drive) — never in the repo and
// never as a GitHub secret: CI must not be able to sign. A path inside a git
// working tree is refused (one `git add -f` or a renamed file away from being
// committed); the default is a file in the user's home directory.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"tray-sing-box/internal/infrastructure/selfupdate"
)

func main() {
	home, _ := os.UserHomeDir()
	out := flag.String("out", filepath.Join(home, "tray-sing-box-release-signing-key.txt"), "file to write the private key to (outside any git working tree)")
	flag.Parse()

	path, err := filepath.Abs(*out)
	if err != nil {
		fail(err)
	}
	if repo := workTreeOf(filepath.Dir(path)); repo != "" {
		fail(fmt.Errorf("%s is inside the git working tree %s - write the private key outside any repository", path, repo))
	}
	if _, err := os.Stat(path); err == nil {
		fail(fmt.Errorf("%s already exists - refusing to overwrite a signing key", path))
	}

	pub, priv, err := selfupdate.GenerateKey()
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(path, []byte(priv+"\n"), 0600); err != nil {
		fail(err)
	}

	fmt.Printf("Public key (internal/config/config.go, AppUpdatePublicKey):\n%s\n\n", pub)
	fmt.Printf("Private key written to %s - keep it offline (never in the repo, never as a CI secret); it is needed to sign every release (tools/relsign -key-file).\n", path)
}

// workTreeOf returns the enclosing git working tree of dir ("" when none):
// the first ancestor holding a .git directory or file (worktrees have a file)
func workTreeOf(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
