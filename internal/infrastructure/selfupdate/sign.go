// Package selfupdate updates the tray application itself from the project's
// GitHub releases. This file holds the platform-independent trust layer:
// the checksum manifest and its ed25519 signature, shared by the release
// tools (tools/relkey, tools/relsign) and the client.
//
// Why a signature and not just SHA-256: the app runs elevated and downloads
// code it then executes. A hash from the same release protects only against
// a broken download; anyone who can publish a release (a compromised GitHub
// account) could publish a matching hash. For the same reason the private
// key is NOT a CI secret — a compromised account could push a tag and have
// CI sign anything. The maintainer signs offline (tools/relsign) and uploads
// the signature to the draft release CI built; the public key is compiled in.
package selfupdate

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ChecksumsFile and SignatureFile are the release asset names next to the exe
const (
	ChecksumsFile = "checksums.txt"
	SignatureFile = "checksums.txt.sig"
)

// GenerateKey creates a new signing key pair. Both halves are returned
// base64-encoded: the public key goes into the app (config), the private
// key stays with the maintainer, offline.
func GenerateKey() (publicKey, privateKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

// ParsePublicKey decodes a base64 public key as produced by GenerateKey
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key has %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey decodes a base64 private key as produced by GenerateKey
func ParsePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("private key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key has %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// Sign returns the base64 signature of data (the whole checksums file)
func Sign(priv ed25519.PrivateKey, data []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
}

// ErrBadSignature is returned when the manifest was not signed by the
// expected key (or was modified after signing)
var ErrBadSignature = errors.New("signature does not match")

// Verify checks a base64 signature of data against the public key
func Verify(pub ed25519.PublicKey, data []byte, signature string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrBadSignature
	}
	return nil
}

// ParseChecksums reads a manifest in sha256sum format: one "<hex>  <name>"
// per line, returning name -> lowercase hex digest
func ParseChecksums(data []byte) (map[string]string, error) {
	sums := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed checksum line %q", line)
		}
		digest := strings.ToLower(fields[0])
		if len(digest) != sha256.Size*2 {
			return nil, fmt.Errorf("checksum for %s has %d hex chars, want %d", fields[1], len(digest), sha256.Size*2)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("checksum for %s is not hex: %w", fields[1], err)
		}
		// sha256sum marks binary mode with a leading '*'
		sums[strings.TrimPrefix(fields[1], "*")] = digest
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sums, nil
}

// FormatChecksums writes a manifest in sha256sum format, in the given order
func FormatChecksums(sums map[string]string, order []string) []byte {
	var b strings.Builder
	for _, name := range order {
		fmt.Fprintf(&b, "%s  %s\n", sums[name], name)
	}
	return []byte(b.String())
}

// FileSHA256 returns the lowercase hex SHA-256 of a file
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
