package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pubEnc, privEnc, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubEnc)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKey(privEnc)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("abc  file.exe\n")
	sig := Sign(priv, data)
	if err := Verify(pub, data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := Verify(pub, []byte("abd  file.exe\n"), sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("modified data verified: %v", err)
	}

	// Another key must not verify
	otherPub, _, _ := GenerateKey()
	other, _ := ParsePublicKey(otherPub)
	if err := Verify(other, data, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("foreign key verified: %v", err)
	}
	if err := Verify(pub, data, "not base64!"); err == nil {
		t.Fatal("garbage signature accepted")
	}
}

func TestParseKeysRejectWrongSizes(t *testing.T) {
	if _, err := ParsePublicKey("AAAA"); err == nil {
		t.Fatal("short public key accepted")
	}
	if _, err := ParsePrivateKey("AAAA"); err == nil {
		t.Fatal("short private key accepted")
	}
}

func TestChecksumsFormatAndParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.exe")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	sum, err := FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("sha256 = %s", sum)
	}

	data := FormatChecksums(map[string]string{"a.exe": sum, "b.txt": sum}, []string{"a.exe", "b.txt"})
	sums, err := ParseChecksums(data)
	if err != nil {
		t.Fatal(err)
	}
	if sums["a.exe"] != sum || sums["b.txt"] != sum {
		t.Fatalf("parsed = %v", sums)
	}

	// sha256sum's binary marker and comments are tolerated, junk is not
	if sums, err := ParseChecksums([]byte("# comment\n" + sum + " *c.exe\n")); err != nil || sums["c.exe"] != sum {
		t.Fatalf("binary marker not handled: %v %v", sums, err)
	}
	if _, err := ParseChecksums([]byte("nothex  x.exe\n")); err == nil {
		t.Fatal("non-hex digest accepted")
	}
	if _, err := ParseChecksums([]byte("deadbeef  x.exe\n")); err == nil {
		t.Fatal("short digest accepted")
	}
	if _, err := ParseChecksums([]byte(sum + "\n")); err == nil {
		t.Fatal("line without a name accepted")
	}
}
