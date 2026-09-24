//go:build windows

package singboxcheck

import (
	"errors"
	"testing"

	"tray-sing-box/internal/domain"
)

// Without sing-box.exe nothing is checked, and the validator says so: an
// ordinary save goes ahead, the first config of an installation does not
func TestValidatorWithoutTheBinary(t *testing.T) {
	dir := t.TempDir()
	if err := NewValidator(dir, dir)([]byte(`{"outbounds":[]}`)); !errors.Is(err, domain.ErrSingBoxMissing) {
		t.Fatalf("want ErrSingBoxMissing, got %v", err)
	}
}
