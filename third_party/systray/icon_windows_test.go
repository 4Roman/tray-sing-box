//go:build windows

package systray

import (
	"encoding/binary"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// PATCH(tray-sing-box) 4: the tray icon is built from the .ico bytes in
// memory — the image choice and the real CreateIconFromResourceEx call
func TestIconFromBytes(t *testing.T) {
	ico, err := os.ReadFile("../../assets/icons/tray.ico")
	if err != nil {
		t.Skipf("generated icon missing (run go run ./tools/genicons): %v", err)
	}
	for _, size := range []int{16, 20, 24, 32, 48, 64, 300} {
		offset, length, err := pickIconImage(ico, size)
		if err != nil {
			t.Fatalf("pickIconImage(%d): %v", size, err)
		}
		if offset <= 0 || offset+length > len(ico) {
			t.Fatalf("pickIconImage(%d) = %d, %d out of range", size, offset, length)
		}
	}
	// 16 is in the file: that exact entry; 20 -> the next larger (32)
	width := func(offset int) int {
		count := int(binary.LittleEndian.Uint16(ico[4:]))
		for i := 0; i < count; i++ {
			e := 6 + 16*i
			if int(binary.LittleEndian.Uint32(ico[e+12:])) == offset {
				if ico[e] == 0 {
					return 256
				}
				return int(ico[e])
			}
		}
		return -1
	}
	if off, _, _ := pickIconImage(ico, 16); width(off) != 16 {
		t.Errorf("size 16 picked a %d px image", width(off))
	}
	if off, _, _ := pickIconImage(ico, 20); width(off) != 32 {
		t.Errorf("size 20 picked a %d px image, want the next larger (32)", width(off))
	}
	if off, _, _ := pickIconImage(ico, 300); width(off) != 256 {
		t.Errorf("size 300 picked a %d px image, want the largest", width(off))
	}

	wt.loadedImages = make(map[string]windows.Handle)
	h, err := wt.iconFromBytes(ico)
	if err != nil || h == 0 {
		t.Fatalf("iconFromBytes: %v", err)
	}
	if again, _ := wt.iconFromBytes(ico); again != h {
		t.Error("the handle is not cached")
	}

	for _, bad := range [][]byte{nil, {0, 0, 2, 0, 1, 0}, append([]byte{0, 0, 1, 0, 1, 0}, make([]byte, 16)...)} {
		if _, _, err := pickIconImage(bad, 16); err == nil {
			t.Errorf("pickIconImage accepted %v", bad)
		}
	}
}
