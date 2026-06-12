//go:build windows

// Package clipboard reads text from the Windows clipboard via WinAPI.
package clipboard

import (
	"fmt"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cfUnicodeText = 13

var (
	user32                         = windows.NewLazySystemDLL("user32.dll")
	kernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procGetClipboardData           = user32.NewProc("GetClipboardData")
	procIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	procGlobalLock                 = kernel32.NewProc("GlobalLock")
	procGlobalUnlock               = kernel32.NewProc("GlobalUnlock")
	procLstrlenW                   = kernel32.NewProc("lstrlenW")
	procRtlMoveMemory              = kernel32.NewProc("RtlMoveMemory")
)

// ReadText returns the current clipboard content as text.
// The clipboard is retried briefly: another process may hold it open.
func ReadText() (string, error) {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		text, err := readTextOnce()
		if err == nil {
			return text, nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return "", lastErr
}

func readTextOnce() (string, error) {
	if ok, _, _ := procIsClipboardFormatAvailable.Call(cfUnicodeText); ok == 0 {
		return "", fmt.Errorf("clipboard does not contain text")
	}

	if ok, _, err := procOpenClipboard.Call(0); ok == 0 {
		return "", fmt.Errorf("failed to open clipboard: %v", err)
	}
	defer procCloseClipboard.Call()

	handle, _, err := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return "", fmt.Errorf("failed to get clipboard data: %v", err)
	}

	ptr, _, err := procGlobalLock.Call(handle)
	if ptr == 0 {
		return "", fmt.Errorf("failed to lock clipboard memory: %v", err)
	}
	defer procGlobalUnlock.Call(handle)

	// Copy the NUL-terminated UTF-16 buffer into Go memory. lstrlenW +
	// RtlMoveMemory avoid constructing a Go pointer from the raw address.
	length, _, _ := procLstrlenW.Call(ptr)
	if length == 0 {
		return "", nil
	}

	codes := make([]uint16, length)
	procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&codes[0])), ptr, length*2)

	return string(utf16.Decode(codes)), nil
}
