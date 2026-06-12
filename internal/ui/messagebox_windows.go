//go:build windows

package ui

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	mbOK            = 0x00000000
	mbIconError     = 0x00000010
	mbIconInfo      = 0x00000040
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000
)

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

func messageBox(title, text string, flags uintptr) {
	textPtr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		flags)
}

// ShowInfo displays an informational popup
func ShowInfo(title, text string) {
	messageBox(title, text, mbOK|mbIconInfo|mbSetForeground|mbTopmost)
}

// ShowError displays an error popup
func ShowError(title, text string) {
	messageBox(title, text, mbOK|mbIconError|mbSetForeground|mbTopmost)
}
