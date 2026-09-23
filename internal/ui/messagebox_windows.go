//go:build windows

package ui

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	mbOK            = 0x00000000
	mbYesNo         = 0x00000004
	mbIconError     = 0x00000010
	mbIconInfo      = 0x00000040
	mbDefButton2    = 0x00000100
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000

	idYes = 6
)

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

// messageBox shows the popup and returns the id of the pressed button
// (0 when it could not be shown)
func messageBox(title, text string, flags uintptr) uintptr {
	textPtr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return 0
	}
	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return 0
	}
	ret, _, _ := procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		flags)
	return ret
}

// ShowInfo displays an informational popup
func ShowInfo(title, text string) {
	messageBox(title, text, mbOK|mbIconInfo|mbSetForeground|mbTopmost)
}

// ShowError displays an error popup
func ShowError(title, text string) {
	messageBox(title, text, mbOK|mbIconError|mbSetForeground|mbTopmost)
}

// AskYesNo displays a question with yes/no buttons; "no" is the default
func AskYesNo(title, text string) bool {
	return messageBox(title, text, mbYesNo|mbDefButton2|mbIconInfo|mbSetForeground|mbTopmost) == idYes
}

// AskErrorYesNo displays an error popup with a yes/no question and reports
// whether the user chose "yes". "No" is the default button: an accidental
// Enter must not pick the action.
func AskErrorYesNo(title, text string) bool {
	return messageBox(title, text, mbYesNo|mbDefButton2|mbIconError|mbSetForeground|mbTopmost) == idYes
}
