# Local fork of github.com/getlantern/systray v1.2.2

Wired in through `replace github.com/getlantern/systray => ./third_party/systray`
in the root `go.mod`. Licence: Apache-2.0 (see `LICENSE`, unchanged).

Only the Windows sources are kept (the app is Windows-only); examples, the
darwin/linux backends, upstream docs and `systray_windows_test.go` were dropped
(the test needs upstream's example assets and cannot compile here). Patches
1-3 have NO automated coverage: they can only be exercised with a missing or
restarting explorer.exe. Patch 4 has `icon_windows_test.go` (run with
`go work init . ./third_party/systray && go test github.com/getlantern/systray`
from the repo root, as CI does). `systray.go` is unmodified. Every change in `systray_windows.go` is marked `PATCH(tray-sing-box)`:

1. **A failed `NIM_ADD` no longer aborts initialization.** Upstream called
   `Shell_NotifyIcon(NIM_ADD)` exactly once inside `initInstance`. When it
   failed — no taskbar yet, or explorer too busy at logon — `registerSystray`
   returned before `createMenu()` and `systrayReady()`: `onReady` never ran,
   and a later `TaskbarCreated` re-added a bare icon with no menu. Now
   `ensureIcon()` retries every 2 s in the background until the icon is in;
   the menu is always created and `onReady` always runs. `t.nid` keeps
   accumulating icon/tooltip meanwhile, so the late `NIM_ADD` shows the full
   icon.
2. **`TaskbarCreated` re-add goes through the same retry** (upstream ignored
   its error). A `NIM_ADD` that fails because the icon is still there is told
   apart with `NIM_MODIFY`.
3. **`WM_ENDSESSION` with `wParam == FALSE` is ignored.** That is a cancelled
   shutdown/logoff; upstream deleted the icon and ran `onExit` while the app
   kept running. `WM_DESTROY` used to fall through into the same branch (its
   `wParam` is always 0), hence the explicit message check.
4. **Icons are built from memory** (`iconFromBytes`: the best-fitting image of
   the .ico for `SM_CXSMICON` -> `CreateIconFromResourceEx`, cached by md5).
   Upstream wrote the bytes to `%TEMP%\systray_temp_icon_<md5>` and loaded
   that file with `LoadImageW(LR_LOADFROMFILE)`: in the elevated app the
   user's TEMP and the predictable name in it belong to the user's
   non-elevated programs (foreign image bytes parsed elevated; a redirected
   TEMP made the write a file creation at a chosen path).
   `iconBytesToFilePath` is gone, `setIcon` takes a handle.

To update the fork: copy the new upstream `systray.go`, `systray_windows.go`,
`systray_windows_test.go`, `LICENSE`, re-apply the four patches, trim `go.mod`.
