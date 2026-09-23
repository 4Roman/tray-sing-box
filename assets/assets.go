// Package assets embeds the runtime resources into the exe, so the app is a
// single file: a deployed copy cannot end up with stale or missing icons next
// to a new exe (which is exactly what happened to a real installation).
package assets

import "embed"

// The whole directory rather than the .ico files by name: they are generated
// by tools/genicons and not tracked in git, and a named pattern without a
// match would break the build (and `go test ./...`) on a fresh clone. A build
// made before `make icons` simply carries no icons — see Icon.
//
//go:embed icons
var icons embed.FS

// Icon returns an embedded icon by file name ("tray.ico", "tray-off.ico").
// It fails when the exe was built without generating the icons first; the
// caller then falls back to <exe dir>/assets/icons/.
func Icon(name string) ([]byte, error) {
	return icons.ReadFile("icons/" + name)
}
