// Package dpibypass manages the zapret DPI-bypass Docker container and exposes
// its proxy address to the sing-box config layer.
package dpibypass

import (
	"fmt"
	"strings"

	"tray-sing-box/internal/domain"
)

// parseInspect turns the output of `docker inspect -f {{.State.Running}}` into
// a container state. A "No such object/container" error means the container was
// never created. Kept platform-independent so it is unit-testable without Docker.
func parseInspect(out []byte, err error) (domain.ContainerState, error) {
	text := strings.TrimSpace(string(out))
	if err != nil {
		if strings.Contains(text, "No such object") || strings.Contains(text, "No such container") {
			return domain.ContainerAbsent, nil
		}
		if text == "" {
			text = err.Error()
		}
		return domain.ContainerAbsent, fmt.Errorf("docker inspect: %s", text)
	}
	switch text {
	case "true":
		return domain.ContainerRunning, nil
	case "false":
		return domain.ContainerStopped, nil
	default:
		return domain.ContainerAbsent, fmt.Errorf("unexpected docker inspect output: %q", text)
	}
}
