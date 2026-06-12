package dpibypass

import (
	"errors"
	"testing"

	"tray-sing-box/internal/domain"
)

func TestParseInspect(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		err     error
		want    domain.ContainerState
		wantErr bool
	}{
		{"running", "true\n", nil, domain.ContainerRunning, false},
		{"stopped", "false\n", nil, domain.ContainerStopped, false},
		{"absent object", "Error: No such object: singbox-dpi", errors.New("exit 1"), domain.ContainerAbsent, false},
		{"absent container", "Error: No such container: singbox-dpi", errors.New("exit 1"), domain.ContainerAbsent, false},
		{"daemon down", "Cannot connect to the Docker daemon", errors.New("exit 1"), domain.ContainerAbsent, true},
		{"garbage", "wat", nil, domain.ContainerAbsent, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseInspect([]byte(c.out), c.err)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
}
