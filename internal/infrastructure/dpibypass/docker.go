//go:build windows

package dpibypass

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/process"
)

const (
	shortTimeout = 20 * time.Second
	pullTimeout  = 5 * time.Minute // first image pull is slow
)

// Manager controls the zapret DPI-bypass container through the docker CLI.
type Manager struct {
	image  string
	name   string
	host   string
	port   int
	params string // ZAPRET_PARAMS env applied at container creation ("" = image default)
	mu     sync.Mutex
}

// New creates a Manager configured from the package constants.
func New() *Manager {
	return &Manager{
		image: config.DPIImage,
		name:  config.DPIContainerName,
		host:  config.DPIProxyHost,
		port:  config.DPIProxyPort,
	}
}

// SetParams sets the zapret strategy (nfqws) parameters. Only applied when the
// container is created; changing it later requires recreating the container.
func (m *Manager) SetParams(p string) { m.params = p }

// ProxyAddr returns the host and port the container publishes the proxy on.
func (m *Manager) ProxyAddr() (string, int) { return m.host, m.port }

// docker runs a docker CLI command with a hidden console window and a timeout.
func docker(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: process.CREATE_NO_WINDOW | process.DETACHED_PROCESS,
	}
	return cmd.CombinedOutput()
}

// dockerErr wraps a failed docker command's output into a readable error.
func dockerErr(action string, out []byte, err error) error {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("%s: %s", action, msg)
}

// Available reports whether the Docker CLI exists and the daemon is reachable.
func (m *Manager) Available() error {
	out, err := docker(shortTimeout, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("Docker CLI не найден — установите Docker Desktop")
		}
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("Docker не запущен: %s", msg)
	}
	return nil
}

// State reports whether the container is running, stopped or absent.
func (m *Manager) State() (domain.ContainerState, error) {
	out, err := docker(shortTimeout, "inspect", "-f", "{{.State.Running}}", m.name)
	return parseInspect(out, err)
}

// EnsureImage pulls the container image when it is not present locally.
func (m *Manager) EnsureImage() error {
	if _, err := docker(shortTimeout, "image", "inspect", m.image); err == nil {
		return nil
	}
	if out, err := docker(pullTimeout, "pull", m.image); err != nil {
		return dockerErr("docker pull "+m.image, out, err)
	}
	return nil
}

// Start brings the container up (idempotent): runs a new one if absent,
// starts it again if stopped, does nothing if already running.
//
// Port publishing (-p 127.0.0.1:3128:3128) is used instead of host networking:
// on Docker Desktop (WSL2) host networking is not reachable from the Windows
// host, while published ports are forwarded to Windows localhost. The container
// runs --privileged because nfqws needs NFQUEUE/iptables.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := m.State()
	if err != nil {
		return err
	}
	switch state {
	case domain.ContainerRunning:
		return nil
	case domain.ContainerStopped:
		if out, err := docker(shortTimeout, "start", m.name); err != nil {
			return dockerErr("docker start", out, err)
		}
		return nil
	}

	if err := m.EnsureImage(); err != nil {
		return err
	}

	args := []string{
		"run", "-d",
		"--name", m.name,
		"--privileged",
		"--restart", "unless-stopped",
		"-p", fmt.Sprintf("%s:%d:%d", m.host, m.port, m.port),
	}
	if m.params != "" {
		args = append(args, "-e", "ZAPRET_PARAMS="+m.params)
	}
	args = append(args, m.image)

	if out, err := docker(pullTimeout, args...); err != nil {
		return dockerErr("docker run", out, err)
	}
	return nil
}

// Stop stops the container. A missing container is treated as success.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	out, err := docker(shortTimeout, "stop", m.name)
	if err != nil {
		if strings.Contains(string(out), "No such container") {
			return nil
		}
		return dockerErr("docker stop", out, err)
	}
	return nil
}
