//go:build windows

package dpibypass

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/paths"
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

// dockerExe finds the Docker CLI the elevated app may run: Docker Desktop's
// own copy under Program Files, and only after paths.CheckAdminOnlyFile —
// the file and every folder above it owned by an administrator and
// writable by no one else. Not PATH: the user's own entries follow the
// system ones and some are writable without elevation, and even %WINDIR%
// has user-writable subfolders; the DPI status check runs docker at every
// start.
func dockerExe() (string, error) {
	f := paths.SystemFolders()
	var tried []string
	for _, root := range []string{f.ProgramFiles, f.ProgramFilesX86} {
		if root == "" {
			continue
		}
		exe := filepath.Join(root, "Docker", "Docker", "resources", "bin", "docker.exe")
		if _, err := os.Stat(exe); err != nil {
			tried = append(tried, exe)
			continue
		}
		if err := paths.CheckAdminOnlyFile(exe); err != nil {
			return "", fmt.Errorf("%s не будет запущен с правами администратора: %v", exe, err)
		}
		return exe, nil
	}
	return "", fmt.Errorf("Docker Desktop не найден — установите Docker Desktop (искали %s)", strings.Join(tried, ", "))
}

var cliConfigDir string

// SetCLIConfigDir sets the directory the docker CLI uses as its
// configuration (DOCKER_CONFIG): one of the app, in its data directory — not
// the user's %USERPROFILE%\.docker, whose config.json (credsStore,
// credHelpers, plugin directories) would make the elevated CLI run programs
// the user's non-elevated software chose
func SetCLIConfigDir(dir string) { cliConfigDir = dir }

// dockerEnv is the whole environment of the elevated docker CLI: built here,
// nothing inherited (the user's environment could point DOCKER_CONFIG,
// DOCKER_HOST, PATH and friends anywhere)
func dockerEnv(exe string) ([]string, error) {
	if cliConfigDir == "" {
		return nil, errors.New("docker CLI configuration directory not set")
	}
	if err := os.MkdirAll(cliConfigDir, 0755); err != nil {
		return nil, err
	}
	f := paths.SystemFolders()
	temp := filepath.Join(f.Windows, "Temp")
	return []string{
		"SystemRoot=" + f.Windows,
		"windir=" + f.Windows,
		"ProgramData=" + f.ProgramData,
		"ProgramFiles=" + f.ProgramFiles,
		"PATH=" + f.System32 + ";" + filepath.Dir(exe),
		"DOCKER_CONFIG=" + cliConfigDir,
		"USERPROFILE=" + cliConfigDir,
		"HOME=" + cliConfigDir,
		"TEMP=" + temp,
		"TMP=" + temp,
		"DOCKER_HOST=npipe:////./pipe/" + enginePipe(),
	}, nil
}

// enginePipe: Docker Desktop's Linux engine pipe when it exists, else the
// classic default one
func enginePipe() string {
	const desktop = "dockerDesktopLinuxEngine"
	name, err := windows.UTF16PtrFromString(`\\.\pipe\` + desktop)
	if err != nil {
		return "docker_engine"
	}
	var data windows.Win32finddata
	h, err := windows.FindFirstFile(name, &data)
	if err != nil {
		return "docker_engine"
	}
	windows.FindClose(h)
	return desktop
}

// docker runs a docker CLI command with a hidden console window and a timeout.
func docker(timeout time.Duration, args ...string) ([]byte, error) {
	exe, err := dockerExe()
	if err != nil {
		return nil, err
	}
	env, err := dockerEnv(exe)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = env
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
	// Missing or refused (not admin-only) — starting Docker would not help
	if _, err := dockerExe(); err != nil {
		return err
	}
	out, err := docker(shortTimeout, "version", "--format", "{{.Server.Version}}")
	if err != nil {
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
