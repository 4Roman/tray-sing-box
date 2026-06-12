package process

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tray-sing-box/internal/config"
)

// Manager manages the sing-box VPN process
type Manager struct {
	cmd     *exec.Cmd
	mu      sync.Mutex
	exeDir  string
	running bool
}

// New creates a new process manager
func New() (*Manager, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	return &Manager{
		exeDir: filepath.Dir(exePath),
	}, nil
}

// Start starts the sing-box process
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Println("=== startVPN called ===")

	singBoxPath := filepath.Join(m.exeDir, config.SingBoxExe)
	configPath := filepath.Join(m.exeDir, config.SingBoxConfig)

	log.Printf("sing-box path: %s", singBoxPath)
	log.Printf("config path: %s", configPath)

	// Check if files exist
	if _, err := os.Stat(singBoxPath); os.IsNotExist(err) {
		return fmt.Errorf("sing-box.exe not found at: %s", singBoxPath)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config.json not found at: %s", configPath)
	}

	// Check if sing-box is already running
	if m.isRunning() {
		log.Println("sing-box.exe is already running, not starting new instance")
		m.running = true
		return nil
	}

	log.Println("sing-box.exe is not running, starting new instance")

	// Start sing-box process
	m.cmd = exec.Command(singBoxPath, "run", "-c", configPath)
	m.cmd.Dir = m.exeDir

	// Capture stderr and stdout for debugging
	stderr, err := m.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Hide the console window on Windows
	hideConsoleWindow(m.cmd)

	log.Println("Starting sing-box process...")
	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box: %w", err)
	}

	log.Printf("sing-box process started successfully (PID: %d)", m.cmd.Process.Pid)

	// Log stderr in background
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				log.Printf("[sing-box stderr]: %s", string(buf[:n]))
			}
			if err != nil {
				break
			}
		}
	}()

	// Log stdout in background
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				log.Printf("[sing-box stdout]: %s", string(buf[:n]))
			}
			if err != nil {
				break
			}
		}
	}()

	m.running = true

	// Monitor the process. Capture the cmd locally: m.cmd may be replaced or
	// nilled (Stop, restart) while this goroutine is still waiting, and state
	// must only be cleared if it still belongs to this process.
	cmd := m.cmd
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()

		if err != nil {
			log.Printf("ERROR: sing-box process exited with error: %v (was running: %v)", err, m.running)
		} else {
			log.Printf("sing-box process exited normally (was running: %v)", m.running)
		}
		if m.cmd == cmd {
			m.running = false
			m.cmd = nil
		}
	}()

	return nil
}

// Stop stops the sing-box process
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Println("=== stopVPN called ===")

	// Kill sing-box process(es) using taskkill
	cmd := NewHiddenCommand("taskkill", "/F", "/IM", config.SingBoxExe)
	log.Println("Executing taskkill for sing-box.exe...")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to kill sing-box process: %v\nOutput: %s", err, string(output))
		return fmt.Errorf("failed to stop sing-box: %w", err)
	}

	log.Printf("sing-box process killed successfully: %s", string(output))

	m.cmd = nil
	m.running = false
	log.Println("stopVPN completed")

	return nil
}

// IsRunning checks if the process is currently running
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// When we own a live process handle, trust the Wait() monitor.
	// Otherwise (attached to an external instance, or not started by us)
	// consult the system so the status reflects reality in both directions:
	// an externally killed sing-box and an externally started one.
	if m.cmd == nil || m.cmd.Process == nil {
		actuallyRunning := m.isRunning()
		if m.running != actuallyRunning {
			log.Printf("MONITOR: VPN state updated from system: %v -> %v", m.running, actuallyRunning)
			m.running = actuallyRunning
		}
	}

	return m.running
}

// isRunning checks if sing-box.exe is running in the system (must be called with lock held)
func (m *Manager) isRunning() bool {
	cmd := NewHiddenCommand("tasklist", "/FI", "IMAGENAME eq "+config.SingBoxExe, "/NH")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("ERROR: Failed to run tasklist: %v", err)
		return false
	}

	outputStr := string(output)
	lowerOutput := strings.ToLower(outputStr)
	isRunning := strings.Contains(lowerOutput, strings.ToLower(config.SingBoxExe))

	log.Printf("Checking if sing-box is running: %v", isRunning)
	if isRunning {
		log.Printf("  tasklist output contains sing-box.exe")
	}

	return isRunning
}

// WaitForExplorer waits for the Windows shell (system tray) to be ready.
// It polls for the Shell_TrayWnd window, which explorer.exe creates once the
// taskbar exists — the actual precondition for registering a tray icon.
func WaitForExplorer() {
	log.Println("Waiting for Windows shell (system tray) to be ready...")

	for i := 0; i < config.ExplorerWaitTimeout; i++ {
		if isTrayReady() {
			log.Printf("System tray is ready (attempt %d/%d)", i+1, config.ExplorerWaitTimeout)
			return
		}
		time.Sleep(time.Second)
	}

	log.Println("Timeout waiting for system tray, proceeding anyway...")
}
