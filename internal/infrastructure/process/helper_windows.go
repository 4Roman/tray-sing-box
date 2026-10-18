//go:build windows

package process

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrHelperNotIsolated: StartHelper could not put the new process into its
// job object (or let it run there) and ended it before it ran a single
// instruction of its own
var ErrHelperNotIsolated = errors.New("the helper process could not be isolated in a job object")

// Helper is a long-lived run of the app's own sing-box.exe that is NOT the VPN
// (the latency test instance): registered in helperPIDs for its whole life (the
// manager neither adopts it nor kills it on Stop; a Start meanwhile starts the
// real VPN), and in a job object that kills it when this process goes away — a
// leftover elevated <Bin>\sing-box.exe would be adopted as "the VPN" by the next
// instance of the app.
type Helper struct {
	cmd *exec.Cmd
	pid uint32
	// process keeps the PID from going to another process until the
	// registration is removed: os/exec closes its own handle inside Wait, and
	// a new process under that PID would be invisible to the manager meanwhile
	process windows.Handle
	job     windows.Handle
	done    chan struct{}
	err     error // valid once done is closed

	killOnce, closeOnce sync.Once
	killErr             error
}

// Test hooks: the isolation steps can be made to fail, and a test can look at
// the process between them (stage "created": started suspended, not in the
// job yet; "assigned": in the job, not resumed yet)
var (
	assignToJob  = windows.AssignProcessToJobObject
	resumeHelper = resumeOnlyThread
	helperStage  func(stage string, pid uint32, job windows.Handle)
)

// StartHelper starts cmd as a Helper. The process is created suspended and
// only resumed once it is in a job object with KILL_ON_JOB_CLOSE, whose only
// handle this process holds: there is no moment in which it runs and could
// outlive the app. Hidden console (NewHiddenCommand) unless cmd brings its own
// SysProcAttr. The caller must Stop it.
func StartHelper(cmd *exec.Cmd) (*Helper, error) {
	if cmd.SysProcAttr == nil {
		hideConsoleWindow(cmd)
	}
	// First, so that a failure here costs no process at all
	job, err := newKillOnCloseJob()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHelperNotIsolated, err)
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED

	// Started and registered under the lock findProcesses takes before its
	// snapshot, like HelperOutput: never seen unregistered
	helperMu.Lock()
	err = cmd.Start()
	var pid uint32
	if err == nil {
		pid = uint32(cmd.Process.Pid)
		helperPIDs[pid] = struct{}{}
	}
	helperMu.Unlock()
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}

	h := &Helper{cmd: cmd, pid: pid, job: job, done: make(chan struct{})}
	if err := h.isolate(); err != nil {
		h.abort()
		return nil, fmt.Errorf("%w: %v", ErrHelperNotIsolated, err)
	}
	go h.wait()
	return h, nil
}

// isolate puts the suspended process into the job and resumes it there
func (h *Helper) isolate() error {
	// The PID is safe to open: cmd.Process holds a handle to the process, so
	// it cannot have exited and left its PID to another one
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, h.pid)
	if err != nil {
		return fmt.Errorf("open process %d: %w", h.pid, err)
	}
	h.process = p
	if helperStage != nil {
		helperStage("created", h.pid, h.job)
	}
	// When the app itself runs in a job (whoever started it may have used
	// one), the process starts in that job too and this nests the new job in
	// it: allowed since Windows 8 for an empty job without UI restrictions
	if err := assignToJob(h.job, p); err != nil {
		return fmt.Errorf("assign process %d to its job: %w", h.pid, err)
	}
	if helperStage != nil {
		helperStage("assigned", h.pid, h.job)
	}
	return resumeHelper(h.pid)
}

// abort ends a helper whose isolation failed, before it was resumed: still
// suspended, it has not run a single instruction of sing-box — no listener,
// no connection, nothing read from stdin. (The one exception, a main thread
// found not suspended, means something else has resumed it; it is ended all
// the same.)
func (h *Helper) abort() {
	h.cmd.Process.Kill() // through os/exec's own handle: works without h.process
	h.cmd.Wait()
	h.unregister()
	windows.CloseHandle(h.job)
}

func (h *Helper) wait() {
	err := h.cmd.Wait()
	h.unregister()
	h.err = err
	close(h.done)
}

// unregister removes the registration of an exited helper — only now: while
// it runs, findProcesses would take it for the VPN
func (h *Helper) unregister() {
	helperMu.Lock()
	delete(helperPIDs, h.pid)
	helperMu.Unlock()
	if h.process != 0 {
		windows.CloseHandle(h.process) // from here on the PID may be reused
	}
}

// PID is the helper's process ID
func (h *Helper) PID() uint32 { return h.pid }

// Done is closed once the helper has exited and is no longer registered
func (h *Helper) Done() <-chan struct{} { return h.done }

// Err is how the helper ended (what exec.Cmd.Wait returned); nil while it runs
func (h *Helper) Err() error {
	select {
	case <-h.done:
		return h.err
	default:
		return nil
	}
}

// Stop kills the helper (the whole job: anything it started goes too), waits
// up to timeout for it to exit, then closes the job. Safe to call more than
// once and after the helper has exited on its own.
func (h *Helper) Stop(timeout time.Duration) error {
	h.killOnce.Do(func() {
		if err := windows.TerminateJobObject(h.job, 1); err != nil {
			h.killErr = fmt.Errorf("terminate the job of process %d: %w", h.pid, err)
		}
	})
	select {
	case <-h.done:
	case <-time.After(timeout):
	}
	// After the kill (killOnce is done by now in every caller): the handle is
	// never used once closed. Closing it ends the process in any case
	// (KILL_ON_JOB_CLOSE); the registration goes when it has exited.
	h.closeOnce.Do(func() { windows.CloseHandle(h.job) })
	select {
	case <-h.done:
		return nil
	default:
		if h.killErr != nil {
			return h.killErr
		}
		return fmt.Errorf("process %d is still running %v after it was killed", h.pid, timeout)
	}
}

// newKillOnCloseJob creates an unnamed, non-inheritable job object whose
// processes are killed when its last handle is closed — by Stop, or by
// Windows when this process ends, however it ends
func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return job, nil
}

// resumeOnlyThread resumes the main thread of a process created suspended.
// os/exec closes the thread handle CreateProcess returns, so the thread is
// looked up by its owner in a thread snapshot. A process that has never run
// has exactly that one thread (the loader starts its workers only once the
// main thread runs); anything else — more threads, or a thread that was not
// suspended — means the process is not in the state this relies on, and it
// is refused rather than guessed at.
func resumeOnlyThread(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("thread snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var threads []uint32
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID == pid {
			threads = append(threads, entry.ThreadID)
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fmt.Errorf("thread snapshot: %w", err)
	}
	if len(threads) != 1 {
		return fmt.Errorf("process %d has %d threads, want only its suspended main thread", pid, len(threads))
	}

	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, threads[0])
	if err != nil {
		return fmt.Errorf("open the main thread of process %d: %w", pid, err)
	}
	defer windows.CloseHandle(thread)
	previous, err := windows.ResumeThread(thread)
	if err != nil {
		return fmt.Errorf("resume the main thread of process %d: %w", pid, err)
	}
	if previous == 0 {
		return fmt.Errorf("the main thread of process %d was not suspended", pid)
	}
	return nil
}
