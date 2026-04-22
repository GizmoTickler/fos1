//go:build linux

package capture

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// fakeCaptureProcess emulates the exec lifecycle without spawning real
// subprocesses.
//
// The real tcpdump-backed manager calls Wait() twice against the same
// process: once from the monitor goroutine spawned by StartCapture, and once
// from stopCaptureInternal after signaling. The fake therefore has to let
// every Wait() caller observe the terminal state — we model that by closing
// a "done" channel on the first terminating signal/kill so all subsequent
// Wait() calls return immediately with the recorded exit error.
type fakeCaptureProcess struct {
	mu         sync.Mutex
	started    bool
	killed     bool
	signaled   os.Signal
	startErr   error
	done       chan struct{}
	terminate  sync.Once
	exitErr    error
	pid        int
}

func newFakeProcess() *fakeCaptureProcess {
	return &fakeCaptureProcess{done: make(chan struct{}), pid: 4242}
}

func (f *fakeCaptureProcess) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.started = true
	return nil
}

// Wait blocks until the process has terminated (via Signal or Kill) and then
// returns the recorded exit error. Multiple concurrent callers all unblock
// when the done channel is closed.
func (f *fakeCaptureProcess) Wait() error {
	<-f.done
	return f.exitErr
}

func (f *fakeCaptureProcess) Kill() error {
	f.mu.Lock()
	f.killed = true
	f.mu.Unlock()
	f.terminate.Do(func() {
		f.exitErr = errors.New("signal: killed")
		close(f.done)
	})
	return nil
}

func (f *fakeCaptureProcess) Signal(sig os.Signal) error {
	f.mu.Lock()
	f.signaled = sig
	f.mu.Unlock()
	f.terminate.Do(func() {
		f.exitErr = errors.New("signal: interrupt")
		close(f.done)
	})
	return nil
}

func (f *fakeCaptureProcess) Pid() int { return f.pid }

// fakeCaptureExec implements captureExec and hands out fakeCaptureProcesses.
type fakeCaptureExec struct {
	lookPathResult string
	lookPathErr    error
	procs          []*fakeCaptureProcess
	nextProcIdx    int
	nextStartErr   error
	countPackets   int64
	countErr       error
	commandLog     [][]string
}

func (f *fakeCaptureExec) LookPath(name string) (string, error) {
	if f.lookPathErr != nil {
		return "", f.lookPathErr
	}
	if f.lookPathResult != "" {
		return f.lookPathResult, nil
	}
	return "/usr/bin/" + name, nil
}

func (f *fakeCaptureExec) Command(_ context.Context, name string, args ...string) captureProcess {
	full := append([]string{name}, args...)
	f.commandLog = append(f.commandLog, full)

	var proc *fakeCaptureProcess
	if f.nextProcIdx < len(f.procs) {
		proc = f.procs[f.nextProcIdx]
		f.nextProcIdx++
	} else {
		proc = newFakeProcess()
		f.procs = append(f.procs, proc)
	}
	if f.nextStartErr != nil {
		proc.startErr = f.nextStartErr
		f.nextStartErr = nil
	}
	return proc
}

func (f *fakeCaptureExec) CountPackets(file string) (int64, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	return f.countPackets, nil
}

func tempCaptureDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fos1-capture-test-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestNewManagerReturnsErrorWhenTCPDumpMissing(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathErr: exec.ErrNotFound}
	_, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTCPDumpNotAvailable)
}

func TestNewManagerSucceedsWhenTCPDumpPresent(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	mgr, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Equal(t, "/usr/sbin/tcpdump", mgr.binaryPath)
}

func TestStartCaptureLaunchesTCPDumpWithExpectedArgs(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	dir := tempCaptureDir(t)
	mgr, err := newManagerWithExec(execer, dir)
	require.NoError(t, err)

	id, err := mgr.StartCapture(types.CaptureConfig{
		Interface: "eth0",
		Filter:    "tcp port 80",
		Filename:  "test.pcap",
	})
	require.NoError(t, err)
	require.NotEmpty(t, id)

	require.Len(t, execer.commandLog, 1)
	cmd := execer.commandLog[0]
	assert.Equal(t, "/usr/sbin/tcpdump", cmd[0])
	assert.Contains(t, cmd, "-i")
	assert.Contains(t, cmd, "eth0")
	assert.Contains(t, cmd, "-w")
	assert.Contains(t, cmd, filepath.Join(dir, "test.pcap"))
	assert.Contains(t, cmd, "tcp port 80")

	status, err := mgr.GetCaptureStatus(id)
	require.NoError(t, err)
	assert.Equal(t, statusRunning, status.Status)
	assert.Equal(t, "eth0", status.Interface)
}

func TestStartCaptureRequiresInterface(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	mgr, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.NoError(t, err)

	_, err = mgr.StartCapture(types.CaptureConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "interface is required")
}

func TestStartCapturePropagatesStartError(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{
		lookPathResult: "/usr/sbin/tcpdump",
		nextStartErr:   errors.New("exec boom"),
	}
	mgr, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.NoError(t, err)

	id, err := mgr.StartCapture(types.CaptureConfig{Interface: "eth0"})
	require.Error(t, err)
	assert.Empty(t, id)
	assert.Contains(t, err.Error(), "eth0")
	assert.Contains(t, err.Error(), "exec boom")
}

func TestStopCaptureSignalsProcessAndMarksStopped(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	mgr, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.NoError(t, err)

	id, err := mgr.StartCapture(types.CaptureConfig{Interface: "eth0"})
	require.NoError(t, err)

	require.NoError(t, mgr.StopCapture(id))

	status, err := mgr.GetCaptureStatus(id)
	require.NoError(t, err)
	assert.Equal(t, statusStopped, status.Status)

	require.Len(t, execer.procs, 1)
	assert.Equal(t, os.Interrupt, execer.procs[0].signaled)
}

func TestStopCaptureReturnsSentinelForUnknownID(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	mgr, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.NoError(t, err)

	err = mgr.StopCapture("nope")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCaptureNotFound)
}

func TestListCapturesReturnsActiveIDs(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	mgr, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.NoError(t, err)

	id1, err := mgr.StartCapture(types.CaptureConfig{Interface: "eth0"})
	require.NoError(t, err)
	id2, err := mgr.StartCapture(types.CaptureConfig{Interface: "eth1"})
	require.NoError(t, err)

	ids, err := mgr.ListCaptures()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{id1, id2}, ids)
}

func TestGetCapturePathReturnsFileForRunningCapture(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	dir := tempCaptureDir(t)
	mgr, err := newManagerWithExec(execer, dir)
	require.NoError(t, err)

	id, err := mgr.StartCapture(types.CaptureConfig{Interface: "eth0", Filename: "out.pcap"})
	require.NoError(t, err)

	path, err := mgr.GetCapturePath(id)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "out.pcap"), path)
}

func TestGetCapturePathReturnsSentinelForUnknownID(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	mgr, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.NoError(t, err)

	_, err = mgr.GetCapturePath("nope")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCaptureNotFound)
}

func TestShutdownStopsRunningCaptures(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	mgr, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.NoError(t, err)

	_, err = mgr.StartCapture(types.CaptureConfig{Interface: "eth0"})
	require.NoError(t, err)

	require.NoError(t, mgr.Shutdown(context.Background()))

	ids, err := mgr.ListCaptures()
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestInitializeReturnsSentinelWhenTCPDumpDisappears(t *testing.T) {
	t.Parallel()

	execer := &fakeCaptureExec{lookPathResult: "/usr/sbin/tcpdump"}
	mgr, err := newManagerWithExec(execer, tempCaptureDir(t))
	require.NoError(t, err)

	execer.lookPathErr = exec.ErrNotFound
	err = mgr.Initialize(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTCPDumpNotAvailable)
}
