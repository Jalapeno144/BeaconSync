// Package evasion — inline hook detection and unhooking
//
// This file implements two capabilities critical for EDR/AV evasion:
//
//  1. Hook Detection: compares the prologues of critical ntdll.dll exports
//     against a clean copy read from disk.  Inline hooks placed by EDR/AV
//     products (typically a 5-byte JMP or 14-byte trampoline at the function
//     entry point) are detected by byte-level comparison.
//
//  2. Unhooking (Full .text Section Restore): overwrites the entire in-memory
//     .text section of ntdll.dll with clean bytes from the on-disk copy.  This
//     restores every exported function at once, covering hooks on functions
//     not in our watch-list.
//
// # Architecture
//
// Detection works by parsing the PE export table to resolve each target
// function's RVA, then comparing the first N bytes at that RVA in the live
// (possibly hooked) ntdll image against the clean bytes at the same RVA in
// the file read from %SystemRoot%\System32\ntdll.dll.
//
// Unhooking locates the .text section header in the on-disk PE, copies its
// raw bytes, and overwrites the live .text pages after flipping their
// protection to PAGE_EXECUTE_READWRITE.
//
// # Limitations
//
//   - Ring 3 only.  Kernel callbacks (PsSetCreateProcessNotifyRoutine, etc.)
//     and ETW providers are unaffected by user-mode unhooking.
//   - Some EDRs re-hook periodically (10–60 s re-hook cycle).  The window of
//     clean execution after UnhookNtdll may be bounded.
//   - The unhook operation itself calls VirtualProtect, which routes through
//     the (possibly still hooked) NtProtectVirtualMemory.  This call is
//     visible to EDR callbacks, though rarely blocked outright.
//   - Thread safety: modifying .text while another thread executes ntdll code
//     is inherently racy.  Perform unhooking early — ideally before spawning
//     additional goroutines that may call into ntdll.
package evasion

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// =============================================================================
// Public types
// =============================================================================

// HookCheckResult describes the hook status of a single exported function.
type HookCheckResult struct {
	FunctionName string // exported name, e.g. "NtCreateThreadEx"
	Hooked       bool   // true when the in-memory prologue differs from disk
	Expected     []byte // first PROLOGUE_LEN bytes from the clean disk copy
	Actual       []byte // first PROLOGUE_LEN bytes from the in-memory image
}

// HookScanResult aggregates the outcome of a full ntdll.dll hook scan.
type HookScanResult struct {
	HookedFunctions []HookCheckResult // only functions where Hooked == true
	CleanFunctions  int               // count of functions that passed check
	Errors          []string          // per-function errors (e.g. export not found)
	IsHooked        bool              // convenience: len(HookedFunctions) > 0
}

// =============================================================================
// Constants
// =============================================================================

const (
	// prologueLen is the number of bytes compared at each function entry
	// point.  A typical NT syscall stub on Windows 10/11 x64 is 18–22 bytes:
	//
	//   mov r10, rcx               ; 4C 8B D1  (3 bytes)
	//   mov eax, <SSN>             ; B8 xx xx 0 (5 bytes)
	//   test byte [SharedUserData] ; F6 04 25 … (8 bytes, WoW64 transition)
	//   jne +2                     ; 75 03      (2 bytes)
	//   syscall                    ; 0F 05      (2 bytes)
	//   ret                        ; C3         (1 byte)
	//   int 2Eh / ret              ; CD 2E C3   (3 bytes)
	//
	// Inline hooks overwrite the first 5 (near JMP rel32), 6 (JMP [rip]),
	// or 13–14 (trampoline) bytes.  32 bytes covers all common hook sizes
	// plus a safety margin.
	prologueLen = 32

	// ntdllPath is the canonical path to the 64-bit ntdll.dll on Windows.
	// We use the SystemRoot variable to handle non-standard install drives.
	ntdllPath = `C:\Windows\System32\ntdll.dll`

	// PE constants
	imageDosSignature       = 0x5A4D // "MZ"
	imageNTSignature        = 0x4550 // "PE\x00\x00"
	imageNTOptionalHdr64    = 0x020B // PE32+
	imageSIZEOFShortName    = 8
	imageDirEntryExport     = 0 // export directory index
	imageSIZOFSectionHdr    = 40
	imageSIZEOFDosHdr       = 64
	imageSIZEOFFileHdr      = 20
	imageSIZEOFDataDirEntry = 8
	// imageNumberOfDirEntries is always 16 in the Windows PE spec.
	imageNumberOfDirEntries = 16
)

// =============================================================================
// Public API — Hook Detection
// =============================================================================

// ScanNtdllHooks checks critical ntdll.dll functions for user-mode inline
// hooks by comparing the in-memory function prologues against a clean copy
// read from disk.
//
// Functions checked are the most commonly hooked by EDR/AV products:
// process/thread creation, memory management, and handle operations.
//
// Returns nil if ntdll.dll cannot be read or parsed (the caller should
// treat this as "unknown", not "clean").
func ScanNtdllHooks() *HookScanResult {
	result := &HookScanResult{}

	ntdllBase := getNtdllBase()
	if ntdllBase == 0 {
		result.Errors = append(result.Errors, "GetModuleHandle(ntdll.dll) failed")
		return result
	}

	// Read clean copy from disk.
	diskBytes, err := os.ReadFile(ntdllPath)
	if err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("cannot read %s: %v", ntdllPath, err))
		return result
	}

	// Parse PE headers.
	pe, err := parsePEHeaders(diskBytes)
	if err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("PE parse error: %v", err))
		return result
	}

	// Build export name → RVA map.
	exports, err := parseExportTable(diskBytes, pe)
	if err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("export table parse error: %v", err))
		return result
	}

	// Check each critical function.
	for _, fn := range criticalNtFunctions {
		rva, ok := exports[fn]
		if !ok {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s not found in ntdll exports", fn))
			continue
		}

		// Expected bytes: clean copy from disk.
		diskOffset, err := rvaToFileOffset(pe, rva, diskBytes)
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: %v", fn, err))
			continue
		}

		expected := safeSlice(diskBytes, diskOffset, prologueLen)

		// Actual bytes: in-memory ntdll image.
		// ntdllBase is a uintptr from GetModuleHandleW; rva is
		// a uint32 file offset.  We add them and convert to a
		// pointer for byte-level reading.
		memAddr := unsafe.Add(unsafe.Pointer(nil), int(ntdllBase+uintptr(rva)))
		actual := safeSliceFromPtr(memAddr, prologueLen)

		clean := byteSlicesEqual(expected, actual)

		if !clean {
			result.HookedFunctions = append(result.HookedFunctions, HookCheckResult{
				FunctionName: fn,
				Hooked:       true,
				Expected:     expected,
				Actual:       actual,
			})
		} else {
			result.CleanFunctions++
		}
	}

	result.IsHooked = len(result.HookedFunctions) > 0
	return result
}

// =============================================================================
// Public API — Unhooking
// =============================================================================

// UnhookNtdll restores the .text section of the in-memory ntdll.dll image
// from the clean on-disk copy.
//
// This is a "full unhook" — every function in .text is restored, not just
// the ones in our watch-list.  It is the most thorough user-mode unhooking
// technique available without direct kernel intervention.
//
// Returns the number of bytes restored (the .text section virtual size) and
// any error encountered.
//
// # Safety
//
// Overwriting .text while other threads execute ntdll code is racy.  Call
// this function early in the process lifetime, before spawning goroutines
// that may enter ntdll through cgo or syscall.
func UnhookNtdll() (int, error) {
	ntdllBase := getNtdllBase()
	if ntdllBase == 0 {
		return 0, fmt.Errorf("evasion: GetModuleHandle(ntdll.dll) returned NULL")
	}

	diskBytes, err := os.ReadFile(ntdllPath)
	if err != nil {
		return 0, fmt.Errorf("evasion: cannot read %s: %w", ntdllPath, err)
	}

	pe, err := parsePEHeaders(diskBytes)
	if err != nil {
		return 0, fmt.Errorf("evasion: PE parse error: %w", err)
	}

	// Locate the .text section.
	textHdr := findSection(pe, diskBytes, ".text")
	if textHdr == nil {
		return 0, fmt.Errorf("evasion: .text section not found in %s", ntdllPath)
	}

	textVA := textHdr.VirtualAddress
	textSize := textHdr.VirtualSize
	textRawPtr := textHdr.PointerToRawData

	if textSize == 0 || textRawPtr == 0 {
		return 0, fmt.Errorf("evasion: .text section is empty or has no raw data")
	}

	// Read the clean .text bytes from disk.
	cleanText := safeSlice(diskBytes, int(textRawPtr), int(textSize))

	// Change protection on the live .text region to RWX so we can overwrite.
	targetAddr := uintptr(ntdllBase) + uintptr(textVA)
	targetSize := uintptr(textSize)

	var oldProtect uint32
	if err := windows.VirtualProtect(
		targetAddr,
		targetSize,
		windows.PAGE_EXECUTE_READWRITE,
		&oldProtect,
	); err != nil {
		return 0, fmt.Errorf("evasion: VirtualProtect(+RWX) on ntdll.text failed: %w", err)
	}

	//Copy the clean .text bytes over the (possibly hooked) live .text.
	dst := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(nil), int(targetAddr))), len(cleanText))
	copy(dst, cleanText)

	// Restore original page protection.
	if err := windows.VirtualProtect(
		targetAddr,
		targetSize,
		oldProtect,
		&oldProtect,
	); err != nil {
		// The overwrite succeeded but we couldn't restore protection.
		// This leaves .text as RWX — functional but conspicuous.
		return len(cleanText),
			fmt.Errorf("evasion: VirtualProtect(restore) on ntdll.text failed (text is RWX): %w", err)
	}

	return len(cleanText), nil
}

// =============================================================================
// Public API — Combined
// =============================================================================

// ScanAndUnhook runs ScanNtdllHooks and, if hooks are detected, attempts
// UnhookNtdll.  It returns the scan result and any unhook error.
//
// A typical use is:
//
//	if result, err := evasion.ScanAndUnhook(); err != nil {
//	    log.Printf("unhook warning: %v (hooked: %v)", err, result.IsHooked)
//	}
func ScanAndUnhook() (*HookScanResult, error) {
	result := ScanNtdllHooks()
	if !result.IsHooked {
		return result, nil
	}

	_, err := UnhookNtdll()
	return result, err
}

// =============================================================================
// PE parsing types (private)
// =============================================================================

// imageDosHeader mirrors IMAGE_DOS_HEADER — only the fields we need.
type imageDosHeader struct {
	_       [60]byte // padding to e_lfanew at offset 0x3C
	ELfanew int32
}

// imageFileHeader mirrors IMAGE_FILE_HEADER.
type imageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	_                    [12]byte // TimeDateStamp, SymbolTable, etc.
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// imageDataDirectory mirrors IMAGE_DATA_DIRECTORY.
type imageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// imageOptionalHeader64 mirrors IMAGE_OPTIONAL_HEADER64 (PE32+).
type imageOptionalHeader64 struct {
	Magic               uint16
	_                   [108 - 2]byte // skip to NumberOfRvaAndSizes
	NumberOfRvaAndSizes uint32
	DataDirectory       [imageNumberOfDirEntries]imageDataDirectory
}

// imageSectionHeader mirrors IMAGE_SECTION_HEADER.
type imageSectionHeader struct {
	Name             [imageSIZEOFShortName]byte
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	_                [12]byte // Relocations, Linenumbers
	_                [4]byte  // Characteristics
}

// peHeaders groups the parsed PE metadata needed for RVA resolution.
type peHeaders struct {
	fileHeader    imageFileHeader
	optionalHdr   imageOptionalHeader64
	sectionOffset int // byte offset in the raw file where section headers begin
}

// =============================================================================
// PE parsing helpers
// =============================================================================

// parsePEHeaders reads DOS, NT, and section headers from a raw PE file buffer.
// Returns a peHeaders struct or an error if the binary is malformed.
func parsePEHeaders(raw []byte) (*peHeaders, error) {
	if len(raw) < imageSIZEOFDosHdr {
		return nil, fmt.Errorf("file too small for DOS header (%d bytes)", len(raw))
	}

	dos := (*imageDosHeader)(unsafe.Pointer(&raw[0]))
	if dos.ELfanew <= 0 || int(dos.ELfanew) > len(raw)-4 {
		return nil, fmt.Errorf("invalid e_lfanew (%d)", dos.ELfanew)
	}

	// PE signature check.
	peOff := int(dos.ELfanew)
	if len(raw) < peOff+4 {
		return nil, fmt.Errorf("truncated PE signature")
	}
	sig := *(*uint32)(unsafe.Pointer(&raw[peOff]))
	if sig != imageNTSignature {
		return nil, fmt.Errorf("bad PE signature: 0x%08X (expected 0x%08X)", sig, imageNTSignature)
	}

	// File header follows the 4-byte signature.
	fileHdrOff := peOff + 4
	if len(raw) < fileHdrOff+imageSIZEOFFileHdr {
		return nil, fmt.Errorf("truncated file header")
	}
	fileHdr := (*imageFileHeader)(unsafe.Pointer(&raw[fileHdrOff]))

	// Sanity: we only support PE32+ for ntdll (64-bit).
	if fileHdr.SizeOfOptionalHeader < 2 {
		return nil, fmt.Errorf("SizeOfOptionalHeader too small (%d)", fileHdr.SizeOfOptionalHeader)
	}

	// Optional header follows the file header.
	optHdrOff := fileHdrOff + imageSIZEOFFileHdr
	if len(raw) < optHdrOff+int(fileHdr.SizeOfOptionalHeader) {
		return nil, fmt.Errorf("truncated optional header")
	}
	magic := *(*uint16)(unsafe.Pointer(&raw[optHdrOff]))
	if magic != imageNTOptionalHdr64 {
		return nil, fmt.Errorf("not PE32+ (magic=0x%04X)", magic)
	}
	if int(fileHdr.SizeOfOptionalHeader) < int(unsafe.Sizeof(imageOptionalHeader64{})) {
		return nil, fmt.Errorf("optional header too small for PE32+ (%d bytes)",
			fileHdr.SizeOfOptionalHeader)
	}
	optHdr := (*imageOptionalHeader64)(unsafe.Pointer(&raw[optHdrOff]))

	// Section headers follow the optional header.
	sectionOffset := optHdrOff + int(fileHdr.SizeOfOptionalHeader)

	return &peHeaders{
		fileHeader:    *fileHdr,
		optionalHdr:   *optHdr,
		sectionOffset: sectionOffset,
	}, nil
}

// findSection locates a section header by name.
func findSection(pe *peHeaders, raw []byte, name string) *imageSectionHeader {
	secOff := pe.sectionOffset
	for i := uint16(0); i < pe.fileHeader.NumberOfSections; i++ {
		off := secOff + int(i)*imageSIZOFSectionHdr
		if len(raw) < off+imageSIZOFSectionHdr {
			return nil
		}
		sec := (*imageSectionHeader)(unsafe.Pointer(&raw[off]))
		secName := cstring(sec.Name[:])
		if strings.EqualFold(secName, name) {
			return sec
		}
	}
	return nil
}

// parseExportTable walks the export directory and returns a map from
// exported name → RVA for every named export.
func parseExportTable(raw []byte, pe *peHeaders) (map[string]uint32, error) {
	exportDir := pe.optionalHdr.DataDirectory[imageDirEntryExport]
	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		return nil, fmt.Errorf("no export directory")
	}

	expOff, err := rvaToFileOffset(pe, exportDir.VirtualAddress, raw)
	if err != nil {
		return nil, fmt.Errorf("export dir RVA→offset: %w", err)
	}

	if len(raw) < expOff+40 {
		return nil, fmt.Errorf("truncated export directory")
	}

	// Parse IMAGE_EXPORT_DIRECTORY fields at known offsets.
	base := readU32(raw, expOff+16)
	numFuncs := readU32(raw, expOff+20)
	numNames := readU32(raw, expOff+24)
	eatRVA := readU32(raw, expOff+28) // AddressOfFunctions
	entRVA := readU32(raw, expOff+32) // AddressOfNames
	eotRVA := readU32(raw, expOff+36) // AddressOfNameOrdinals

	if numNames == 0 || eatRVA == 0 || entRVA == 0 || eotRVA == 0 {
		return nil, fmt.Errorf("export table missing required arrays")
	}

	// Convert export-table RVAs to file offsets.
	eatOff, err := rvaToFileOffset(pe, eatRVA, raw)
	if err != nil {
		return nil, fmt.Errorf("EAT RVA→offset: %w", err)
	}
	entOff, err := rvaToFileOffset(pe, entRVA, raw)
	if err != nil {
		return nil, fmt.Errorf("ENT RVA→offset: %w", err)
	}
	eotOff, err := rvaToFileOffset(pe, eotRVA, raw)
	if err != nil {
		return nil, fmt.Errorf("EOT RVA→offset: %w", err)
	}

	exports := make(map[string]uint32)

	for i := uint32(0); i < numNames; i++ {
		// Read the i-th entry in the name table.
		nameRVA := readU32(raw, entOff+int(i)*4)
		if nameRVA == 0 {
			continue
		}
		nameOff, err := rvaToFileOffset(pe, nameRVA, raw)
		if err != nil {
			continue
		}

		exportName := cstringFromBytes(raw[nameOff:])

		// Read the i-th ordinal (index into EAT).
		ordinal := readU16(raw, eotOff+int(i)*2)

		// Look up the function RVA in the EAT.
		eatIdx := uint32(ordinal) + base
		if eatIdx >= numFuncs {
			continue
		}
		funcRVA := readU32(raw, eatOff+int(eatIdx)*4)
		if funcRVA == 0 {
			continue
		}

		exports[exportName] = funcRVA
	}

	return exports, nil
}

// =============================================================================
// RVA / offset helpers
// =============================================================================

// rvaToFileOffset converts a virtual address (RVA) to a raw file offset
// using the section headers.
//
// For RVAs that fall within a section:
//
//	file_off = section.PointerToRawData + (rva - section.VirtualAddress)
//
// For RVAs in header regions (before the first section):
//
//	file_off = rva  (valid when FileAlignment == SectionAlignment)
func rvaToFileOffset(pe *peHeaders, rva uint32, raw []byte) (int, error) {
	secOff := pe.sectionOffset

	// Search sections.
	for i := uint16(0); i < pe.fileHeader.NumberOfSections; i++ {
		off := secOff + int(i)*imageSIZOFSectionHdr
		if len(raw) < off+imageSIZOFSectionHdr {
			break
		}
		sec := (*imageSectionHeader)(unsafe.Pointer(&raw[off]))

		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.VirtualSize {
			if sec.PointerToRawData == 0 {
				return 0, fmt.Errorf("section has no raw data (RVA=0x%08X)", rva)
			}
			return int(sec.PointerToRawData) + int(rva-sec.VirtualAddress), nil
		}
	}

	// RVA falls outside all sections — treat as header region.
	// This is valid for PE files where FileAlignment == SectionAlignment.
	return int(rva), nil
}

// =============================================================================
// Memory helpers
// =============================================================================

// getNtdllBase returns the base address of ntdll.dll in the current process,
// or 0 if the module handle cannot be obtained.
//
// Uses kernel32!GetModuleHandleW — a thin wrapper that we call directly
// rather than going through golang.org/x/sys/windows (which does not export
// this function).
func getNtdllBase() uintptr {
	ntdllName, err := windows.UTF16PtrFromString("ntdll.dll")
	if err != nil {
		return 0
	}
	handle, _, _ := procGetModuleHandle.Call(uintptr(unsafe.Pointer(ntdllName)))
	return handle
}

var procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")

// =============================================================================
// Byte helpers
// =============================================================================

// safeSlice returns a slice of up to n bytes starting at offset within buf,
// clamped to the buffer bounds.  If offset is out of bounds, returns nil.
func safeSlice(buf []byte, offset, n int) []byte {
	if offset < 0 || offset >= len(buf) {
		return nil
	}
	end := offset + n
	if end > len(buf) {
		end = len(buf)
	}
	return buf[offset:end]
}

// safeSliceFromPtr reads up to n bytes from an unsafe pointer.
// Returns nil if ptr is nil.
func safeSliceFromPtr(ptr unsafe.Pointer, n int) []byte {
	if ptr == nil {
		return nil
	}
	return unsafe.Slice((*byte)(ptr), n)
}

// readU32 reads a little-endian uint32 from raw[off:].  Returns 0 if the
// offset is out of bounds (caller should validate).
func readU32(raw []byte, off int) uint32 {
	if off < 0 || len(raw) < off+4 {
		return 0
	}
	return binary.LittleEndian.Uint32(raw[off:])
}

// readU16 reads a little-endian uint16 from raw[off:].
func readU16(raw []byte, off int) uint16 {
	if off < 0 || len(raw) < off+2 {
		return 0
	}
	return binary.LittleEndian.Uint16(raw[off:])
}

// cstring converts a null-terminated byte slice to a Go string.
func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// cstringFromBytes converts a null-terminated chunk of bytes to a Go string.
// It reads from offset 0 of the slice (the caller has already positioned).
func cstringFromBytes(b []byte) string {
	return cstring(b)
}

// byteSlicesEqual returns true if a and b have identical length and content.
// nil slices are treated as unequal (they represent errors in our context).
func byteSlicesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return false // empty slices here mean read failure
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// =============================================================================
// Data tables
// =============================================================================

// criticalNtFunctions lists NT syscall stubs most commonly hooked by EDR/AV
// products.  Each entry is the exported name as it appears in ntdll.dll
// (case-sensitive).
//
// Selection criteria:
//   - Memory management: Allocate, Protect, Write, Read, Map, Unmap
//   - Process / thread creation and manipulation
//   - Code injection primitives (QueueApc, SetContext, MapViewOfSection)
//   - Handle and token operations
//   - System information queries commonly monitored
var criticalNtFunctions = []string{
	// ── Memory management ────────────────────────────────────────────
	"NtAllocateVirtualMemory",
	"NtProtectVirtualMemory",
	"NtWriteVirtualMemory",
	"NtReadVirtualMemory",
	"NtQueryVirtualMemory",
	"NtFreeVirtualMemory",

	// ── Section / mapping (used for injection) ───────────────────────
	"NtCreateSection",
	"NtOpenSection",
	"NtMapViewOfSection",
	"NtUnmapViewOfSection",

	// ── Process creation & manipulation ──────────────────────────────
	"NtCreateProcess",
	"NtCreateProcessEx",
	"NtCreateUserProcess",
	"NtOpenProcess",
	"NtTerminateProcess",
	"NtSuspendProcess",
	"NtResumeProcess",

	// ── Thread creation & manipulation ───────────────────────────────
	"NtCreateThreadEx",
	"NtOpenThread",
	"NtSuspendThread",
	"NtResumeThread",
	"NtTerminateThread",
	"NtSetContextThread",
	"NtGetContextThread",
	"NtQueueApcThread",
	"NtAlertResumeThread",

	// ── Tokens & privileges ─────────────────────────────────────────
	"NtOpenProcessToken",
	"NtOpenThreadToken",
	"NtAdjustPrivilegesToken",
	"NtDuplicateToken",
	"NtSetInformationToken",

	// ── Handle operations ────────────────────────────────────────────
	"NtClose",
	"NtDuplicateObject",

	// ── System / process information queries ────────────────────────
	"NtQuerySystemInformation",
	"NtQueryInformationProcess",
	"NtSetInformationProcess",
	"NtQuerySystemTime",
	"NtQueryPerformanceCounter",

	// ── File / device I/O ───────────────────────────────────────────
	"NtCreateFile",
	"NtOpenFile",
	"NtReadFile",
	"NtWriteFile",
	"NtDeviceIoControlFile",
	"NtFsControlFile",

	// ── Additional injection / evasion surfaces ─────────────────────
	"NtCreateThread",
	"NtAllocateReserveObject",
	"NtSetInformationThread",
	"NtQueryInformationThread",
}
