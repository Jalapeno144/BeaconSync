use std::ptr::NonNull;

use windows::core::Result;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_PROTECTION_FLAGS,
};

pub struct MemoryRegion {
    ptr: NonNull<u8>,
    size: usize,
}

/// Memory protection level for a [`MemoryRegion`].
///
/// Follows the **W^X** principle: `ExecuteReadWrite` exists for completeness
/// but should be avoided — never hold Write and Execute simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protect {
    ReadOnly,
    ReadWrite,
    Execute,
    ExecuteRead,
    ExecuteReadWrite,
    NoAccess,
}

impl Protect {
    fn to_page_protection(self) -> PAGE_PROTECTION_FLAGS {
        match self {
            Protect::ReadOnly => PAGE_READONLY,
            Protect::ReadWrite => PAGE_READWRITE,
            Protect::Execute => PAGE_EXECUTE,
            Protect::ExecuteRead => PAGE_EXECUTE_READ,
            Protect::ExecuteReadWrite => PAGE_EXECUTE_READWRITE,
            Protect::NoAccess => PAGE_NOACCESS,
        }
    }
}

impl MemoryRegion {
    /// Allocate a new memory region and initialize it with the given data.
    ///
    /// The region starts as `PAGE_READWRITE` so we can copy data in,
    /// then immediately drops to `final_protect`. This avoids a window
    /// where the caller forgets to call [`protect`](Self::protect).
    pub fn new_with_data(data: &[u8], final_protect: Protect) -> Result<Self> {
        let size = data.len();
        let region = Self::alloc(size, PAGE_READWRITE)?;

        // Copy data into the freshly allocated region
        // SAFETY: we just allocated `size` bytes, fully writable
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), region.ptr.as_ptr(), size);
        }

        // Immediately drop to the desired protection level
        if final_protect != Protect::ReadWrite {
            region.protect(final_protect)?;
        }

        Ok(region)
    }

    /// Allocate an empty (zeroed) region with the given protection.
    ///
    /// `VirtualAlloc` with `MEM_COMMIT` returns zeroed pages, so no
    /// separate zero-initialization is needed.
    pub fn new_zeroed(size: usize, protect: Protect) -> Result<Self> {
        Self::alloc(size, protect.to_page_protection())
    }

    /// Low-level allocation — caller chooses the exact page protection.
    fn alloc(size: usize, protect: PAGE_PROTECTION_FLAGS) -> Result<Self> {
        // SAFETY: VirtualAlloc with null base address lets the system choose
        // the allocation address. MEM_COMMIT | MEM_RESERVE both reserves and
        // commits the pages.
        let ptr = unsafe {
            VirtualAlloc(
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                protect,
            )
        };

        let ptr: NonNull<std::ffi::c_void> = NonNull::new(ptr).ok_or_else(|| {
            windows::core::Error::from_win32()
        })?;

        Ok(Self {
            ptr: ptr.cast::<u8>(),
            size,
        })
    }

    /// View the region as an immutable byte slice.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is always a valid, non-null pointer to `size` bytes
        // of committed memory for the lifetime of `self`.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    /// View the region as a mutable byte slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` is always a valid, non-null pointer to `size` bytes
        // of committed, writable memory for the lifetime of `self`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }

    /// Change the memory protection of the region.
    ///
    /// Use this to implement the **W^X** lifecycle:
    /// 1. Allocate with `ReadWrite` → write shellcode/data
    /// 2. Call `protect(ExecuteRead)` → execute
    /// 3. Never hold `Write` and `Execute` at the same time.
    pub fn protect(&self, protect: Protect) -> Result<()> {
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        // SAFETY: `ptr` points to valid committed memory of `size` bytes.
        unsafe {
            VirtualProtect(
                self.ptr.as_ptr().cast::<std::ffi::c_void>(),
                self.size,
                protect.to_page_protection(),
                &mut old_protect,
            )
        }
    }

    /// Return the size of the memory region in bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        // SAFETY: `ptr` was allocated via VirtualAlloc with MEM_COMMIT.
        // MEM_RELEASE frees the entire region; size must be 0.
        unsafe {
            let _ = VirtualFree(
                self.ptr.as_ptr().cast::<std::ffi::c_void>(),
                0,
                MEM_RELEASE,
            );
        }
    }
}
