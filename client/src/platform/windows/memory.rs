use std::ptr::NonNull;

pub struct MemoryRegion {
    ptr: NonNull<u8>,
    size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protect {
    ReadOnly,
    ReadWrite,
    Execute,
    ExecuteRead,
    ExecuteReadWrite,
    NoAccess,
}

impl MemoryRegion {
    // initialize a MemoryRegion Instance
    pub fn new(size: usize) -> Result<Self>{
        todo!();
    }
    // 
    pub fn as_slice(&self) -> &[u8] {
        todo!();
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        todo!();
    }

    pub fn protect(&self, protect: Protect) -> Result<()> {
        todo!();
    }

    pub fn size(&self) -> usize {
        todo!();
    }
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        // TODO
    }
}