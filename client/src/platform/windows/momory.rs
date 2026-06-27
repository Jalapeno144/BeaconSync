use std::ptr::NonNull;

pub struct MemoryRegion {
    ptr: NonNull<u8>,
    size: usize,
}

impl MemoryRegion {
    // initialize a MemoryRegion Instance
    pub fn new(size: usize) -> Result<Self>;
    // 
    pub fn as_slice(&self) -> &[u8];

    pub fn as_mut_slice(&mut self) -> &mut [u8];

    pub fn protect(&self, protect: Protect) -> Result<()>;

    pub fn size(&self) -> usize;
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        // TODO
    }
}