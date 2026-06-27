use std::time::Duration;

use windows::core::Result;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

pub struct WaitableTimer {
    handle: HANDLE,
}

impl WaitableTimer {
    pub fn new() -> Result<Self> {
        todo!();
    }
    pub fn set(&self, duration: Duration) -> Result<()> {
        todo!();
    }
    pub fn wait(&self) -> Result<()> {
        todo!();
    }
    pub fn sleep(duration: Duration) -> Result<()>{
        todo!();
    }

    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle); }
    }
}