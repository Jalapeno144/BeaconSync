pub struct WaitableTimer {
    handle: HANDLE,
}

impl WaitableTimer {

    pub fn new() -> Result<Self>;

    pub fn sleep(duration: Duration) -> Result<()>;
}