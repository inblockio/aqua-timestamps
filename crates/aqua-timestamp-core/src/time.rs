//! Tiny clock abstraction so the seal task can be driven by a fixed time
//! in tests without leaning on `tokio::time::advance`.

/// Anything that can report a unix-seconds timestamp. Send + Sync so the
/// seal task can hold one for the lifetime of the process.
pub trait Clock: Send + Sync {
    fn now_secs(&self) -> u64;
}

/// Wall-clock implementation. Used by the binary in production.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Test clock that returns the value it was constructed with on every call.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(u64);

impl FixedClock {
    pub fn new(secs: u64) -> Self {
        Self(secs)
    }
}

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}
