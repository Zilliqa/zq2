//! When the `fake_time` feature is disabled, this module just re-exports [std::time::SystemTime].
//!
//! When the `fake_time` feature is enabled, an alternative fake [SystemTime] is exported, which can be controlled by
//! the `pause_at_epoch` and `advance` methods. This allows tests to run the system in a fully deterministic way.

#[cfg(not(feature = "fake_time"))]
pub type SystemTime = std::time::SystemTime;

pub type OffsetDateTime = time::OffsetDateTime;

#[cfg(feature = "fake_time")]
impl From<time_impl::SystemTime> for OffsetDateTime {
    fn from(time: time_impl::SystemTime) -> Self {
        let duration = time
            .duration_since(time_impl::SystemTime::UNIX_EPOCH)
            .unwrap();
        time::OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64).unwrap()
    }
}

#[cfg(feature = "fake_time")]
pub use time_impl::*;

#[cfg(feature = "fake_time")]
mod time_impl {
    use serde::{Deserialize, Serialize};
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex, OnceLock,
        },
        time::Duration,
    };

    /// A fake implementation of [std::time::SystemTime]. The value of `SystemTime::now` can be controlled with [advance_time].
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    pub struct SystemTime(std::time::SystemTime);

    impl SystemTime {
        pub const UNIX_EPOCH: SystemTime = SystemTime(std::time::SystemTime::UNIX_EPOCH);

        pub fn now() -> Self {
            let paused = PAUSED.load(Ordering::Acquire);
            if paused {
                // Time has been paused, get the fake time.
                let current_time = *CURRENT_TIME.get_or_init(Mutex::default).lock().unwrap();
                SystemTime(std::time::SystemTime::UNIX_EPOCH + current_time)
            } else {
                // Time has not been paused, use the real time.
                SystemTime(std::time::SystemTime::now())
            }
        }

        pub fn elapsed(&self) -> Result<Duration, SystemTimeError> {
            self.duration_since(SystemTime::now())
        }

        pub fn duration_since(&self, other: SystemTime) -> Result<Duration, SystemTimeError> {
            self.0
                .duration_since(other.0)
                .map_err(|e| SystemTimeError(e.duration()))
        }
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct SystemTimeError(Duration);

    impl SystemTimeError {
        pub fn duration(&self) -> Duration {
            self.0
        }
    }

    static PAUSED: AtomicBool = AtomicBool::new(false);
    /// Stores the duration between the currently set fake time time and the `UNIX_EPOCH`.
    static CURRENT_TIME: OnceLock<Mutex<Duration>> = OnceLock::new();

    /// Pause the fake time at the unix epoch.
    pub fn pause_at_epoch() {
        // Do not pause if it already paused
        if PAUSED.load(Ordering::Acquire) {
            return;
        }

        PAUSED.store(true, Ordering::Release);
        let mut current_time = CURRENT_TIME.get_or_init(Mutex::default).lock().unwrap();
        *current_time = Duration::ZERO;
    }

    /// Advance the fake time by this duration. Panics if time has not been paused with `pause_at_epoch()`.
    pub fn advance(delta: Duration) {
        let paused = PAUSED.load(Ordering::Acquire);
        if !paused {
            panic!("time is not paused");
        }
        let mut current_time = CURRENT_TIME.get_or_init(Mutex::default).lock().unwrap();
        *current_time += delta;
    }
}
