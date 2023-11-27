//! When the `fake_time` feature is disabled, this module just re-exports [std::time::SystemTime].
//!
//! When the `fake_time` feature is enabled, an alternative fake [SystemTime] is exported, which can be controlled by
//! the `pause_at_epoch` and `advance` methods. This allows tests to run the system in a fully deterministic way.

#[cfg(not(feature = "fake_time"))]
pub type SystemTime = std::time::SystemTime;

#[cfg(feature = "fake_time")]
pub use time_impl::*;

#[cfg(feature = "fake_time")]
mod time_impl {
    use futures::Future;
    use serde::{Deserialize, Serialize};
    use std::{error::Error, fmt, sync::Mutex, time::Duration};

    /// A fake implementation of [std::time::SystemTime]. The value of `SystemTime::now` can be controlled with [advance_time].
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    pub struct SystemTime(std::time::SystemTime);

    impl SystemTime {
        pub const UNIX_EPOCH: SystemTime = SystemTime(std::time::SystemTime::UNIX_EPOCH);

        pub fn now() -> Self {
            CURRENT_TIME
                .try_with(|current_time| {
                    let current_time = *current_time.lock().unwrap();
                    SystemTime(std::time::SystemTime::UNIX_EPOCH + current_time)
                })
                .unwrap_or_else(|_| {
                    // We are not within the scope of `with_fake_time()`, so use the real time.
                    SystemTime(std::time::SystemTime::now())
                })
        }

        pub fn elapsed(&self) -> Result<Duration, SystemTimeError> {
            self.duration_since(Self::UNIX_EPOCH)
        }

        pub fn duration_since(&self, other: SystemTime) -> Result<Duration, SystemTimeError> {
            println!("duration_since({:?}, {:?})", self, other);
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
    impl fmt::Display for SystemTimeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "second time provided was later than self")
        }
    }

    impl Error for SystemTimeError {
        fn description(&self) -> &str {
            "other time was not earlier than self"
        }
    }

    tokio::task_local! {
        /// Stores the duration between the currently set fake time time and the `UNIX_EPOCH`.
        static CURRENT_TIME: Mutex<Duration>;
    }

    pub fn with_fake_time<F: Future>(f: F) -> impl Future<Output = F::Output> {
        CURRENT_TIME.scope(Mutex::new(Duration::ZERO), f)
    }

    /// Advance the fake time by this duration. Panics if not called within the scope of `with_fake_time()`.
    pub fn advance(delta: Duration) {
        CURRENT_TIME.with(|current_time| {
            let mut current_time = current_time.lock().unwrap();
            *current_time += delta;
        });
    }
}
