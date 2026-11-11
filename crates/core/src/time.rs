//! Counter-to-time arithmetic shared by the POSIX and NT personalities.
//!
//! The kernel has two very different counters: the programmable interval timer,
//! which counts at [`crate::time::NANOS_PER_SECOND`]'s coarsest granularity, and
//! the timestamp counter, which counts at a rate that must be measured against
//! it. Everything that leaves the kernel to userspace is a `timespec`-shaped
//! instant, so the conversion lives here where a host test can exercise the
//! rounding and the saturation without a running kernel.

use crate::{Error, Result};

/// Nanoseconds in one second.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Size in bytes of the x64 `struct timespec` layout.
pub const TIMESPEC_SIZE: usize = 16;

/// A counter rate in ticks per second.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Frequency(u64);

impl Frequency {
    /// Validate a measured rate.
    ///
    /// Errors:
    /// - [`Error::InvalidInput`]: `hertz` is zero, so no tick can be converted.
    pub const fn new(hertz: u64) -> Result<Self> {
        if hertz == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self(hertz))
    }

    /// The rate in ticks per second.
    pub const fn hertz(self) -> u64 {
        self.0
    }

    /// Nanoseconds elapsed for `ticks` at this rate, saturating at `u64::MAX`.
    ///
    /// The intermediate product is 128-bit, so a counter that has run for
    /// centuries still converts instead of wrapping.
    pub fn nanos(self, ticks: u64) -> u64 {
        let nanos = (u128::from(ticks) * u128::from(NANOS_PER_SECOND)) / u128::from(self.0);
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }
}

/// A point in time expressed as seconds and nanoseconds since an epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Instant {
    /// Whole seconds since the epoch.
    pub seconds: u64,
    /// Nanoseconds inside the second, always below [`NANOS_PER_SECOND`].
    pub nanos: u32,
}

impl Instant {
    /// Split a nanosecond count, dropping anything past `u64::MAX` seconds.
    pub fn from_nanos(total: u64) -> Self {
        Self {
            seconds: total / NANOS_PER_SECOND,
            nanos: (total % NANOS_PER_SECOND) as u32,
        }
    }

    /// Convert a counter reading into an instant at `frequency`.
    pub fn from_ticks(frequency: Frequency, ticks: u64) -> Self {
        Self::from_nanos(frequency.nanos(ticks))
    }

    /// The instant as a nanosecond count, or `None` when it does not fit.
    pub fn to_nanos(self) -> Option<u64> {
        if self.nanos >= NANOS_PER_SECOND as u32 {
            return None;
        }
        self.seconds
            .checked_mul(NANOS_PER_SECOND)?
            .checked_add(u64::from(self.nanos))
    }

    /// Encode the 16-byte x64 `struct timespec` layout.
    ///
    /// Seconds are signed in the ABI. An instant this module can hold always
    /// fits when it is below `i64::MAX` seconds, which every realistic counter
    /// reading satisfies; anything larger saturates rather than wrapping into a
    /// negative time.
    pub fn encode(self) -> [u8; TIMESPEC_SIZE] {
        let seconds = i64::try_from(self.seconds).unwrap_or(i64::MAX);
        let mut bytes = [0u8; TIMESPEC_SIZE];
        bytes[0..8].copy_from_slice(&seconds.to_le_bytes());
        bytes[8..16].copy_from_slice(&i64::from(self.nanos).to_le_bytes());
        bytes
    }

    /// Decode the 16-byte x64 `struct timespec` layout.
    ///
    /// Errors:
    /// - [`Error::InvalidInput`]: seconds are negative or nanoseconds are out
    ///   of range.
    pub fn decode(bytes: &[u8; TIMESPEC_SIZE]) -> Result<Self> {
        let seconds = i64::from_le_bytes(field(bytes, 0));
        let nanos = i64::from_le_bytes(field(bytes, 8));
        if seconds < 0 {
            return Err(Error::InvalidInput);
        }
        let nanos = u32::try_from(nanos).map_err(|_| Error::InvalidInput)?;
        if nanos >= NANOS_PER_SECOND as u32 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            seconds: seconds as u64,
            nanos,
        })
    }
}

fn field(bytes: &[u8; TIMESPEC_SIZE], offset: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequency_converts_ticks_to_nanoseconds() {
        let gigahertz = Frequency::new(1_000_000_000).unwrap();
        assert_eq!(gigahertz.nanos(1), 1);
        assert_eq!(gigahertz.nanos(1_000_000_000), NANOS_PER_SECOND);
        let hundred_hertz = Frequency::new(100).unwrap();
        assert_eq!(hundred_hertz.nanos(1), 10_000_000);
    }

    #[test]
    fn frequency_rejects_zero() {
        assert_eq!(Frequency::new(0), Err(Error::InvalidInput));
        assert_eq!(Frequency::new(1).map(Frequency::hertz), Ok(1));
    }

    #[test]
    fn frequency_saturates_instead_of_wrapping() {
        let slow = Frequency::new(1).unwrap();
        assert_eq!(slow.nanos(u64::MAX), u64::MAX);
    }

    #[test]
    fn instant_splits_and_rejoins() {
        let instant = Instant::from_nanos(2_500_000_001);
        assert_eq!(instant.seconds, 2);
        assert_eq!(instant.nanos, 500_000_001);
        assert_eq!(instant.to_nanos(), Some(2_500_000_001));
    }

    #[test]
    fn instant_rejects_out_of_range_values() {
        assert_eq!(
            Instant {
                seconds: 0,
                nanos: 1_000_000_000
            }
            .to_nanos(),
            None
        );
        let mut bytes = [0u8; TIMESPEC_SIZE];
        bytes[0..8].copy_from_slice(&(-1i64).to_le_bytes());
        assert_eq!(Instant::decode(&bytes), Err(Error::InvalidInput));

        let mut bytes = [0u8; TIMESPEC_SIZE];
        bytes[8..16].copy_from_slice(&1_000_000_000i64.to_le_bytes());
        assert_eq!(Instant::decode(&bytes), Err(Error::InvalidInput));
    }

    #[test]
    fn timespec_encoding_round_trips() {
        let instant = Instant {
            seconds: 1234,
            nanos: 567_000_000,
        };
        let bytes = instant.encode();
        assert_eq!(Instant::decode(&bytes), Ok(instant));
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 1234);
    }

    #[test]
    fn timespec_encoding_saturates_seconds() {
        let instant = Instant {
            seconds: u64::MAX,
            nanos: 0,
        };
        let bytes = instant.encode();
        assert_eq!(
            i64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            i64::MAX
        );
    }

    #[test]
    fn ticks_convert_through_the_frequency() {
        let frequency = Frequency::new(100).unwrap();
        let instant = Instant::from_ticks(frequency, 250);
        assert_eq!(
            instant,
            Instant {
                seconds: 2,
                nanos: 500_000_000
            }
        );
    }
}
