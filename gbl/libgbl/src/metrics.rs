// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! GBL metrics and time traits.

use crate::{
    gbl_avb::MAX_PARTITIONS_TO_VERIFY,
    partition::{split_partition_suffix, RAW_PARTITION_NAME_LEN},
};
use arrayvec::{ArrayString, ArrayVec};
use core::fmt::{Display, Formatter};
use liberror::Result;

/// Interface for hardware timestamp and tick operations.
pub trait GblTime {
    /// Returns the current hardware tick.
    fn current_tick(&self) -> Result<u64>;

    /// Calculates the elapsed ticks since `start`, handling wrap-around.
    fn elapsed_ticks(&self, start: u64) -> Result<u64>;

    /// Converts a hardware tick delta to microseconds.
    fn ticks_to_us(&self, ticks: u64) -> u64;
}

/// Container for GBL metrics data.
#[derive(Default)]
pub struct GblMetrics {
    /// Start tick captured at entry.
    pub start_tick: Option<u64>,

    /// AVB verification time in hardware ticks.
    pub avb_ticks: Option<u64>,

    /// Per-partition I/O timings in hardware ticks: (Partition Name, Timing).
    pub io_timings_ticks:
        ArrayVec<(ArrayString<RAW_PARTITION_NAME_LEN>, u64), MAX_PARTITIONS_TO_VERIFY>,
}

impl GblMetrics {
    /// Creates a new instance of `GblMetrics`.
    pub fn new(start_tick: Option<u64>) -> Self {
        Self { start_tick, ..Default::default() }
    }

    /// Records AVB verification time.
    pub fn add_avb_ticks(&mut self, ticks: u64) {
        self.avb_ticks = Some(self.avb_ticks.unwrap_or(0).saturating_add(ticks));
    }

    /// Records an incremental duration for a specific partition I/O.
    pub fn add_io_timing_ticks(&mut self, name: &str, ticks: u64) {
        let base_name = split_partition_suffix(name).map(|(base, _)| base).unwrap_or(name);

        if let Some((_, timing)) =
            self.io_timings_ticks.iter_mut().find(|(part_name, _)| part_name == base_name)
        {
            *timing = timing.saturating_add(ticks);
        } else if let Ok(s) = ArrayString::<RAW_PARTITION_NAME_LEN>::try_from(base_name) {
            let _ = self.io_timings_ticks.try_push((s, ticks));
        }
    }
}

/// Represents a firmware version.
pub struct FirmwareVersion {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
}

impl Display for FirmwareVersion {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Type alias for tracking firmware versions.
pub type FirmwareVersionMetrics = ArrayVec<(&'static str, FirmwareVersion), 32>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gbl_metrics_new() {
        let metrics = GblMetrics::new(Some(100));

        assert_eq!(metrics.start_tick, Some(100));
        assert_eq!(metrics.avb_ticks, None);
        assert!(metrics.io_timings_ticks.is_empty());
    }

    #[test]
    fn test_add_avb_ticks() {
        let mut metrics = GblMetrics::default();

        metrics.add_avb_ticks(100);
        metrics.add_avb_ticks(200);

        assert_eq!(metrics.avb_ticks, Some(300));
    }

    #[test]
    fn test_add_avb_ticks_overflow() {
        let mut metrics = GblMetrics::default();

        metrics.add_avb_ticks(u64::MAX - 50);
        metrics.add_avb_ticks(100);

        assert_eq!(metrics.avb_ticks, Some(u64::MAX));
    }

    #[test]
    fn test_add_io_timing_ticks() {
        let mut metrics = GblMetrics::default();

        metrics.add_io_timing_ticks("boot", 100);
        metrics.add_io_timing_ticks("boot", 200);
        metrics.add_io_timing_ticks("vendor_boot", 50);

        assert_eq!(
            metrics.io_timings_ticks.as_slice(),
            [("boot".try_into().unwrap(), 300), ("vendor_boot".try_into().unwrap(), 50)]
        );
    }

    #[test]
    fn test_add_io_timing_ticks_overflow() {
        let mut metrics = GblMetrics::default();

        metrics.add_io_timing_ticks("boot", u64::MAX - 50);
        metrics.add_io_timing_ticks("boot", 100);

        assert_eq!(metrics.io_timings_ticks.as_slice(), [("boot".try_into().unwrap(), u64::MAX)]);
    }

    #[test]
    fn test_add_io_timing_ticks_split_suffix() {
        let mut metrics = GblMetrics::default();

        metrics.add_io_timing_ticks("boot_a", 100);
        metrics.add_io_timing_ticks("boot_b", 200);

        assert_eq!(metrics.io_timings_ticks.as_slice(), [("boot".try_into().unwrap(), 300)]);
    }
}
