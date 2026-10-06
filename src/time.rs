//! The clock: seconds since the epoch, and how a time is written out.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const SECONDS_PER_DAY: u64 = 86_400;

/// Whole seconds since the epoch; 0 where the clock is set before it.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// `seconds` since the epoch as `YYYY-MM-DD HH:MM UTC`.
pub(crate) fn utc(seconds: u64) -> String {
    let days = seconds / SECONDS_PER_DAY;
    let rest = seconds % SECONDS_PER_DAY;
    // Days to a civil date (Howard Hinnant's algorithm), for dates after 1970.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_is_past_the_epoch_and_does_not_run_backwards() {
        let first = now();
        assert!(first > 1_700_000_000, "{first}");
        assert!(now() >= first);
    }

    #[test]
    fn times_are_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(59), "1970-01-01 00:00 UTC");
        assert_eq!(utc(SECONDS_PER_DAY - 1), "1970-01-01 23:59 UTC");
        assert_eq!(utc(SECONDS_PER_DAY), "1970-01-02 00:00 UTC");
        // A leap day, and the day after it.
        assert_eq!(utc(1_709_164_800), "2024-02-29 00:00 UTC");
        assert_eq!(utc(1_709_251_200), "2024-03-01 00:00 UTC");
        assert_eq!(utc(1_790_792_730), "2026-09-30 18:25 UTC");
    }
}
