//! Calendar arithmetic for the timestamps the status contract carries. The
//! conversion is the civil-from-days algorithm, so no time zone database or
//! locale is consulted: every instant is UTC.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Wall-clock time since the Unix epoch: whole seconds and nanoseconds.
pub fn wall_clock() -> (i64, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (i64::try_from(d.as_secs()).unwrap_or(i64::MAX), d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            if d.subsec_nanos() == 0 {
                (-secs, 0)
            } else {
                (-secs - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    }
}

/// Wall-clock seconds since the Unix epoch.
pub fn unix_seconds() -> i64 {
    wall_clock().0
}

/// Wall-clock milliseconds since the Unix epoch.
pub fn unix_ms() -> i64 {
    let (s, nanos) = wall_clock();
    s.saturating_mul(1000).saturating_add(i64::from(nanos / 1_000_000))
}

/// The proleptic Gregorian date of a day count since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let mut y = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let d = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let m = month_prime + if month_prime < 10 { 3 } else { -9 };
    if m <= 2 {
        y += 1;
    }
    (y, u32::try_from(m).unwrap_or(1), u32::try_from(d).unwrap_or(1))
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let m = i64::from(month);
    let day_of_year = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: i64,
    minute: i64,
    second: i64,
}

fn split(seconds: i64) -> Civil {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Civil { year, month, day, hour: rest / 3600, minute: rest % 3600 / 60, second: rest % 60 }
}

/// "YYYY-MM-DDTHH:MM:SS.mmmZ".
pub fn rfc3339_millis(seconds: i64, millis: u32) -> String {
    let c = split(seconds);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        millis % 1000
    )
}

/// The current wall-clock time as "YYYY-MM-DDTHH:MM:SS.mmmZ".
pub fn now_rfc3339_millis() -> String {
    let (seconds, nanos) = wall_clock();
    rfc3339_millis(seconds, nanos / 1_000_000)
}

/// The IMF-fixdate HTTP uses (RFC 9110 §5.6.7), such as
/// "Tue, 27 Oct 2026 14:05:00 GMT".
pub fn http_date(seconds: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let c = split(seconds);
    let weekday = DAYS[usize::try_from(seconds.div_euclid(86_400).rem_euclid(7)).unwrap_or(0)];
    let month = MONTHS[usize::try_from(c.month.saturating_sub(1)).unwrap_or(0).min(11)];
    format!(
        "{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT",
        c.day, c.year, c.hour, c.minute, c.second
    )
}

/// "YYYYMMDDTHHMMSSZ".
pub fn compact_utc(seconds: i64) -> String {
    let c = split(seconds);
    format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", c.year, c.month, c.day, c.hour, c.minute, c.second)
}

fn digits(s: &[u8], at: usize, n: usize) -> Option<u32> {
    let field = s.get(at..at + n)?;
    field.iter().try_fold(0_u32, |v, &c| c.is_ascii_digit().then(|| v * 10 + u32::from(c - b'0')))
}

fn leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Parses an RFC 3339 date-time (the form the time crate's Rfc3339 accepted):
/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`, case-insensitive T and
/// Z. Returns the instant as seconds and nanoseconds since the epoch.
pub fn parse_rfc3339(text: &str) -> Option<(i64, u32)> {
    const DAYS_IN: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let s = text.as_bytes();
    let year = digits(s, 0, 4)?;
    let month = digits(s, 5, 2)?;
    let day = digits(s, 8, 2)?;
    let hour = digits(s, 11, 2)?;
    let minute = digits(s, 14, 2)?;
    let second = digits(s, 17, 2)?;
    if s[4] != b'-'
        || s[7] != b'-'
        || !matches!(s[10], b'T' | b't')
        || s[13] != b':'
        || s[16] != b':'
    {
        return None;
    }
    if !(1..=12).contains(&month) || day < 1 {
        return None;
    }
    let dim = DAYS_IN[month as usize - 1] + u32::from(month == 2 && leap(i64::from(year)));
    // A leap second (:60) is accepted and folded into the next second, as the
    // time crate does for RFC 3339 input.
    if day > dim || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut p = 19;
    let mut frac: u32 = 0;
    if s.get(p) == Some(&b'.') {
        p += 1;
        let mut n = 0;
        while let Some(&c) = s.get(p).filter(|c| c.is_ascii_digit()) {
            if n < 9 {
                frac = frac * 10 + u32::from(c - b'0');
            }
            n += 1;
            p += 1;
        }
        if n == 0 {
            return None;
        }
        for _ in n..9 {
            frac *= 10;
        }
    }
    let offset: i64 = match s.get(p) {
        Some(b'Z' | b'z') => {
            p += 1;
            0
        }
        Some(&sign @ (b'+' | b'-')) => {
            let oh = digits(s, p + 1, 2)?;
            let om = digits(s, p + 4, 2)?;
            if s.get(p + 3) != Some(&b':') || oh > 23 || om > 59 {
                return None;
            }
            p += 6;
            i64::from(oh * 3600 + om * 60) * if sign == b'-' { -1 } else { 1 }
        }
        _ => return None,
    };
    if p != s.len() {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, day);
    let seconds = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second) - offset;
    Some((seconds, frac))
}

/// Milliseconds on the monotonic clock since an arbitrary fixed origin, for
/// deadlines.
pub fn now_ms() -> u64 {
    u64::try_from(origin().elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Seconds on the monotonic clock since an arbitrary fixed origin.
pub fn now_seconds() -> f64 {
    origin().elapsed().as_secs_f64()
}

/// Milliseconds left until a monotonic deadline, never negative.
pub fn remaining_ms(deadline_ms: u64) -> u64 {
    deadline_ms.saturating_sub(now_ms())
}

/// The origin [`now_ms`] counts from. It is set one second before first use,
/// so a deadline computed at start-up is never zero.
fn origin() -> Instant {
    static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *ORIGIN.get_or_init(|| {
        let now = Instant::now();
        now.checked_sub(Duration::from_secs(1)).unwrap_or(now)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(rfc3339_millis(0, 7), "1970-01-01T00:00:00.007Z");
        assert_eq!(rfc3339_millis(1_700_000_000, 999), "2023-11-14T22:13:20.999Z");
        assert_eq!(compact_utc(951_782_400), "20000229T000000Z");
        assert_eq!(rfc3339_millis(-1, 0), "1969-12-31T23:59:59.000Z");
    }

    #[test]
    fn civil_round_trips() {
        for days in [-800_000, -1, 0, 1, 11_016, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn http_dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_793_109_900), "Tue, 27 Oct 2026 14:05:00 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    #[test]
    fn parses_rfc3339() {
        assert_eq!(parse_rfc3339("2023-11-14T22:13:20Z"), Some((1_700_000_000, 0)));
        assert_eq!(parse_rfc3339("2023-11-14t22:13:20.5z"), Some((1_700_000_000, 500_000_000)));
        assert_eq!(parse_rfc3339("2023-11-14T23:13:20+01:00"), Some((1_700_000_000, 0)));
        assert_eq!(parse_rfc3339("2023-11-14T22:13:60Z"), Some((1_700_000_040, 0)));
        for bad in [
            "2023-02-29T00:00:00Z",
            "2023-11-14T22:13:20",
            "2023-11-14T22:13:20.Z",
            "2023-11-14 22:13:20Z",
            "2023-11-14T22:13:20+1:00",
            "2023-11-14T22:13:20Zx",
            "",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
        assert!(parse_rfc3339("2024-02-29T00:00:00Z").is_some());
    }
}
