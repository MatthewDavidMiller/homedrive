//! Single-range `Range: bytes=...` parsing (RFC 9110 §14.1.2).
//!
//! Media players seek and resume with one range at a time, so that is all
//! this serves. A multi-range request, an unknown unit, or a malformed
//! header is answered with the whole representation, which the RFC allows a
//! server to do for any Range it chooses to ignore.

/// What to send for a representation of `size` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeOutcome {
    /// The whole representation (200).
    Full,
    /// Bytes `start..=end` (206).
    Partial { start: u64, end: u64 },
    /// No byte of the range exists (416).
    Unsatisfiable,
}

pub fn parse_range(header: Option<&str>, size: u64) -> RangeOutcome {
    let Some(spec) = header.map(str::trim).and_then(|h| h.strip_prefix("bytes=")) else {
        return RangeOutcome::Full;
    };
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return RangeOutcome::Full;
    };
    let number = |s: &str| hd_common::buf::parse_u64(s.trim().as_bytes(), u64::MAX);
    match (first.trim().is_empty(), last.trim().is_empty()) {
        // "-n": the final n bytes.
        (true, false) => {
            let Some(n) = number(last) else { return RangeOutcome::Full };
            if n == 0 || size == 0 {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial { start: size.saturating_sub(n), end: size - 1 }
        }
        // "a-": from a to the end.
        (false, true) => {
            let Some(start) = number(first) else { return RangeOutcome::Full };
            if start >= size {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial { start, end: size - 1 }
        }
        // "a-b": inclusive, with b clamped to the end.
        (false, false) => {
            let (Some(start), Some(end)) = (number(first), number(last)) else {
                return RangeOutcome::Full;
            };
            if start > end {
                return RangeOutcome::Full;
            }
            if start >= size {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial { start, end: end.min(size - 1) }
        }
        (true, true) => RangeOutcome::Full,
    }
}

#[cfg(test)]
mod tests {
    use super::RangeOutcome::{Full, Partial, Unsatisfiable};
    use super::*;

    #[test]
    fn single_ranges() {
        assert_eq!(parse_range(None, 100), Full);
        assert_eq!(parse_range(Some("bytes=0-0"), 100), Partial { start: 0, end: 0 });
        assert_eq!(parse_range(Some("bytes=10-"), 100), Partial { start: 10, end: 99 });
        assert_eq!(parse_range(Some("bytes=10-1000"), 100), Partial { start: 10, end: 99 });
        assert_eq!(parse_range(Some("bytes=-10"), 100), Partial { start: 90, end: 99 });
        assert_eq!(parse_range(Some("bytes=-1000"), 100), Partial { start: 0, end: 99 });
        assert_eq!(parse_range(Some(" bytes= 5 - 6 "), 100), Partial { start: 5, end: 6 });
    }

    #[test]
    fn unsatisfiable_and_ignored_ranges() {
        assert_eq!(parse_range(Some("bytes=100-"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=200-300"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=-0"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=0-"), 0), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=5-4"), 100), Full);
        assert_eq!(parse_range(Some("bytes=0-1,5-6"), 100), Full);
        assert_eq!(parse_range(Some("items=0-1"), 100), Full);
        assert_eq!(parse_range(Some("bytes=a-b"), 100), Full);
        assert_eq!(parse_range(Some("bytes=-"), 100), Full);
        assert_eq!(parse_range(Some("bytes=+1-2"), 100), Full);
    }
}
