//! UTC time helpers. Storage uses integer milliseconds.

use chrono::{DateTime, SecondsFormat, Utc};

/// Current UTC time in milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// Format a stored millisecond timestamp as RFC 3339 UTC.
pub fn format_rfc3339(ms: i64) -> String {
    match DateTime::<Utc>::from_timestamp_millis(ms) {
        Some(dt) => dt.to_rfc3339_opts(SecondsFormat::Millis, true),
        None => format!("invalid-timestamp({ms})"),
    }
}

/// Format a stored millisecond timestamp for compact human output.
pub fn format_short(ms: i64) -> String {
    match DateTime::<Utc>::from_timestamp_millis(ms) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("invalid-timestamp({ms})"),
    }
}
