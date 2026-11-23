//! Logging: text by default, JSON with `KEMLOCK_LOG_FORMAT=json`, written to stdout. `LOG_LEVEL`
//! (or a `tracing` filter such as `info,kemlock_api_kem=debug`) sets what is logged; `RUST_LOG`
//! is not read, so the Vaultwarden name is the one that works.

use crate::config::{Config, LogFormat};
use tracing_subscriber::EnvFilter;

/// The filter for a `LOG_LEVEL` value; a value that isn't a filter falls back to `info`.
pub fn filter(level: &str) -> EnvFilter {
    // Vaultwarden's "off" and "warning" spellings are not tracing's.
    let level = match level.trim().to_ascii_lowercase().as_str() {
        "warning" => "warn".to_owned(),
        other => other.to_owned(),
    };
    EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Starts logging. Call once, before anything logs.
pub fn init(config: &Config) {
    let filter = filter(&config.log_level);
    match config.log_format {
        LogFormat::Text => tracing_subscriber::fmt().with_env_filter(filter).init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_and_filters_parse_and_nonsense_falls_back() {
        for level in [
            "info",
            "debug",
            "warn",
            "warning",
            "error",
            "trace",
            "off",
            "info,hyper=warn",
        ] {
            assert!(EnvFilter::try_new(level).is_ok(), "{level}");
            let _ = filter(level);
        }
        // Not a level: still a filter (a target name), never a panic.
        let _ = filter("definitely not a level [");
    }
}
