//! The Migration screen's request checks. Reading and writing the Vaultwarden data is the
//! server's [`MigrationRunner`](kemlock_app::admin::MigrationRunner), which runs in the
//! background: a request is only checked here and handed over.

/// The longest source text accepted.
const MAX_SOURCE_LEN: usize = 1024;

/// Whether a source or files value is plausible text, before anything is opened.
pub(crate) fn text_ok(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_SOURCE_LEN
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_are_plausible_text() {
        assert!(text_ok("/data/vaultwarden"));
        assert!(text_ok("postgres://u:p@db/vw"));
        assert!(!text_ok(""));
        assert!(!text_ok("   "));
        assert!(!text_ok("a\nb"));
        assert!(!text_ok(&"x".repeat(2000)));
    }
}
