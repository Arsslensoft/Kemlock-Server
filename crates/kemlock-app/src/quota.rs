//! Storage quotas, as Vaultwarden's `USER_ATTACHMENT_LIMIT`, `ORG_ATTACHMENT_LIMIT` and
//! `USER_SEND_LIMIT` work: a limit unset is no limit; one set to 0 switches the feature off; any
//! other is a number of bytes (the settings take KiB), counted against what the owner stores
//! already.
//!
//! Both APIs call [`check`] when a file or a file Send is announced. The Bitwarden API calls it again
//! when an attachment's bytes arrive, as Vaultwarden's `save_attachment` does, so a quota lowered in
//! between is held to there (the slot stays, as in Vaultwarden). A file Send is checked once, when it
//! is made, as in Vaultwarden, and the Kemlock API checks an attachment only when its upload starts.

/// Why a quota refuses a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaRefusal {
    /// The limit is 0: the feature is off for everyone.
    Disabled,
    /// Nothing is left of the limit.
    Reached,
    /// Some is left, but not enough for this file.
    Exceeded,
}

impl QuotaRefusal {
    /// What Vaultwarden says when an attachment is refused.
    pub fn attachment_message(self) -> &'static str {
        match self {
            QuotaRefusal::Disabled => "Attachments are disabled",
            QuotaRefusal::Reached => {
                "Attachment storage limit reached! Delete some attachments to free up space"
            }
            QuotaRefusal::Exceeded => "Attachment storage limit exceeded with this file",
        }
    }

    /// What Vaultwarden says when a file Send is refused.
    pub fn send_message(self) -> &'static str {
        match self {
            QuotaRefusal::Disabled => "File uploads are disabled",
            QuotaRefusal::Reached => {
                "Send storage limit reached! Delete some sends to free up space"
            }
            QuotaRefusal::Exceeded => "Send storage limit exceeded with this file",
        }
    }
}

/// Whether a file of `size` bytes fits a quota of `limit` bytes when `used` bytes are stored
/// already. `None` is no limit.
pub fn check(limit: Option<u64>, used: u64, size: u64) -> Result<(), QuotaRefusal> {
    let Some(limit) = limit else {
        return Ok(());
    };
    if limit == 0 {
        return Err(QuotaRefusal::Disabled);
    }
    let left = limit.saturating_sub(used);
    if left == 0 {
        return Err(QuotaRefusal::Reached);
    }
    if size > left {
        return Err(QuotaRefusal::Exceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limit_takes_anything() {
        assert_eq!(check(None, u64::MAX, u64::MAX), Ok(()));
    }

    #[test]
    fn a_limit_of_zero_switches_the_feature_off() {
        assert_eq!(check(Some(0), 0, 1), Err(QuotaRefusal::Disabled));
    }

    #[test]
    fn a_file_fits_what_is_left_and_not_a_byte_more() {
        assert_eq!(check(Some(1_000), 400, 600), Ok(()));
        assert_eq!(check(Some(1_000), 400, 601), Err(QuotaRefusal::Exceeded));
        assert_eq!(check(Some(1_000), 1_000, 1), Err(QuotaRefusal::Reached));
        // Over the limit already (the limit was lowered): nothing is left either.
        assert_eq!(check(Some(1_000), 5_000, 1), Err(QuotaRefusal::Reached));
    }
}
