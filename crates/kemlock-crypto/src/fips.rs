//! The FIPS build's start-up check (feature `fips`).
//!
//! Which library backs the formats is decided when the crate is built, not at run time, so there is
//! nothing to select here. What can still be wrong is the build: aws-lc-rs compiled without its own
//! `fips` feature (the workspace manifest turns it on only in the FIPS overlay), or a module that is
//! linked but not in FIPS mode. The first is refused at compile time below; [`verify`] covers the
//! second and is what the server should call before it serves a request.

use crate::Error;

// `aws_lc_rs::fips_mode` exists only when aws-lc-rs is built with its `fips` feature, so naming it
// here fails the compile of a `kemlock-crypto/fips` build whose aws-lc-rs isn't on the FIPS module.
// That is the silent fallback this guards against: the formats would still work, on a library whose
// certificate nobody holds.
const _: fn() = aws_lc_rs::fips_mode;

/// Checks that the linked aws-lc-rs is the AWS-LC FIPS module, in FIPS mode, and that it hashes.
///
/// # Errors
///
/// [`Error`] when the library isn't in FIPS mode or the hash check fails; the caller should refuse
/// to start.
pub fn verify() -> Result<(), Error> {
    aws_lc_rs::try_fips_mode().map_err(|_| Error::invalid())?;
    // The module's algorithms self-test on first use, so running one here moves a failure from the
    // first request to start-up.
    if crate::hash::sha256(b"abc")[..4] != [0xba, 0x78, 0x16, 0xbf] {
        return Err(Error::invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_module_is_linked_and_in_fips_mode() {
        verify().expect("aws-lc-rs is the FIPS module");
        assert!(aws_lc_rs::fips_version().is_some_and(|v| v >= 3));
    }
}
