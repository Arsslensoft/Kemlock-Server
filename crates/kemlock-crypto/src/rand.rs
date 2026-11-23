//! Random bytes from the operating system, through the active backend.

use crate::{
    Error,
    backend::{Active, Backend},
};

/// Fills `buf` with random bytes.
///
/// # Panics
///
/// If the operating system's random source fails, which leaves nothing safe to do.
pub fn fill(buf: &mut [u8]) {
    if try_fill::<Active>(buf).is_err() {
        panic!("the operating system's random source failed");
    }
}

/// Returns `N` random bytes.
///
/// # Panics
///
/// If the operating system's random source fails.
pub fn bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill(&mut out);
    out
}

/// Every random byte the formats use comes through here, so the test-vector generator can swap in a
/// seeded stream.
pub(crate) fn try_fill<B: Backend>(buf: &mut [u8]) -> Result<(), Error> {
    #[cfg(any(test, feature = "vectors"))]
    {
        if deterministic::try_fill(buf) {
            return Ok(());
        }
    }
    B::random(buf)
}

/// `N` random bytes, or an error when the random source fails.
pub(crate) fn try_bytes<B: Backend, const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    try_fill::<B>(&mut out)?;
    Ok(out)
}

/// A thread-local stand-in for the operating system's random source, for reproducible vectors and
/// tests. Compiled only for tests and the `vectors` feature.
#[cfg(any(test, feature = "vectors"))]
pub(crate) mod deterministic {
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::{RngCore as _, SeedableRng as _};
    use std::cell::RefCell;

    thread_local! {
        static SOURCE: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
    }

    /// Restores the operating system's source when dropped, even if the closure panics.
    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            SOURCE.with(|source| *source.borrow_mut() = None);
        }
    }

    /// Fills `buf` from the seeded stream and says `true`, or says `false` when none is set.
    pub(crate) fn try_fill(buf: &mut [u8]) -> bool {
        SOURCE.with(|source| match source.borrow_mut().as_mut() {
            Some(rng) => {
                rng.fill_bytes(buf);
                true
            }
            None => false,
        })
    }

    pub(crate) fn with_seed<R>(seed: [u8; 32], f: impl FnOnce() -> R) -> R {
        SOURCE.with(|source| *source.borrow_mut() = Some(ChaCha20Rng::from_seed(seed)));
        let _reset = Reset;
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_changes_the_buffer() {
        let a: [u8; 32] = bytes();
        let b: [u8; 32] = bytes();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn seeded_stream_is_reproducible_and_scoped() {
        let a = deterministic::with_seed([7; 32], bytes::<16>);
        let b = deterministic::with_seed([7; 32], bytes::<16>);
        let c = deterministic::with_seed([8; 32], bytes::<16>);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Outside the closure the operating system's source is back.
        assert_ne!(bytes::<16>(), bytes::<16>());
    }
}
