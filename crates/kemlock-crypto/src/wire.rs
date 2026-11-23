//! The byte conventions of `docs/crypto.md`: `lp(x)`, big-endian integers, and a reader that checks
//! every length and refuses trailing bytes.

use crate::Error;

/// Appends `u32be(len(x)) ‖ x`.
pub(crate) fn lp(out: &mut Vec<u8>, x: &[u8]) -> Result<(), Error> {
    let len = u32::try_from(x.len()).map_err(|_| Error::invalid())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
    Ok(())
}

/// Copies a slice into an array, refusing any other length.
pub(crate) fn array<const N: usize>(s: &[u8]) -> Result<[u8; N], Error> {
    s.try_into().map_err(|_| Error::invalid())
}

/// Borrows a slice as an array, refusing any other length.
pub(crate) fn array_ref<const N: usize>(s: &[u8]) -> Result<&[u8; N], Error> {
    s.try_into().map_err(|_| Error::invalid())
}

/// Copies at most `N` bytes into a zero-filled array. For primitives whose output length is fixed.
pub(crate) fn fixed<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = N.min(s.len());
    out[..n].copy_from_slice(&s[..n]);
    out
}

/// A cursor over a byte string that never reads past the end.
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { rest: bytes }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.rest.len() < n {
            return Err(Error::invalid());
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        array(self.take(N)?)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// Fails unless every byte was read.
    pub(crate) fn finish(self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::invalid())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lp_prefixes_the_length() {
        let mut out = Vec::new();
        lp(&mut out, b"abc").expect("short");
        assert_eq!(out, [0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn array_checks_length() {
        assert_eq!(array::<2>(&[1, 2]), Ok([1, 2]));
        assert!(array::<2>(&[1]).is_err());
        assert!(array_ref::<2>(&[1, 2, 3]).is_err());
    }

    #[test]
    fn fixed_never_panics() {
        assert_eq!(fixed::<3>(&[1, 2]), [1, 2, 0]);
        assert_eq!(fixed::<1>(&[1, 2]), [1]);
    }

    #[test]
    fn reader_reads_and_refuses_trailing_bytes() {
        let mut r = Reader::new(&[1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.u32(), Ok(2));
        assert_eq!(r.u64(), Ok(3));
        assert!(r.finish().is_ok());

        let mut r = Reader::new(&[1, 2]);
        assert!(r.take(3).is_err());
        assert_eq!(r.u8(), Ok(1));
        assert!(r.finish().is_err());
    }
}
