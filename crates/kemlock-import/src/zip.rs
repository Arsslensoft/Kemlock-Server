//! A ZIP reader for 1PUX, Dashlane and Proton Pass exports: stored and deflated entries, ZIP64
//! sizes, no encryption. It checks the limits before it allocates: the number of entries from the
//! directory, each entry's declared size, and the total inflated size, and the inflater is bounded
//! by the declared size so an entry can't claim a little and inflate to a lot.

use crate::error::{ImportError, Result};
use crate::limits::Limits;

const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const EOCD_LEN: usize = 22;

/// One file in the archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    /// The path inside the archive.
    pub name: String,
    method: u16,
    flags: u16,
    crc: u32,
    compressed: u64,
    size: u64,
    offset: u64,
}

impl ZipEntry {
    /// The inflated size the directory declares.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether the entry is a folder.
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

/// An open archive.
#[derive(Debug)]
pub struct Zip<'a> {
    data: &'a [u8],
    limits: &'a Limits,
    entries: Vec<ZipEntry>,
    inflated: usize,
}

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    let b = d.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(d: &[u8], at: usize) -> Option<u64> {
    let b = d.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn bad() -> ImportError {
    ImportError::malformed("the ZIP file is damaged")
}

/// Whether `data` starts like a ZIP file.
pub fn looks_like_zip(data: &[u8]) -> bool {
    data.starts_with(&[0x50, 0x4b, 0x03, 0x04])
        || data.starts_with(&[0x50, 0x4b, 0x05, 0x06])
        || data.starts_with(&[0x50, 0x4b, 0x07, 0x08])
}

impl<'a> Zip<'a> {
    /// Reads the directory of `data`. Refuses an archive over [`Limits::max_zip_bytes`] or listing
    /// more than [`Limits::max_zip_entries`] files.
    pub fn open(data: &'a [u8], limits: &'a Limits) -> Result<Zip<'a>> {
        limits.check_zip_input(data)?;
        if data.len() < EOCD_LEN {
            return Err(ImportError::Unsupported);
        }
        let first = data.len().saturating_sub(EOCD_LEN + 65_535);
        let mut eocd = None;
        let mut at = data.len() - EOCD_LEN;
        loop {
            if data.get(at..at + 4) == Some(&EOCD_SIGNATURE[..]) {
                eocd = Some(at);
                break;
            }
            if at == first {
                break;
            }
            at -= 1;
        }
        let eocd = eocd.ok_or(ImportError::Unsupported)?;

        let mut total = u64::from(u16_at(data, eocd + 10).ok_or_else(bad)?);
        let mut dir_size = u64::from(u32_at(data, eocd + 12).ok_or_else(bad)?);
        let mut dir_offset = u64::from(u32_at(data, eocd + 16).ok_or_else(bad)?);
        if total == 0xFFFF || dir_size == 0xFFFF_FFFF || dir_offset == 0xFFFF_FFFF {
            // ZIP64: the locator sits just before the end record.
            let locator = eocd.checked_sub(20).ok_or_else(bad)?;
            if data.get(locator..locator + 4) != Some(&[0x50, 0x4b, 0x06, 0x07][..]) {
                return Err(bad());
            }
            let record =
                usize::try_from(u64_at(data, locator + 8).ok_or_else(bad)?).map_err(|_| bad())?;
            if data.get(record..record.checked_add(4).ok_or_else(bad)?)
                != Some(&[0x50, 0x4b, 0x06, 0x06][..])
            {
                return Err(bad());
            }
            total = u64_at(data, record + 32).ok_or_else(bad)?;
            dir_size = u64_at(data, record + 40).ok_or_else(bad)?;
            dir_offset = u64_at(data, record + 48).ok_or_else(bad)?;
        }
        if total > limits.max_zip_entries as u64 {
            return Err(ImportError::LimitExceeded("files in the ZIP"));
        }
        let dir_offset = usize::try_from(dir_offset).map_err(|_| bad())?;
        let dir_end = dir_offset
            .checked_add(usize::try_from(dir_size).map_err(|_| bad())?)
            .ok_or_else(bad)?;
        let directory = data.get(dir_offset..dir_end).ok_or_else(bad)?;

        let mut entries = Vec::with_capacity(total as usize);
        let mut pos = 0usize;
        for _ in 0..total {
            if u32_at(directory, pos) != Some(0x0201_4b50) {
                return Err(bad());
            }
            let flags = u16_at(directory, pos + 8).ok_or_else(bad)?;
            let method = u16_at(directory, pos + 10).ok_or_else(bad)?;
            let crc = u32_at(directory, pos + 16).ok_or_else(bad)?;
            let mut compressed = u64::from(u32_at(directory, pos + 20).ok_or_else(bad)?);
            let mut size = u64::from(u32_at(directory, pos + 24).ok_or_else(bad)?);
            let name_len = usize::from(u16_at(directory, pos + 28).ok_or_else(bad)?);
            let extra_len = usize::from(u16_at(directory, pos + 30).ok_or_else(bad)?);
            let comment_len = usize::from(u16_at(directory, pos + 32).ok_or_else(bad)?);
            let mut offset = u64::from(u32_at(directory, pos + 42).ok_or_else(bad)?);
            let name_at = pos + 46;
            let name_bytes = directory.get(name_at..name_at + name_len).ok_or_else(bad)?;
            let extra_at = name_at + name_len;
            let extra = directory
                .get(extra_at..extra_at + extra_len)
                .ok_or_else(bad)?;
            if size == 0xFFFF_FFFF || compressed == 0xFFFF_FFFF || offset == 0xFFFF_FFFF {
                let mut cursor = 0usize;
                while cursor + 4 <= extra.len() {
                    let id = u16_at(extra, cursor).ok_or_else(bad)?;
                    let len = usize::from(u16_at(extra, cursor + 2).ok_or_else(bad)?);
                    if id == 1 {
                        let mut at = cursor + 4;
                        if size == 0xFFFF_FFFF {
                            size = u64_at(extra, at).ok_or_else(bad)?;
                            at += 8;
                        }
                        if compressed == 0xFFFF_FFFF {
                            compressed = u64_at(extra, at).ok_or_else(bad)?;
                            at += 8;
                        }
                        if offset == 0xFFFF_FFFF {
                            offset = u64_at(extra, at).ok_or_else(bad)?;
                        }
                        break;
                    }
                    cursor += 4 + len;
                }
            }
            entries.push(ZipEntry {
                name: String::from_utf8_lossy(name_bytes).into_owned(),
                method,
                flags,
                crc,
                compressed,
                size,
                offset,
            });
            pos = extra_at + extra_len + comment_len;
        }
        Ok(Zip {
            data,
            limits,
            entries,
            inflated: 0,
        })
    }

    /// The files, in directory order.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// The index of the file named exactly `name`.
    pub fn find(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.name == name)
    }

    /// Reads one file. Refuses an encrypted entry, a method other than stored and deflate, a
    /// declared size over [`Limits::max_entry_bytes`] or one that takes the total over
    /// [`Limits::max_inflated_bytes`], and data that doesn't match its declared size or checksum.
    pub fn read(&mut self, index: usize) -> Result<Vec<u8>> {
        let entry = self.entries.get(index).ok_or_else(bad)?.clone();
        if entry.flags & 1 != 0 {
            return Err(ImportError::UnsupportedEncryption(
                "a password-protected ZIP entry".to_string(),
            ));
        }
        if entry.size > self.limits.max_entry_bytes as u64 {
            return Err(ImportError::LimitExceeded("size of a file in the ZIP"));
        }
        let size = usize::try_from(entry.size).map_err(|_| bad())?;
        if self.inflated.saturating_add(size) > self.limits.max_inflated_bytes {
            return Err(ImportError::LimitExceeded("inflated size of the ZIP"));
        }
        let at = usize::try_from(entry.offset).map_err(|_| bad())?;
        if u32_at(self.data, at) != Some(0x0403_4b50) {
            return Err(bad());
        }
        let name_len = usize::from(u16_at(self.data, at + 26).ok_or_else(bad)?);
        let extra_len = usize::from(u16_at(self.data, at + 28).ok_or_else(bad)?);
        let start = at + 30 + name_len + extra_len;
        let compressed = usize::try_from(entry.compressed).map_err(|_| bad())?;
        let raw = self
            .data
            .get(start..start.checked_add(compressed).ok_or_else(bad)?)
            .ok_or_else(bad)?;
        let out = match entry.method {
            0 => {
                if raw.len() != size {
                    return Err(bad());
                }
                raw.to_vec()
            }
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(raw, size + 1)
                .map_err(|_| bad())?,
            _ => {
                return Err(ImportError::UnsupportedEncryption(
                    "a compression method the ZIP reader does not know".to_string(),
                ));
            }
        };
        if out.len() != size || crc32(&out) != entry.crc {
            return Err(bad());
        }
        self.inflated += size;
        Ok(out)
    }
}

/// CRC-32 (IEEE), as ZIP checks entries with.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Builds a ZIP with stored entries, for tests in this crate and in its fixtures.
#[cfg(test)]
pub(crate) fn build_stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for (name, data) in files {
        let offset = out.len() as u32;
        let crc = crc32(data);
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        directory.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        directory.extend_from_slice(&crc.to_le_bytes());
        directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&[0; 12]);
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let dir_offset = out.len() as u32;
    out.extend_from_slice(&directory);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    out.extend_from_slice(&dir_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn reads_stored_entries() {
        let zip = build_stored_zip(&[("a.txt", b"hello"), ("dir/b.txt", b"world!")]);
        let limits = Limits::default();
        let mut z = Zip::open(&zip, &limits).expect("open");
        assert_eq!(z.entries().len(), 2);
        let b = z.find("dir/b.txt").expect("find");
        assert_eq!(z.read(b).expect("read"), b"world!");
        assert_eq!(z.read(0).expect("read"), b"hello");
        assert!(z.find("missing").is_none());
        assert!(!z.entries()[0].is_dir());
    }

    #[test]
    fn reads_a_deflated_entry() {
        // "hello hello hello hello" as raw deflate (made with Node's zlib).
        let deflated = [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x01];
        let plain = b"hello hello hello hello";
        let crc = crc32(plain);
        let mut out = Vec::new();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
        out.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        out.extend_from_slice(&5u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(b"a.txt");
        out.extend_from_slice(&deflated);
        let dir_offset = out.len() as u32;
        let mut dir = Vec::new();
        dir.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        dir.extend_from_slice(&[20, 0, 20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
        dir.extend_from_slice(&crc.to_le_bytes());
        dir.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
        dir.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        dir.extend_from_slice(&5u16.to_le_bytes());
        dir.extend_from_slice(&[0; 12]);
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(b"a.txt");
        out.extend_from_slice(&dir);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        out.extend_from_slice(&(dir.len() as u32).to_le_bytes());
        out.extend_from_slice(&dir_offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);

        let limits = Limits::default();
        let mut z = Zip::open(&out, &limits).expect("open");
        assert_eq!(z.read(0).expect("read"), plain);
    }

    #[test]
    fn refuses_what_is_over_the_limits() {
        let zip = build_stored_zip(&[("a", b"1"), ("b", b"2"), ("c", b"3")]);
        let few = Limits {
            max_zip_entries: 2,
            ..Limits::default()
        };
        assert_eq!(
            Zip::open(&zip, &few).err(),
            Some(ImportError::LimitExceeded("files in the ZIP"))
        );

        let big = build_stored_zip(&[("a", &[7u8; 100])]);
        let small_entries = Limits {
            max_entry_bytes: 50,
            ..Limits::default()
        };
        let mut z = Zip::open(&big, &small_entries).expect("open");
        assert!(matches!(z.read(0), Err(ImportError::LimitExceeded(_))));

        let two = build_stored_zip(&[("a", &[7u8; 60]), ("b", &[8u8; 60])]);
        let total = Limits {
            max_inflated_bytes: 100,
            ..Limits::default()
        };
        let mut z = Zip::open(&two, &total).expect("open");
        assert!(z.read(0).is_ok());
        assert!(matches!(z.read(1), Err(ImportError::LimitExceeded(_))));

        let tiny = Limits {
            max_zip_bytes: 10,
            ..Limits::default()
        };
        assert!(matches!(
            Zip::open(&zip, &tiny),
            Err(ImportError::TooLarge { .. })
        ));
    }

    #[test]
    fn refuses_damage() {
        let limits = Limits::default();
        assert_eq!(
            Zip::open(b"", &limits).err(),
            Some(ImportError::Unsupported)
        );
        assert_eq!(
            Zip::open(&[0u8; 100], &limits).err(),
            Some(ImportError::Unsupported)
        );
        let mut zip = build_stored_zip(&[("a.txt", b"hello")]);
        // A flipped data byte fails the checksum.
        zip[35] ^= 1;
        let mut z = Zip::open(&zip, &limits).expect("open");
        assert!(matches!(z.read(0), Err(ImportError::Malformed(_))));
        // A truncated directory fails.
        let good = build_stored_zip(&[("a.txt", b"hello")]);
        let cut = &good[..good.len() - 30];
        assert!(Zip::open(cut, &limits).is_err());
    }

    #[test]
    fn a_lying_directory_size_is_caught() {
        // Declares 5 bytes stored but the data is 5: change the declared size to 4.
        let mut zip = build_stored_zip(&[("a.txt", b"hello")]);
        let at = zip.len() - 22 - (46 + 5) + 24;
        zip[at] = 4;
        let limits = Limits::default();
        let mut z = Zip::open(&zip, &limits).expect("open");
        assert!(z.read(0).is_err());
    }

    #[test]
    fn looks_like_zip_checks_the_signature() {
        assert!(looks_like_zip(b"PK\x03\x04abc"));
        assert!(!looks_like_zip(b"{\"a\":1}"));
    }
}
