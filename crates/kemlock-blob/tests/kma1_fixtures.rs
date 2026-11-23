//! The header and length checks against the files the Kemlock app wrote.
//!
//! `tests/fixtures/` holds `kma1.json` and `two-chunks.kma1` byte for byte as the app's
//! `test/fixtures/attachments` has them (they pin the format other versions read, and
//! `.gitattributes` keeps them out of line-ending conversion). The server never opens a chunk,
//! so these tests check what it does check: the magic, the nonce prefix and the length.

use kemlock_blob::kma1::{self, Header, Kma1Error, StreamCheck};
use serde_json::Value;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Standard base64 with padding, as the fixture file writes bytes.
fn unbase64(text: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            other => panic!("not base64: {other}"),
        }
    };
    let digits: Vec<u8> = text.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for group in digits.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in group.iter().enumerate() {
            acc |= value(c) << (18 - 6 * i);
        }
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..group.len()]);
    }
    out
}

/// Every file of the fixture, as `(name, kma1 bytes)`.
fn files() -> Vec<(String, Vec<u8>)> {
    let json = std::fs::read_to_string(fixture_path("kma1.json")).expect("kma1.json is there");
    let doc: Value = serde_json::from_str(&json).expect("kma1.json is JSON");
    doc["files"]
        .as_array()
        .expect("a files list")
        .iter()
        .map(|file| {
            let name = file["name"].as_str().expect("a name").to_owned();
            let bytes = match file["kma1"].as_str() {
                Some(inline) => unbase64(inline),
                None => {
                    let path = file["kma1File"].as_str().expect("a kma1 or kma1File");
                    std::fs::read(fixture_path(path)).expect("the fixture file is there")
                }
            };
            (name, bytes)
        })
        .collect()
}

#[test]
fn the_decoder_reads_known_base64() {
    assert_eq!(unbase64("S01BMQ=="), b"KMA1");
    assert_eq!(unbase64("S01BMQE="), b"KMA1\x01");
    assert_eq!(unbase64("S01BMQEC"), b"KMA1\x01\x02");
}

#[test]
fn the_fixture_has_the_three_files() {
    let names: Vec<String> = files().into_iter().map(|(name, _)| name).collect();
    assert_eq!(names, ["empty", "short", "two chunks"]);
}

#[test]
fn every_fixture_file_has_a_valid_header_and_length() {
    for (name, bytes) in files() {
        Header::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        kma1::check_length(bytes.len() as u64).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn the_nonce_prefixes_are_the_ones_the_app_wrote() {
    let by_name: std::collections::HashMap<String, Vec<u8>> = files().into_iter().collect();
    let prefix = |name: &str| Header::parse(&by_name[name]).expect("valid").nonce_prefix;
    assert_eq!(prefix("empty"), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(prefix("short"), [9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(
        prefix("two chunks"),
        [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
    );
}

#[test]
fn the_sizes_are_those_of_the_plaintexts() {
    let by_name: std::collections::HashMap<String, Vec<u8>> = files().into_iter().collect();
    // The short file's plaintext is 27 bytes; the long one's is 65 636 bytes.
    assert_eq!(by_name["empty"].len() as u64, kma1::sealed_length(0));
    assert_eq!(by_name["short"].len() as u64, kma1::sealed_length(27));
    assert_eq!(
        by_name["two chunks"].len() as u64,
        kma1::sealed_length(65_636)
    );
    assert_eq!(by_name["two chunks"].len(), 65_680);
}

#[test]
fn the_stream_check_accepts_each_file_however_it_arrives() {
    for (name, bytes) in files() {
        for step in [1, 7, 4096, 65_552, 1 << 20] {
            let mut check = StreamCheck::new();
            for piece in bytes.chunks(step) {
                check
                    .push(piece)
                    .unwrap_or_else(|e| panic!("{name} in {step}s: {e}"));
            }
            let (_, total) = check.finish().unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(total, bytes.len() as u64);
        }
    }
}

#[test]
fn a_fixture_cut_short_or_changed_at_the_start_is_refused() {
    let (_, long) = files().pop().expect("the long file");
    // Cut inside a chunk's tag: the last chunk is then shorter than a tag.
    let cut = &long[..12 + 65_552 + 10];
    assert_eq!(
        kma1::check_length(cut.len() as u64),
        Err(Kma1Error::BadLength)
    );
    // Another file type: a ZIP's magic.
    let mut zip = long.clone();
    zip[..4].copy_from_slice(b"PK\x03\x04");
    assert_eq!(Header::parse(&zip), Err(Kma1Error::BadMagic));
    // Truncated to under a header.
    assert_eq!(Header::parse(&long[..11]), Err(Kma1Error::TooShort));
}
