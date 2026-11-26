//! The test vectors of `test-vectors/`: one JSON file per format, generated from fixed seeds and
//! checked against both backends.
//!
//! Every file is `{"format", "version", "description", "cases"}` with bytes as lower-case hex.
//! The generator (feature `vectors`) runs on the RustCrypto backend, the only one a seeded random
//! source can drive end to end; the checks run on every compiled-in backend.

use rand_core_06::{CryptoRng, RngCore};
use serde_json::{Value, json};

use crate::Error;

#[cfg(any(feature = "vectors", test))]
pub(crate) mod generate;

#[cfg(test)]
mod check;

#[cfg(any(feature = "vectors", test))]
pub(crate) mod sig1_edge;

#[cfg(any(feature = "vectors", test))]
pub(crate) mod space_chain;

#[cfg(any(feature = "vectors", test))]
pub(crate) mod normalise_cases;

/// The files, without their `.json`.
pub const FILES: &[&str] = &[
    "account-keys",
    "password-wrap",
    "argon2id",
    "kx1",
    "sealed-box",
    "sig1",
    "sig1-edge",
    "bundle",
    "kem1",
    "manifest",
    "dedup",
    "server-seal",
    "opaque",
    "legacy-ids",
    "dedup-normalise",
    "phrase",
    "private-keys",
    "prf-wrap",
    "confirm",
    "send",
    "space-names",
    "space-chain",
];

/// The version every file carries; bumping a format means a new label, not a new number here.
pub const VERSION: u64 = 1;

// Only the generator writes hex; a test build without the RustCrypto backend has no generator.
#[allow(dead_code)]
pub(crate) fn hx(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

/// Unpadded base64url, for the links and access ids of the Send vectors.
#[allow(dead_code)]
pub(crate) fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// A UUID as its hyphenated lower-case text.
pub(crate) fn uuid_text(id: &[u8; 16]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&id[..4]),
        hex::encode(&id[4..6]),
        hex::encode(&id[6..8]),
        hex::encode(&id[8..10]),
        hex::encode(&id[10..])
    )
}

pub(crate) fn document(format: &str, description: &str, cases: Vec<Value>) -> Value {
    json!({
        "format": format,
        "version": VERSION,
        "description": description,
        "cases": cases,
    })
}

/// A file's text: pretty-printed JSON with a final newline.
pub fn render(doc: &Value) -> Result<String, Error> {
    let mut text = serde_json::to_string_pretty(doc).map_err(|_| Error::invalid())?;
    text.push('\n');
    Ok(text)
}

/// A random source that hands out prepared chunks, one per draw, and refuses a draw whose length
/// isn't the next chunk's. It lets a vector pin the exact random inputs of an OPAQUE exchange.
#[derive(Debug)]
pub(crate) struct ScriptedRng {
    chunks: std::collections::VecDeque<Vec<u8>>,
}

impl ScriptedRng {
    pub(crate) fn new(chunks: Vec<Vec<u8>>) -> ScriptedRng {
        ScriptedRng {
            chunks: chunks.into(),
        }
    }
}

impl RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        panic!("a scripted random source was asked for a u32");
    }

    fn next_u64(&mut self) -> u64 {
        panic!("a scripted random source was asked for a u64");
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self.chunks.pop_front() {
            Some(chunk) if chunk.len() == dest.len() => dest.copy_from_slice(&chunk),
            Some(chunk) => panic!(
                "a scripted draw of {} bytes was asked for {}",
                chunk.len(),
                dest.len()
            ),
            None => panic!("a scripted random source ran out"),
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ScriptedRng {}

/// Writes every file and `SHA256SUMS` into `out`, creating it if needed.
#[cfg(feature = "vectors")]
pub fn write_all(out: &std::path::Path) -> Result<(), String> {
    use std::fmt::Write as _;

    let docs = generate::all().map_err(|e| format!("generating the vectors failed: {e}"))?;
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    // Lines for files made elsewhere (test-vectors/openapi.json, by kemlock-api-kem's tests) stay.
    let previous = std::fs::read_to_string(out.join("SHA256SUMS")).unwrap_or_default();
    let mut sums = String::new();
    for (name, doc) in &docs {
        let text = render(doc).map_err(|e| format!("{name}: {e}"))?;
        let file = format!("{name}.json");
        std::fs::write(out.join(&file), &text).map_err(|e| format!("{file}: {e}"))?;
        let digest = crate::hash::sha256(text.as_bytes());
        writeln!(sums, "{}  {file}", hex::encode(digest)).map_err(|e| e.to_string())?;
    }
    for line in previous.lines() {
        let made_here = line
            .split_once("  ")
            .is_some_and(|(_, file)| docs.iter().any(|(name, _)| format!("{name}.json") == file));
        if !made_here && !line.trim().is_empty() {
            writeln!(sums, "{line}").map_err(|e| e.to_string())?;
        }
    }
    std::fs::write(out.join("SHA256SUMS"), sums).map_err(|e| format!("SHA256SUMS: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_is_the_unpadded_url_alphabet() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn uuid_text_is_hyphenated() {
        let id = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        assert_eq!(uuid_text(&id), "01234567-89ab-cdef-0123-456789abcdef");
        assert!(crate::legacy_id::is_uuid(&uuid_text(&id)));
    }

    #[test]
    fn documents_carry_their_header() {
        let doc = document("x", "about x", vec![json!({"a": 1})]);
        assert_eq!(doc["format"], "x");
        assert_eq!(doc["version"], 1);
        assert_eq!(doc["description"], "about x");
        assert_eq!(doc["cases"][0]["a"], 1);
        assert!(render(&doc).expect("render").ends_with("}\n"));
    }

    #[test]
    fn the_scripted_source_hands_out_its_chunks_in_order() {
        let mut rng = ScriptedRng::new(vec![vec![1, 2], vec![3]]);
        let mut a = [0u8; 2];
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        assert_eq!((a, b), ([1, 2], [3]));
    }

    #[test]
    #[should_panic(expected = "ran out")]
    fn the_scripted_source_refuses_an_extra_draw() {
        ScriptedRng::new(vec![]).fill_bytes(&mut [0u8; 1]);
    }

    #[test]
    #[should_panic(expected = "was asked for")]
    fn the_scripted_source_refuses_a_draw_of_the_wrong_length() {
        ScriptedRng::new(vec![vec![1, 2]]).fill_bytes(&mut [0u8; 3]);
    }
}
