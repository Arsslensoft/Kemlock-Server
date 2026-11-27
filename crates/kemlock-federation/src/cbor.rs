//! The deterministic CBOR subset every federation message uses.
//!
//! It is RFC 8949's core deterministic encoding (section 4.2.1) restricted to what a federation
//! message needs: unsigned integers, byte strings, text strings, arrays, and maps keyed by
//! unsigned integers. There are no floats, tags, simple values or indefinite lengths. An encoder
//! writes the shortest head and sorts map keys; a decoder refuses anything else, so a message has
//! exactly one encoding and can be signed or hashed as bytes.

use crate::error::{FedError, Result};

/// A decoded value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries with strictly ascending keys.
    Map(Vec<(u64, Value)>),
}

/// How deep arrays and maps may nest.
pub const MAX_DEPTH: u8 = 6;

/// How many values (integers, strings, arrays and maps, each counted once) one decoded message may
/// hold. A value takes tens of bytes in memory and one byte on the wire, so without a bound a
/// message of a few MiB of single-byte integers would take hundreds of MiB to decode. The largest
/// real message (a list of 4,096 grants) is under 20,000.
pub const MAX_VALUES: usize = 131_072;

impl Value {
    /// A map from entries in any order; they are sorted by key. A repeated key is a bug in the
    /// caller, and the later entry is dropped.
    pub fn map(mut entries: Vec<(u64, Value)>) -> Value {
        entries.sort_by_key(|(k, _)| *k);
        entries.dedup_by_key(|(k, _)| *k);
        Value::Map(entries)
    }

    pub fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }

    pub fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    pub fn flag(b: bool) -> Value {
        Value::Uint(u64::from(b))
    }

    /// The value's canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Value::Uint(n) => head(out, 0, *n),
            Value::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.write(out);
                }
            }
            Value::Map(entries) => {
                head(out, 5, entries.len() as u64);
                for (key, value) in entries {
                    head(out, 0, *key);
                    value.write(out);
                }
            }
        }
    }

    /// Parses exactly one value that fills `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Value> {
        let mut d = Decoder {
            rest: bytes,
            left: MAX_VALUES,
        };
        let value = d.value(0)?;
        if d.rest.is_empty() {
            Ok(value)
        } else {
            Err(FedError::Malformed("trailing bytes after a value"))
        }
    }

    pub fn as_uint(&self) -> Result<u64> {
        match self {
            Value::Uint(n) => Ok(*n),
            _ => Err(FedError::Malformed("expected an integer")),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(FedError::Malformed("expected a byte string")),
        }
    }

    pub fn as_text(&self) -> Result<&str> {
        match self {
            Value::Text(s) => Ok(s),
            _ => Err(FedError::Malformed("expected a text string")),
        }
    }

    pub fn as_array(&self) -> Result<&[Value]> {
        match self {
            Value::Array(a) => Ok(a),
            _ => Err(FedError::Malformed("expected an array")),
        }
    }

    pub fn as_flag(&self) -> Result<bool> {
        match self {
            Value::Uint(0) => Ok(false),
            Value::Uint(1) => Ok(true),
            _ => Err(FedError::Malformed("expected 0 or 1")),
        }
    }

    pub fn as_fields(&self) -> Result<Fields<'_>> {
        match self {
            Value::Map(entries) => Ok(Fields(entries)),
            _ => Err(FedError::Malformed("expected a map")),
        }
    }
}

/// Writes a head: the major type and the shortest form of the argument.
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if let Ok(v) = u8::try_from(n) {
        out.push(m | 24);
        out.push(v);
    } else if let Ok(v) = u16::try_from(n) {
        out.push(m | 25);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(n) {
        out.push(m | 26);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

struct Decoder<'a> {
    rest: &'a [u8],
    /// Values this decode may still make.
    left: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.rest.len() < n {
            return Err(FedError::Malformed("truncated"));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    /// Reads a head, refusing a longer form than the argument needs.
    fn head(&mut self) -> Result<(u8, u64)> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let info = first & 0x1f;
        let n = match info {
            0..=23 => u64::from(info),
            24 => {
                let v = u64::from(self.take(1)?[0]);
                if v < 24 {
                    return Err(FedError::Malformed("integer not in shortest form"));
                }
                v
            }
            25 => {
                let b = self.take(2)?;
                let v = u64::from(u16::from_be_bytes([b[0], b[1]]));
                if v < 256 {
                    return Err(FedError::Malformed("integer not in shortest form"));
                }
                v
            }
            26 => {
                let b = self.take(4)?;
                let v = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if v < 65_536 {
                    return Err(FedError::Malformed("integer not in shortest form"));
                }
                v
            }
            27 => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                let v = u64::from_be_bytes(a);
                if v < 4_294_967_296 {
                    return Err(FedError::Malformed("integer not in shortest form"));
                }
                v
            }
            _ => return Err(FedError::Malformed("indefinite or reserved head")),
        };
        Ok((major, n))
    }

    fn value(&mut self, depth: u8) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(FedError::Malformed("nested too deeply"));
        }
        self.left = self
            .left
            .checked_sub(1)
            .ok_or(FedError::Malformed("too many values"))?;
        let (major, n) = self.head()?;
        match major {
            0 => Ok(Value::Uint(n)),
            2 => {
                let len = usize::try_from(n).map_err(|_| FedError::Malformed("length"))?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = usize::try_from(n).map_err(|_| FedError::Malformed("length"))?;
                let raw = self.take(len)?;
                let s = std::str::from_utf8(raw)
                    .map_err(|_| FedError::Malformed("text is not UTF-8"))?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                let count = self.count(n)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let count = self.count(n)?;
                let mut entries: Vec<(u64, Value)> = Vec::with_capacity(count);
                for _ in 0..count {
                    let (kmajor, key) = self.head()?;
                    if kmajor != 0 {
                        return Err(FedError::Malformed("map keys are unsigned integers"));
                    }
                    if entries.last().is_some_and(|(last, _)| *last >= key) {
                        return Err(FedError::Malformed("map keys not strictly ascending"));
                    }
                    entries.push((key, self.value(depth + 1)?));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(FedError::Malformed("unsupported type")),
        }
    }

    /// An element count, which can't exceed the bytes left (each element takes at least one), so
    /// a hostile head can't make us reserve memory the input doesn't back.
    fn count(&self, n: u64) -> Result<usize> {
        let count = usize::try_from(n).map_err(|_| FedError::Malformed("count"))?;
        if count > self.rest.len() || count > self.left {
            return Err(FedError::Malformed("count exceeds the input"));
        }
        Ok(count)
    }
}

/// The entries of a decoded map, with typed getters.
#[derive(Clone, Copy, Debug)]
pub struct Fields<'a>(&'a [(u64, Value)]);

impl<'a> Fields<'a> {
    pub fn get(&self, key: u64) -> Option<&'a Value> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    pub fn req(&self, key: u64) -> Result<&'a Value> {
        self.get(key)
            .ok_or(FedError::Malformed("a required field is missing"))
    }

    pub fn uint(&self, key: u64) -> Result<u64> {
        self.req(key)?.as_uint()
    }

    pub fn flag(&self, key: u64) -> Result<bool> {
        self.req(key)?.as_flag()
    }

    pub fn bytes(&self, key: u64) -> Result<&'a [u8]> {
        self.req(key)?.as_bytes()
    }

    pub fn text(&self, key: u64) -> Result<&'a str> {
        self.req(key)?.as_text()
    }

    pub fn array(&self, key: u64) -> Result<&'a [Value]> {
        self.req(key)?.as_array()
    }

    /// A byte string of exactly `N` bytes.
    pub fn fixed<const N: usize>(&self, key: u64) -> Result<[u8; N]> {
        self.bytes(key)?
            .try_into()
            .map_err(|_| FedError::Malformed("a field has the wrong length"))
    }

    /// An array of text strings, at most `max` of them, each at most `max_len` bytes.
    pub fn texts(&self, key: u64, max: usize, max_len: usize) -> Result<Vec<String>> {
        let items = self.array(key)?;
        if items.len() > max {
            return Err(FedError::Malformed("too many entries"));
        }
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let s = item.as_text()?;
            if s.len() > max_len {
                return Err(FedError::Malformed("an entry is too long"));
            }
            out.push(s.to_owned());
        }
        Ok(out)
    }

    /// Refuses any key outside `allowed`: unknown fields are errors, not extensions.
    pub fn only(&self, allowed: &[u64]) -> Result<()> {
        if self.0.iter().all(|(k, _)| allowed.contains(k)) {
            Ok(())
        } else {
            Err(FedError::Malformed("unknown field"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_use_the_shortest_form() {
        assert_eq!(Value::Uint(23).encode(), [0x17]);
        assert_eq!(Value::Uint(24).encode(), [0x18, 24]);
        assert_eq!(Value::Uint(255).encode(), [0x18, 255]);
        assert_eq!(Value::Uint(256).encode(), [0x19, 1, 0]);
        assert_eq!(Value::Uint(65_536).encode(), [0x1a, 0, 1, 0, 0]);
        assert_eq!(
            Value::Uint(4_294_967_296).encode(),
            [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]
        );
    }

    #[test]
    fn rfc_8949_examples_encode_as_listed() {
        assert_eq!(
            Value::Uint(1_000_000).encode(),
            [0x1a, 0x00, 0x0f, 0x42, 0x40]
        );
        assert_eq!(Value::text("IETF").encode(), [0x64, 0x49, 0x45, 0x54, 0x46]);
        assert_eq!(Value::bytes(&[1, 2, 3, 4]).encode(), [0x44, 1, 2, 3, 4]);
        assert_eq!(
            Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)]).encode(),
            [0x83, 1, 2, 3]
        );
    }

    #[test]
    fn maps_sort_their_keys() {
        let v = Value::map(vec![(2, Value::Uint(1)), (0, Value::Uint(9))]);
        assert_eq!(v.encode(), [0xa2, 0x00, 0x09, 0x02, 0x01]);
    }

    #[test]
    fn values_round_trip() {
        let v = Value::map(vec![
            (0, Value::Uint(u64::MAX)),
            (1, Value::bytes(&[7; 300])),
            (2, Value::text("kfed1")),
            (
                3,
                Value::Array(vec![Value::text("a"), Value::Array(vec![])]),
            ),
            (300, Value::map(vec![(1, Value::flag(true))])),
        ]);
        assert_eq!(Value::decode(&v.encode()), Ok(v));
    }

    #[test]
    fn long_forms_are_refused() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0x18, 5],
            vec![0x19, 0, 5],
            vec![0x1a, 0, 0, 1, 0],
            vec![0x1b, 0, 0, 0, 0, 0, 0, 1, 0],
        ];
        for bad in cases {
            assert!(Value::decode(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn everything_else_unsupported_is_refused() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0x9f, 0xff],                                           // indefinite array
            vec![0x5f, 0xff],                                           // indefinite bytes
            vec![0x20],                                                 // negative integer
            vec![0xf4],                                                 // false
            vec![0xf9, 0, 0],                                           // float
            vec![0xc0, 0x00],                                           // tag
            vec![0xa1, 0x41, 0x00, 0],                                  // byte-string key
            vec![0xa2, 2, 0, 1, 0],                                     // keys not ascending
            vec![0xa2, 1, 0, 1, 0],                                     // repeated key
            vec![0x00, 0x00],                                           // trailing byte
            vec![0x62, 0xff, 0xff],                                     // invalid UTF-8
            vec![0x43, 1, 2],                                           // truncated
            vec![],                                                     // empty
            vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // huge count
        ];
        for bad in cases {
            assert!(Value::decode(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_number_of_values_in_a_message_is_bounded() {
        // An array of single-byte integers, as many as the bound allows, decodes; one more doesn't.
        let mut ok = vec![0x9a];
        ok.extend_from_slice(&u32::try_from(MAX_VALUES - 1).expect("small").to_be_bytes());
        ok.extend(std::iter::repeat_n(0u8, MAX_VALUES - 1));
        assert!(Value::decode(&ok).is_ok());
        let mut over = vec![0x9a];
        over.extend_from_slice(&u32::try_from(MAX_VALUES).expect("small").to_be_bytes());
        over.extend(std::iter::repeat_n(0u8, MAX_VALUES));
        assert!(Value::decode(&over).is_err());
        // Arrays of empty arrays can't get around it: every level counts.
        let mut wide = vec![0x9a];
        wide.extend_from_slice(&u32::try_from(MAX_VALUES).expect("small").to_be_bytes());
        wide.extend(std::iter::repeat_n(0x80u8, MAX_VALUES));
        assert!(Value::decode(&wide).is_err());
    }

    #[test]
    fn nesting_is_bounded() {
        let mut bytes = vec![0x81; usize::from(MAX_DEPTH) + 2];
        bytes.push(0);
        assert!(Value::decode(&bytes).is_err());
        let mut ok = vec![0x81; usize::from(MAX_DEPTH)];
        ok.push(0);
        assert!(Value::decode(&ok).is_ok());
    }

    #[test]
    fn fields_get_typed_values_and_refuse_extras() {
        let v = Value::map(vec![
            (0, Value::Uint(1)),
            (1, Value::bytes(&[1, 2, 3])),
            (2, Value::Array(vec![Value::text("x")])),
        ]);
        let f = v.as_fields().expect("a map");
        assert_eq!(f.uint(0), Ok(1));
        assert_eq!(f.fixed::<3>(1), Ok([1, 2, 3]));
        assert!(f.fixed::<4>(1).is_err());
        assert_eq!(f.texts(2, 4, 4), Ok(vec!["x".to_owned()]));
        assert!(f.texts(2, 0, 4).is_err());
        assert!(f.uint(9).is_err());
        assert!(f.only(&[0, 1, 2]).is_ok());
        assert!(f.only(&[0, 1]).is_err());
    }
}
