//! The strict subset of JSON a space chain record is written in, so a record has exactly one
//! spelling (docs/crypto.md, "Space chain", "Encoding").
//!
//! Values are objects, arrays, strings, integers and booleans. A string holds only
//! `A-Z a-z 0-9 - _ :` and has no escape. An integer is `0` to `2^53 - 1` in decimal with no
//! leading zero. Member names are ASCII letters, strictly ascending. There is no whitespace and
//! no `null`.

/// The largest integer a record holds, `2^53 - 1`.
pub(crate) const MAX_INT: u64 = 9_007_199_254_740_991;
/// Objects nest at most this deep.
const MAX_OBJECT_DEPTH: usize = 6;
/// Objects and arrays together nest at most this deep, so a hostile record can't exhaust the stack.
const MAX_DEPTH: usize = 12;

/// A parsed value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Json {
    Obj(Vec<(String, Json)>),
    Arr(Vec<Json>),
    Str(String),
    Int(u64),
    Bool(bool),
}

impl Json {
    /// An object from members in any order; they are written in byte order of their names.
    pub(crate) fn obj(mut pairs: Vec<(&str, Json)>) -> Json {
        pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    pub(crate) fn str(text: &str) -> Json {
        Json::Str(text.to_owned())
    }
}

fn string_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b':')
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// Parses `bytes` as one object, with nothing before or after it.
pub(crate) fn parse(bytes: &[u8]) -> Result<Json, ()> {
    let mut parser = Parser { bytes, pos: 0 };
    let value = parser.value(0, 0)?;
    if parser.pos != bytes.len() || !matches!(value, Json::Obj(_)) {
        return Err(());
    }
    Ok(value)
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn eat(&mut self, c: u8) -> Result<(), ()> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    fn value(&mut self, depth: usize, objects: usize) -> Result<Json, ()> {
        if depth >= MAX_DEPTH {
            return Err(());
        }
        match self.peek().ok_or(())? {
            b'{' => self.object(depth, objects),
            b'[' => self.array(depth, objects),
            b'"' => Ok(Json::Str(self.string()?)),
            b'0'..=b'9' => Ok(Json::Int(self.int()?)),
            b't' => self.word(b"true", Json::Bool(true)),
            b'f' => self.word(b"false", Json::Bool(false)),
            _ => Err(()),
        }
    }

    fn word(&mut self, word: &[u8], value: Json) -> Result<Json, ()> {
        if self.bytes[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(())
        }
    }

    fn string(&mut self) -> Result<String, ()> {
        self.eat(b'"')?;
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == b'"' {
                let text = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| ())?;
                self.pos += 1;
                return Ok(text.to_owned());
            }
            if !string_byte(c) {
                return Err(());
            }
            self.pos += 1;
        }
        Err(())
    }

    fn int(&mut self) -> Result<u64, ()> {
        let start = self.pos;
        let mut value: u64 = 0;
        while let Some(c @ b'0'..=b'9') = self.peek() {
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(c - b'0')))
                .ok_or(())?;
            if value > MAX_INT {
                return Err(());
            }
            self.pos += 1;
        }
        // No leading zero: `0` alone is fine, `01` is not.
        if self.pos - start > 1 && self.bytes[start] == b'0' {
            return Err(());
        }
        Ok(value)
    }

    fn array(&mut self, depth: usize, objects: usize) -> Result<Json, ()> {
        self.eat(b'[')?;
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1, objects)?);
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(()),
            }
        }
    }

    fn object(&mut self, depth: usize, objects: usize) -> Result<Json, ()> {
        if objects >= MAX_OBJECT_DEPTH {
            return Err(());
        }
        self.eat(b'{')?;
        let mut pairs: Vec<(String, Json)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            let name = self.string()?;
            if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphabetic()) {
                return Err(());
            }
            // Strictly ascending: this refuses a name given twice and one out of order.
            if let Some((last, _)) = pairs.last()
                && name.as_bytes() <= last.as_bytes()
            {
                return Err(());
            }
            self.eat(b':')?;
            let value = self.value(depth + 1, objects + 1)?;
            pairs.push((name, value));
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(pairs));
                }
                _ => return Err(()),
            }
        }
    }
}

/// Appends the text of `value`.
pub(crate) fn write(value: &Json, out: &mut Vec<u8>) {
    match value {
        Json::Obj(pairs) => {
            out.push(b'{');
            for (i, (name, v)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.push(b'"');
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(b"\":");
                write(v, out);
            }
            out.push(b'}');
        }
        Json::Arr(items) => {
            out.push(b'[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(v, out);
            }
            out.push(b']');
        }
        Json::Str(text) => {
            out.push(b'"');
            out.extend_from_slice(text.as_bytes());
            out.push(b'"');
        }
        Json::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Json::Bool(true) => out.extend_from_slice(b"true"),
        Json::Bool(false) => out.extend_from_slice(b"false"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Json {
        parse(text.as_bytes()).unwrap_or_else(|()| panic!("{text} should parse"))
    }

    #[test]
    fn parses_and_writes_back_the_same_bytes() {
        let text = r#"{"a":1,"b":[true,false,"x-y:z"],"c":{"d":0},"e":{}}"#;
        let mut out = Vec::new();
        write(&ok(text), &mut out);
        assert_eq!(out, text.as_bytes());
    }

    #[test]
    fn obj_sorts_by_name_bytes() {
        let v = Json::obj(vec![
            ("b", Json::Int(2)),
            ("a", Json::Int(1)),
            ("B", Json::Int(0)),
        ]);
        let mut out = Vec::new();
        write(&v, &mut out);
        assert_eq!(out, br#"{"B":0,"a":1,"b":2}"#);
    }

    #[test]
    fn refuses_everything_outside_the_subset() {
        for bad in [
            r#"{"a":null}"#,
            r#"{"a":1.0}"#,
            r#"{"a":-1}"#,
            r#"{"a":-0}"#,
            r#"{"a":1e0}"#,
            r#"{"a":1E2}"#,
            r#"{"a":9007199254740992}"#,
            r#"{"a":01}"#,
            r#"{"a":"\ud800"}"#,
            r#"{"a":"a\nb"}"#,
            r#"{"a":"a b"}"#,
            "{\"a\":\"\u{e9}\"}",
            r#"{"a" :1}"#,
            r#"{"a": 1}"#,
            r#"{ "a":1}"#,
            "{\"a\":1}\n",
            " {\"a\":1}",
            "\u{feff}{\"a\":1}",
            r#"{"a":1,"a":2}"#,
            r#"{"b":1,"a":2}"#,
            r#"{"a":1,}"#,
            r#"{"1":1}"#,
            r#"{"":1}"#,
            r#"{"a":1}x"#,
            r#"[1]"#,
            r#"{"a":"x}"#,
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(parse(br#"{"a":9007199254740991}"#).is_ok());
    }

    #[test]
    fn limits_the_nesting() {
        let mut six = String::new();
        for _ in 0..6 {
            six.push_str(r#"{"a":"#);
        }
        six.push('1');
        six.push_str(&"}".repeat(6));
        assert!(parse(six.as_bytes()).is_ok());
        let seven = format!("{{\"a\":{six}}}");
        assert!(parse(seven.as_bytes()).is_err());

        let arrays = format!("{{\"a\":{}1{}}}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(parse(arrays.as_bytes()).is_err());
    }
}
