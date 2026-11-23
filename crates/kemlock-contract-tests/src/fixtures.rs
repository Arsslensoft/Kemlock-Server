//! The recorded answers, in `fixtures/`: copied byte for byte from the Kemlock app, see
//! `fixtures/SOURCE.md`.

use serde_json::Value;
use std::path::PathBuf;

/// The folder the fixtures are in.
pub fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// A fixture's text; `relative` is a path under `fixtures/`, such as `webauthn/token.json`.
pub fn text(relative: &str) -> String {
    let path = dir().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the fixture {} can't be read: {e}", path.display()))
}

/// A fixture parsed as JSON.
pub fn json(relative: &str) -> Value {
    let text = text(relative);
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("the fixture {relative} is not JSON: {e}"))
}

/// `account-pbkdf2.json` or `account-argon2id.json`: `prelogin`, `token` and `sync` as a real
/// Vaultwarden 1.37.5 answered, and `expected`, what each item holds.
pub fn account(name: &str) -> Value {
    json(name)
}

/// Every string in `value`, with the path it is at, in document order. Keys are not strings here.
pub fn strings(value: &Value) -> Vec<(String, String)> {
    fn walk(path: &str, value: &Value, out: &mut Vec<(String, String)>) {
        match value {
            Value::String(text) => out.push((path.to_owned(), text.clone())),
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(&format!("{path}[{i}]"), item, out);
                }
            }
            Value::Object(map) => {
                for (key, item) in map {
                    walk(&format!("{path}.{key}"), item, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk("$", value, &mut out);
    out
}
