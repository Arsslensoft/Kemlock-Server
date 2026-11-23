//! A structural comparator: it ignores every value and checks every key path, every type and the
//! casing of every key, and that no key is spelled twice in different cases.
//!
//! The apps read JSON by shape. Kemlock's Dart code matches keys with `jsonKey` in any case but
//! reads a number with `is int`, so `600000.0` where Vaultwarden sends `600000` would break the KDF
//! check (`mobile/lib/crypto/bitwarden.dart:45-58`). Amethystora refuses a key sent twice in
//! different cases (design, "Compatibility"). The fixtures are what Vaultwarden 1.37.5 sent.
//!
//! Rules, at every path:
//!
//! - `null` on either side matches anything: a field that is `null` for one item is a string for
//!   the next, and nothing below it can be compared.
//! - Otherwise the kinds must be equal: `boolean`, `integer`, `float`, `string`, `array`, `object`.
//! - Objects must have the same keys with the same casing ([`Mode::Exact`]), or at least those of
//!   the fixture ([`Mode::Subset`]), and none twice in different cases.
//! - Arrays are compared item by item against the fixture's items: each item must fit at least one
//!   of them. An empty array on either side compares nothing.

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// How strictly objects are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The same keys on both sides.
    Exact,
    /// Every key of the fixture is there; the server may send more.
    Subset,
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) => {
            if number.is_f64() {
                "float"
            } else {
                "integer"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// What differs between `expected` (a recorded answer of Vaultwarden) and `actual`, one line each;
/// empty when the shapes agree.
pub fn compare(expected: &Value, actual: &Value, mode: Mode) -> Vec<String> {
    let mut problems = Vec::new();
    walk("$", expected, actual, mode, &mut problems);
    problems
}

/// Panics with every difference found by [`compare`], under `what`.
pub fn assert_shape(what: &str, expected: &Value, actual: &Value, mode: Mode) {
    let problems = compare(expected, actual, mode);
    assert!(
        problems.is_empty(),
        "{what}: the shape differs from Vaultwarden 1.37.5's recorded answer:\n  {}\nanswer: {actual}",
        problems.join("\n  ")
    );
}

/// The paths of every object in `value` that spells one key in more than one case.
pub fn case_duplicates(value: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    find_duplicates("$", value, &mut problems);
    problems
}

/// Panics when [`case_duplicates`] finds one. Amethystora refuses a key sent twice in different
/// cases (design, "Compatibility").
pub fn assert_single_spelling(what: &str, value: &Value) {
    let problems = case_duplicates(value);
    assert!(
        problems.is_empty(),
        "{what}: every JSON key must be spelled once, Vaultwarden never sends one twice in \
         different cases, and Amethystora refuses it:\n  {}",
        problems.join("\n  ")
    );
}

fn find_duplicates(path: &str, value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            let mut seen: BTreeMap<String, Vec<&str>> = BTreeMap::new();
            for key in map.keys() {
                seen.entry(key.to_lowercase())
                    .or_default()
                    .push(key.as_str());
            }
            for names in seen.values() {
                if names.len() > 1 {
                    out.push(format!("{path}: {}", names.join(" and ")));
                }
            }
            for (key, item) in map {
                find_duplicates(&format!("{path}.{key}"), item, out);
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                find_duplicates(&format!("{path}[{i}]"), item, out);
            }
        }
        _ => {}
    }
}

fn walk(path: &str, expected: &Value, actual: &Value, mode: Mode, out: &mut Vec<String>) {
    let expected_kind = kind(expected);
    let actual_kind = kind(actual);
    if expected_kind != actual_kind {
        if expected_kind != "null" && actual_kind != "null" {
            out.push(format!(
                "{path}: Vaultwarden sends {expected_kind}, the server sends {actual_kind}"
            ));
        }
        return;
    }
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => walk_object(path, e, a, mode, out),
        (Value::Array(e), Value::Array(a)) => walk_array(path, e, a, mode, out),
        _ => {}
    }
}

fn walk_object(
    path: &str,
    expected: &Map<String, Value>,
    actual: &Map<String, Value>,
    mode: Mode,
    out: &mut Vec<String>,
) {
    let mut seen: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for key in actual.keys() {
        seen.entry(key.to_lowercase())
            .or_default()
            .push(key.as_str());
    }
    for names in seen.values() {
        if names.len() > 1 {
            out.push(format!(
                "{path}: the key is spelled more than once, as {}",
                names.join(" and ")
            ));
        }
    }
    for (key, expected_item) in expected {
        match actual.get(key) {
            Some(actual_item) => {
                walk(
                    &format!("{path}.{key}"),
                    expected_item,
                    actual_item,
                    mode,
                    out,
                );
            }
            None => match actual.keys().find(|name| name.eq_ignore_ascii_case(key)) {
                Some(other) => out.push(format!(
                    "{path}: Vaultwarden spells the key {key}, the server spells it {other}"
                )),
                None => out.push(format!("{path}.{key}: missing, Vaultwarden sends it")),
            },
        }
    }
    if mode == Mode::Exact {
        for key in actual.keys() {
            let known = expected.keys().any(|name| name.eq_ignore_ascii_case(key));
            if !known {
                out.push(format!("{path}.{key}: extra, Vaultwarden does not send it"));
            }
        }
    }
}

fn walk_array(path: &str, expected: &[Value], actual: &[Value], mode: Mode, out: &mut Vec<String>) {
    if expected.is_empty() || actual.is_empty() {
        return;
    }
    for (i, item) in actual.iter().enumerate() {
        let item_path = format!("{path}[{i}]");
        let mut best: Vec<String> = Vec::new();
        let mut matched = false;
        for shape in expected {
            let mut found = Vec::new();
            walk(&item_path, shape, item, mode, &mut found);
            if found.is_empty() {
                matched = true;
                break;
            }
            if best.is_empty() || found.len() < best.len() {
                best = found;
            }
        }
        if !matched {
            out.extend(best);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_same_shape_with_other_values_agrees() {
        let a = json!({"kdf": 0, "salt": null, "list": [{"id": "x"}], "n": {"a": true}});
        let b =
            json!({"kdf": 1, "salt": "s", "list": [{"id": "y"}, {"id": "z"}], "n": {"a": false}});
        assert!(compare(&a, &b, Mode::Exact).is_empty());
    }

    #[test]
    fn a_missing_key_a_wrong_type_and_a_float_are_found() {
        let a = json!({"kdf": 0, "name": "x", "inner": {"a": 1}});
        let b = json!({"kdf": 0.0, "inner": {}});
        let problems = compare(&a, &b, Mode::Exact);
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(
            problems
                .iter()
                .any(|p| p.contains("$.kdf") && p.contains("float"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("$.name") && p.contains("missing"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("$.inner.a") && p.contains("missing"))
        );
    }

    #[test]
    fn casing_is_a_difference_and_a_twice_spelled_key_is_found() {
        let a = json!({"Key": "x"});
        let b = json!({"key": "x"});
        let problems = compare(&a, &b, Mode::Exact);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("spells"));

        let twice = json!({"Key": "x", "key": "y", "ok": {"A": 1, "a": 2}});
        let found = case_duplicates(&twice);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(!compare(&json!({"Key": "x"}), &twice, Mode::Subset).is_empty());
    }

    #[test]
    fn subset_allows_extra_keys_and_exact_does_not() {
        let a = json!({"a": 1});
        let b = json!({"a": 1, "b": 2});
        assert!(compare(&a, &b, Mode::Subset).is_empty());
        assert_eq!(compare(&a, &b, Mode::Exact).len(), 1);
    }

    #[test]
    fn array_items_must_fit_one_of_the_fixtures_items() {
        let a = json!({"l": [{"x": 1}, {"y": "s"}]});
        assert!(compare(&a, &json!({"l": [{"y": "t"}]}), Mode::Exact).is_empty());
        assert!(!compare(&a, &json!({"l": [{"z": 1}]}), Mode::Exact).is_empty());
        assert!(compare(&a, &json!({"l": []}), Mode::Exact).is_empty());
    }
}
