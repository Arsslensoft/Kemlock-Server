//! A small CSV reader with the behaviour Bitwarden's importers rely on from Papa Parse: line
//! endings are normalised and the whole text trimmed first, the delimiter is found from the header
//! line, quoted fields may hold line breaks, and a row longer than the header keeps its extra
//! cells (RoboForm writes its form fields that way).
//!
//! Unlike Papa Parse with `skipEmptyLines: false`, a blank line gives no row at all; Bitwarden
//! turns each into an empty entry named "--".

use std::borrow::Cow;

use crate::context::Context;
use crate::error::{ImportError, Result};
use crate::util::decode_text;

/// Columns kept in one row; the rest of a longer row is dropped.
const MAX_COLUMNS: usize = 4096;

/// How to read a CSV.
#[derive(Debug, Clone, Copy, Default)]
pub struct CsvOptions {
    /// `\"` inside a quoted field is a quote (1Password's exports; Bitwarden sets Papa Parse's
    /// `escapeChar` to a backslash for them).
    pub backslash_escape: bool,
}

/// A parsed CSV: a header and the rows under it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    /// The first row.
    pub headers: Vec<String>,
    /// The other rows, none of them blank.
    pub rows: Vec<Vec<String>>,
    /// How many more rows there were past the limit, which were not read (counted by their line
    /// breaks, so a lower bound when blank lines come between them).
    pub unread: usize,
}

/// One row, read by column name.
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    headers: &'a [String],
    cells: &'a [String],
}

impl Table {
    /// Reads `text`, keeping at most `max_rows` rows below the header. An empty table is what text
    /// with no header gives.
    pub fn parse(text: &str, options: CsvOptions, max_rows: usize) -> Table {
        let text = normalise(text);
        let text = text.trim();
        if text.is_empty() {
            return Table::default();
        }
        let delimiter = detect_delimiter(text);
        let (mut rows, unread) = read_rows(text, delimiter, options.backslash_escape, max_rows);
        if rows.is_empty() {
            return Table::default();
        }
        let headers = rows.remove(0);
        Table {
            headers,
            rows,
            unread,
        }
    }

    /// The rows as records.
    pub fn records(&self) -> impl Iterator<Item = Record<'_>> {
        self.rows.iter().map(move |cells| Record {
            headers: &self.headers,
            cells,
        })
    }

    /// Whether a column is named exactly `name`.
    pub fn has(&self, name: &str) -> bool {
        self.headers.iter().any(|h| h == name)
    }

    /// Whether every one of `names` is a column.
    pub fn has_all(&self, names: &[&str]) -> bool {
        names.iter().all(|n| self.has(n))
    }

    /// Whether a column is named `name`, ignoring case.
    pub fn has_ci(&self, name: &str) -> bool {
        self.headers.iter().any(|h| h.eq_ignore_ascii_case(name))
    }
}

impl<'a> Record<'a> {
    /// The cell under the column named exactly `name`; `None` when the row has no such column or
    /// is too short to reach it (the `undefined` of the TypeScript). An empty cell is `Some("")`.
    pub fn get(&self, name: &str) -> Option<&'a str> {
        let at = self.headers.iter().position(|h| h == name)?;
        self.cells.get(at).map(String::as_str)
    }

    /// Like [`Record::get`], ignoring the case of the column name.
    pub fn get_ci(&self, name: &str) -> Option<&'a str> {
        let at = self
            .headers
            .iter()
            .position(|h| h.eq_ignore_ascii_case(name))?;
        self.cells.get(at).map(String::as_str)
    }

    /// The cells past the last header.
    pub fn extra(&self) -> &'a [String] {
        self.cells.get(self.headers.len()..).unwrap_or(&[])
    }

    /// Each column name with its cell, for the columns the row reaches.
    pub fn pairs(&self) -> impl Iterator<Item = (&'a str, &'a str)> + use<'a> {
        self.headers
            .iter()
            .zip(self.cells.iter())
            .map(|(h, c)| (h.as_str(), c.as_str()))
    }
}

/// What every CSV parser starts with: the size limit, the text decoded, the table read with at
/// most [`Limits::max_entries`](crate::limits::Limits::max_entries) rows. A file with no header is
/// [`ImportError::Unsupported`].
pub fn read_table(bytes: &[u8], ctx: &Context<'_>, options: CsvOptions) -> Result<Table> {
    ctx.limits.check_input(bytes)?;
    let text = decode_text(bytes);
    let table = Table::parse(&text, options, ctx.limits.max_entries);
    if table.headers.is_empty() {
        return Err(ImportError::Unsupported);
    }
    Ok(table)
}

/// The cells of one comma-separated line (Bitwarden's CSV keeps several addresses in one cell this
/// way). Empty for blank text.
pub fn split_row(text: &str) -> Vec<String> {
    let text = normalise(text);
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let (mut rows, _) = read_rows(text, ',', false, 0);
    if rows.is_empty() {
        Vec::new()
    } else {
        rows.remove(0)
    }
}

/// Line endings to `\n`.
fn normalise(text: &str) -> Cow<'_, str> {
    if !text.contains('\r') {
        return Cow::Borrowed(text);
    }
    Cow::Owned(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// The delimiter that appears most in the header line, outside quotes; a comma when none does.
fn detect_delimiter(text: &str) -> char {
    const CANDIDATES: [char; 4] = [',', ';', '\t', '|'];
    let mut counts = [0usize; 4];
    let mut in_quotes = false;
    for c in text.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == '\n' && !in_quotes {
            break;
        } else if !in_quotes && let Some(i) = CANDIDATES.iter().position(|d| *d == c) {
            counts[i] += 1;
        }
    }
    // The most common one; on a tie, the earlier in the list.
    let best = counts
        .iter()
        .enumerate()
        .max_by_key(|&(i, count)| (*count, std::cmp::Reverse(i)))
        .map(|(i, _)| i)
        .unwrap_or(0);
    if counts.get(best).copied().unwrap_or(0) == 0 {
        ','
    } else {
        CANDIDATES.get(best).copied().unwrap_or(',')
    }
}

fn read_rows(
    text: &str,
    delimiter: char,
    backslash: bool,
    max_rows: usize,
) -> (Vec<Vec<String>>, usize) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut at_start = true;
    let mut chars = text.chars().peekable();

    // The header counts as a row, so one more than `max_rows` is read.
    let limit = max_rows.saturating_add(1);

    let finish_row = |rows: &mut Vec<Vec<String>>, row: &mut Vec<String>, field: &mut String| {
        row.push(std::mem::take(field));
        let blank = row.len() == 1 && row[0].trim().is_empty();
        let done = std::mem::take(row);
        if !blank {
            rows.push(done);
        }
    };

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else if backslash && c == '\\' && chars.peek() == Some(&'"') {
                field.push('"');
                chars.next();
            } else {
                field.push(c);
            }
            at_start = false;
            continue;
        }
        if c == '"' && at_start {
            in_quotes = true;
            at_start = false;
        } else if c == delimiter {
            if row.len() < MAX_COLUMNS {
                row.push(std::mem::take(&mut field));
            } else {
                field.clear();
            }
            at_start = true;
        } else if c == '\n' {
            finish_row(&mut rows, &mut row, &mut field);
            at_start = true;
            if rows.len() >= limit {
                return (rows, count_rows(chars));
            }
        } else {
            field.push(c);
            at_start = false;
        }
    }
    if !field.is_empty() || !row.is_empty() {
        finish_row(&mut rows, &mut row, &mut field);
    }
    (rows, 0)
}

/// How many rows the rest of the text holds, by its line breaks outside quotes. The text was
/// trimmed, so its last line is a row.
fn count_rows(rest: impl Iterator<Item = char>) -> usize {
    let mut in_quotes = false;
    let mut rows = 1;
    let mut any = false;
    for c in rest {
        any = true;
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == '\n' && !in_quotes {
            rows += 1;
        }
    }
    if any { rows } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Table {
        Table::parse(text, CsvOptions::default(), 1000)
    }

    #[test]
    fn reads_quotes_commas_and_line_breaks_in_fields() {
        let t = parse("name,note\r\n\"a, b\",\"line1\r\nline2\"\r\n\"say \"\"hi\"\"\",x\r\n");
        assert_eq!(t.headers, ["name", "note"]);
        assert_eq!(t.rows.len(), 2);
        assert_eq!(t.rows[0], ["a, b", "line1\nline2"]);
        assert_eq!(t.rows[1], ["say \"hi\"", "x"]);
    }

    #[test]
    fn finds_the_delimiter_from_the_header() {
        let t = parse("a;b;c\n1;2;3");
        assert_eq!(t.headers, ["a", "b", "c"]);
        assert_eq!(t.rows[0], ["1", "2", "3"]);
        let t = parse("a\tb\n1\t2");
        assert_eq!(t.rows[0], ["1", "2"]);
    }

    #[test]
    fn a_delimiter_inside_quotes_in_the_header_does_not_count() {
        let t = parse("\"a;b;c;d\",e\n1,2");
        assert_eq!(t.headers, ["a;b;c;d", "e"]);
    }

    #[test]
    fn blank_lines_make_no_rows_and_empty_text_makes_an_empty_table() {
        let t = parse("a,b\n\n1,2\n\n\n");
        assert_eq!(t.rows.len(), 1);
        assert_eq!(parse("   \n ").headers.len(), 0);
        assert_eq!(parse("").rows.len(), 0);
    }

    #[test]
    fn a_short_row_has_no_cell_and_a_long_one_keeps_its_extra_cells() {
        let t = parse("a,b,c\n1\n1,2,3,4,5");
        let rows: Vec<Record<'_>> = t.records().collect();
        assert_eq!(rows[0].get("a"), Some("1"));
        assert_eq!(rows[0].get("b"), None);
        assert_eq!(rows[1].get("c"), Some("3"));
        assert_eq!(rows[1].extra(), ["4", "5"]);
        assert_eq!(rows[0].extra().len(), 0);
    }

    #[test]
    fn a_bom_free_text_with_a_quote_in_the_middle_of_a_field_keeps_it() {
        let t = parse("a,b\nx\"y,z");
        assert_eq!(t.rows[0], ["x\"y", "z"]);
    }

    #[test]
    fn backslash_escapes_a_quote_only_when_asked() {
        let t = Table::parse(
            "a,b\n\"he said \\\"hi\\\"\",x",
            CsvOptions {
                backslash_escape: true,
            },
            10,
        );
        assert_eq!(t.rows[0][0], "he said \"hi\"");
        let t = parse("a,b\n\"back\\\\slash\",x");
        assert_eq!(t.rows[0][0], "back\\\\slash");
    }

    #[test]
    fn stops_at_the_row_limit() {
        let t = Table::parse("a\n1\n2\n3\n4", CsvOptions::default(), 2);
        assert_eq!(t.rows.len(), 2);
        assert_eq!(t.unread, 2);
        let t = Table::parse("a\n1\n2", CsvOptions::default(), 2);
        assert_eq!(t.unread, 0);
    }

    #[test]
    fn an_unterminated_quote_reads_to_the_end() {
        let t = parse("a,b\n\"never closed,1\n2,3");
        assert_eq!(t.rows.len(), 1);
        assert!(t.rows[0][0].starts_with("never closed"));
    }

    #[test]
    fn lookup_by_name_ignores_case_only_when_asked() {
        let t = parse("Name,URL\nx,y");
        let r = t.records().next().expect("row");
        assert_eq!(r.get("name"), None);
        assert_eq!(r.get_ci("name"), Some("x"));
        assert!(t.has("URL") && !t.has("url") && t.has_ci("url"));
    }

    #[test]
    fn a_row_with_many_columns_is_cut() {
        let header = "a,b";
        let row = "x,".repeat(MAX_COLUMNS + 10);
        let t = parse(&format!("{header}\n{row}"));
        assert!(t.rows[0].len() <= MAX_COLUMNS + 1);
    }
}
