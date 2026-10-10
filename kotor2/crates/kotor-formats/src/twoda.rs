//! 2DA tables: binary V2.b (read and write) and text V2.0 (read and write).
//!
//! # Binary V2.b layout (from public documentation: xoreos, PyKotor)
//!
//! `"2DA V2.b\n"`; the column labels, each followed by a tab, then a NUL; the
//! row count (u32); the row labels, each followed by a tab; one u16 offset per
//! cell (row-major) into the string pool; the pool size (u16); the pool of
//! NUL-terminated strings. Identical cell strings share one pool entry. An
//! empty cell is the empty string (the text format writes it as `****`).
//!
//! # Round trips
//!
//! [`TwoDa::read_binary`] remembers the pool order; [`TwoDa::to_binary`]
//! emits still-used strings in that order and new strings after, in row-major
//! first-use order. An unmodified table whose pool held each string once comes
//! back byte-identical.

use std::collections::HashMap;

use crate::binio::{us, Bytes, Hint, Put};
use crate::error::{Error, Result};
use crate::text;

const FMT: &str = "2DA";
const BINARY_SIG: &[u8] = b"2DA V2.b\n";

/// A 2DA table.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct TwoDa {
    /// Column labels.
    pub columns: Vec<String>,
    /// Row labels (normally `"0"`, `"1"`, ...).
    pub row_labels: Vec<String>,
    /// Cells, `rows[row][column]`; an empty string is an empty cell.
    pub rows: Vec<Vec<String>>,
    /// The text format's `DEFAULT:` value, if any.
    pub default: Option<String>,
    pool: Hint<Vec<String>>,
}

fn split_tabs(s: &[u8]) -> Vec<String> {
    let mut v: Vec<String> = s.split(|&b| b == b'\t').map(text::decode).collect();
    if v.last().is_some_and(String::is_empty) {
        v.pop();
    }
    v
}

impl TwoDa {
    /// An empty table with these columns.
    pub fn new(columns: &[&str]) -> TwoDa {
        TwoDa {
            columns: columns.iter().map(|c| c.to_string()).collect(),
            ..Default::default()
        }
    }

    /// Parse either the binary or the text form, by signature.
    pub fn read(data: &[u8]) -> Result<TwoDa> {
        if data.starts_with(BINARY_SIG) {
            TwoDa::read_binary(data)
        } else if data.starts_with(b"2DA V2.0") || data.starts_with(b"2DA\tV2.0") {
            TwoDa::read_text(data)
        } else {
            Err(Error::BadSignature {
                format: FMT,
                found: String::from_utf8_lossy(data.get(..9).unwrap_or(data)).into_owned(),
                expected: "2DA V2.b or 2DA V2.0",
            })
        }
    }

    /// Parse the binary V2.b form.
    pub fn read_binary(data: &[u8]) -> Result<TwoDa> {
        let b = Bytes::new(data, FMT);
        if !data.starts_with(BINARY_SIG) {
            return Err(Error::BadSignature {
                format: FMT,
                found: String::from_utf8_lossy(data.get(..9).unwrap_or(data)).into_owned(),
                expected: "2DA V2.b",
            });
        }
        let mut pos = BINARY_SIG.len();
        let nul = data[pos..]
            .iter()
            .position(|&c| c == 0)
            .ok_or_else(|| Error::invalid(FMT, "column header has no terminating NUL"))?;
        let columns = split_tabs(&data[pos..pos + nul]);
        pos += nul + 1;
        let row_count = us(b.u32(pos)?);
        pos += 4;
        let mut row_labels = Vec::with_capacity(row_count.min(1 << 16));
        for r in 0..row_count {
            let tab = data
                .get(pos..)
                .and_then(|s| s.iter().position(|&c| c == b'\t'))
                .ok_or_else(|| {
                    Error::invalid(FMT, format!("row label {r} has no terminating tab"))
                })?;
            row_labels.push(text::decode(&data[pos..pos + tab]));
            pos += tab + 1;
        }
        let cells = row_count
            .checked_mul(columns.len())
            .ok_or_else(|| Error::invalid(FMT, "cell count overflows"))?;
        let offsets_at = pos;
        b.slice(offsets_at, cells * 2)?;
        pos += cells * 2;
        let pool_size = usize::from(b.u16(pos)?);
        pos += 2;
        let pool = b.slice(pos, pool_size).map_err(|_| {
            Error::invalid(FMT, format!("string pool ({pool_size} bytes at {pos}) runs past the end of the file ({} bytes)", data.len()))
        })?;
        let mut cache: HashMap<usize, String> = HashMap::new();
        let mut rows = Vec::with_capacity(row_count);
        for r in 0..row_count {
            let mut row = Vec::with_capacity(columns.len());
            for c in 0..columns.len() {
                let off = usize::from(b.u16(offsets_at + 2 * (r * columns.len() + c))?);
                let s = match cache.get(&off) {
                    Some(s) => s.clone(),
                    None => {
                        let rest = pool.get(off..).ok_or_else(|| {
                            Error::invalid(FMT, format!("cell ({r}, {c}) offset {off} is past the string pool ({pool_size} bytes)"))
                        })?;
                        let end = rest.iter().position(|&ch| ch == 0).ok_or_else(|| {
                            Error::invalid(
                                FMT,
                                format!("cell ({r}, {c}) string at {off} has no terminating NUL"),
                            )
                        })?;
                        let s = text::decode(&rest[..end]);
                        cache.insert(off, s.clone());
                        s
                    }
                };
                row.push(s);
            }
            rows.push(row);
        }
        let mut by_offset: Vec<(usize, String)> = cache.into_iter().collect();
        by_offset.sort();
        Ok(TwoDa {
            columns,
            row_labels,
            rows,
            default: None,
            pool: Hint(by_offset.into_iter().map(|(_, s)| s).collect()),
        })
    }

    /// Parse the text V2.0 form. `****` cells become empty strings; quoted
    /// cells may contain spaces.
    pub fn read_text(data: &[u8]) -> Result<TwoDa> {
        let s = text::decode(data);
        let mut lines = s.lines();
        let first = lines.next().unwrap_or_default();
        if !first.trim_start().starts_with("2DA") || !first.contains("V2.0") {
            return Err(Error::BadSignature {
                format: FMT,
                found: first.chars().take(16).collect(),
                expected: "2DA V2.0",
            });
        }
        let mut t = TwoDa::default();
        let mut header_seen = false;
        for (n, line) in lines.enumerate() {
            let line_no = n + 2;
            let toks = tokenize(line);
            if toks.is_empty() {
                continue;
            }
            if !header_seen {
                if toks[0].eq_ignore_ascii_case("DEFAULT:") {
                    t.default = toks.get(1).cloned();
                    continue;
                }
                if let Some(rest) = line.trim_start().strip_prefix("DEFAULT:") {
                    t.default = Some(rest.trim().to_string());
                    continue;
                }
                t.columns = toks;
                header_seen = true;
                continue;
            }
            let mut toks = toks.into_iter();
            let label = toks.next().unwrap_or_default();
            let mut row: Vec<String> = toks
                .map(|v| if v == "****" { String::new() } else { v })
                .collect();
            if row.len() > t.columns.len() {
                return Err(Error::invalid(
                    FMT,
                    format!(
                        "line {line_no}: {} cells but {} columns",
                        row.len(),
                        t.columns.len()
                    ),
                ));
            }
            row.resize(t.columns.len(), String::new());
            t.row_labels.push(label);
            t.rows.push(row);
        }
        if !header_seen {
            return Err(Error::invalid(FMT, "no column header line"));
        }
        Ok(t)
    }

    /// Index of a column (case-insensitive).
    pub fn column(&self, name: &str) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| c.eq_ignore_ascii_case(name))
    }

    /// A cell by row index and column name. `None` for a missing row/column;
    /// `Some("")` for an empty cell.
    pub fn get(&self, row: usize, column: &str) -> Option<&str> {
        let c = self.column(column)?;
        self.rows.get(row)?.get(c).map(String::as_str)
    }

    /// Set a cell; fails if the row or column does not exist.
    pub fn set(&mut self, row: usize, column: &str, value: impl Into<String>) -> Result<()> {
        let c = self
            .column(column)
            .ok_or_else(|| Error::NotFound(format!("2DA column {column}")))?;
        let cell = self
            .rows
            .get_mut(row)
            .and_then(|r| r.get_mut(c))
            .ok_or_else(|| Error::NotFound(format!("2DA row {row}")))?;
        *cell = value.into();
        Ok(())
    }

    /// Append a row labelled with its index; returns the index.
    pub fn push_row(&mut self, cells: Vec<String>) -> usize {
        let mut cells = cells;
        cells.resize(self.columns.len(), String::new());
        let i = self.rows.len();
        self.row_labels.push(i.to_string());
        self.rows.push(cells);
        i
    }

    fn check_shape(&self) -> Result<()> {
        if self.rows.len() != self.row_labels.len() {
            return Err(Error::invalid(
                FMT,
                format!(
                    "{} rows but {} row labels",
                    self.rows.len(),
                    self.row_labels.len()
                ),
            ));
        }
        if let Some((i, r)) = self
            .rows
            .iter()
            .enumerate()
            .find(|(_, r)| r.len() != self.columns.len())
        {
            return Err(Error::invalid(
                FMT,
                format!(
                    "row {i} has {} cells, expected {}",
                    r.len(),
                    self.columns.len()
                ),
            ));
        }
        Ok(())
    }

    /// Serialize to binary V2.b.
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        self.check_shape()?;
        let mut out = Vec::new();
        out.extend_from_slice(BINARY_SIG);
        for c in &self.columns {
            out.extend_from_slice(&text::encode(c, "2DA column label")?);
            out.push(b'\t');
        }
        out.push(0);
        out.put_u32(crate::binio::to_u32(self.rows.len(), FMT, "row count")?);
        for l in &self.row_labels {
            out.extend_from_slice(&text::encode(l, "2DA row label")?);
            out.push(b'\t');
        }
        // Pool: source order for strings still used, then first use.
        let used: std::collections::HashSet<&str> =
            self.rows.iter().flatten().map(String::as_str).collect();
        let mut pool = Vec::new();
        let mut offset_of: HashMap<&str, u16> = HashMap::new();
        let source_order = self.pool.0.iter().filter(|s| used.contains(s.as_str()));
        for s in source_order.chain(self.rows.iter().flatten()) {
            if offset_of.contains_key(s.as_str()) {
                continue;
            }
            let off = u16::try_from(pool.len())
                .map_err(|_| Error::invalid(FMT, "string pool exceeds 65535 bytes"))?;
            pool.extend_from_slice(&text::encode(s, "2DA cell")?);
            pool.push(0);
            offset_of.insert(s.as_str(), off);
        }
        for s in self.rows.iter().flatten() {
            out.put_u16(offset_of[s.as_str()]);
        }
        let size = u16::try_from(pool.len())
            .map_err(|_| Error::invalid(FMT, "string pool exceeds 65535 bytes"))?;
        out.put_u16(size);
        out.extend_from_slice(&pool);
        Ok(out)
    }

    /// Render as text V2.0 (tab-separated, `****` for empty cells, values
    /// with spaces quoted).
    pub fn to_text(&self) -> String {
        fn cell(v: &str) -> String {
            if v.is_empty() {
                "****".into()
            } else if v.contains(char::is_whitespace) {
                format!("\"{v}\"")
            } else {
                v.to_string()
            }
        }
        let mut s = String::from("2DA V2.0\r\n");
        if let Some(d) = &self.default {
            s.push_str(&format!("DEFAULT: {d}"));
        }
        s.push_str("\r\n");
        s.push('\t');
        s.push_str(
            &self
                .columns
                .iter()
                .map(|c| cell(c))
                .collect::<Vec<_>>()
                .join("\t"),
        );
        s.push_str("\r\n");
        for (label, row) in self.row_labels.iter().zip(&self.rows) {
            s.push_str(&cell(label));
            for v in row {
                s.push('\t');
                s.push_str(&cell(v));
            }
            s.push_str("\r\n");
        }
        s
    }
}

/// Whitespace-separated tokens with `"quoted strings"`.
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&c) = chars.peek() else { break };
        let mut tok = String::new();
        if c == '"' {
            chars.next();
            for ch in chars.by_ref() {
                if ch == '"' {
                    break;
                }
                tok.push(ch);
            }
        } else {
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() {
                    break;
                }
                tok.push(ch);
                chars.next();
            }
        }
        out.push(tok);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TwoDa {
        let mut t = TwoDa::new(&["label", "value", "resref"]);
        t.push_row(vec!["first".into(), "1".into(), "".into()]);
        t.push_row(vec!["second".into(), "1".into(), "tex_a".into()]);
        t.push_row(vec!["".into(), "".into(), "tex_a".into()]);
        t
    }

    #[test]
    fn binary_round_trip() {
        let t = sample();
        let bytes = t.to_binary().unwrap();
        assert!(bytes.starts_with(b"2DA V2.b\nlabel\tvalue\tresref\t\0"));
        let back = TwoDa::read(&bytes).unwrap();
        assert_eq!(back, t);
        assert_eq!(back.get(1, "RESREF"), Some("tex_a"));
        assert_eq!(back.to_binary().unwrap(), bytes);
    }

    #[test]
    fn foreign_pool_order_round_trips() {
        // Pool in reverse first-use order: "b\0a\0", cells a, b.
        let mut f = Vec::new();
        f.extend_from_slice(b"2DA V2.b\ncol\t\0");
        f.extend_from_slice(&2u32.to_le_bytes());
        f.extend_from_slice(b"0\t1\t");
        f.extend_from_slice(&2u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&4u16.to_le_bytes());
        f.extend_from_slice(b"b\0a\0");
        let t = TwoDa::read(&f).unwrap();
        assert_eq!(t.rows, vec![vec!["a".to_string()], vec!["b".to_string()]]);
        assert_eq!(t.to_binary().unwrap(), f);
    }

    #[test]
    fn text_reader() {
        let src = b"2DA V2.0\r\nDEFAULT: ****\r\n\r\n   label  value   name\r\n0 first 1 \"two words\"\r\n1 **** 2 ****\r\n";
        let t = TwoDa::read(src).unwrap();
        assert_eq!(t.columns, ["label", "value", "name"]);
        assert_eq!(t.default.as_deref(), Some("****"));
        assert_eq!(t.get(0, "name"), Some("two words"));
        assert_eq!(t.get(1, "label"), Some(""));
        let again = TwoDa::read_text(t.to_text().as_bytes()).unwrap();
        assert_eq!(again, t);
    }

    #[test]
    fn errors() {
        assert!(TwoDa::read(b"2DA V9").is_err());
        let bytes = sample().to_binary().unwrap();
        assert!(TwoDa::read(&bytes[..bytes.len() - 2]).is_err());
        let mut t = sample();
        t.rows[0].pop();
        assert!(t.to_binary().is_err());
    }
}
