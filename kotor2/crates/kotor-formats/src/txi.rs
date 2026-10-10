//! TXI texture information: plain text, one `key value...` per line.
//!
//! Keys are case-insensitive. Font TXIs use two multi-line keys,
//! `upperleftcoords N` and `lowerrightcoords N`, each followed by N lines of
//! coordinates; those lines are kept in [`TxiEntry::lines`].
//!
//! [`Txi::to_text`] writes `key value` lines with the newline style of the
//! source (`\r\n` by default). It normalizes spacing, so it is not a byte-exact
//! writer; [`crate::tpc::Tpc`] keeps a TPC's TXI as raw bytes for that.

use crate::text;

/// One key and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxiEntry {
    /// The key as written.
    pub key: String,
    /// Everything after the key, trimmed.
    pub value: String,
    /// Continuation lines (only for `upperleftcoords` / `lowerrightcoords`).
    pub lines: Vec<String>,
}

/// A parsed TXI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Txi {
    /// Entries in order.
    pub entries: Vec<TxiEntry>,
    /// Newline used when writing.
    pub newline: &'static str,
}

impl Default for Txi {
    fn default() -> Self {
        Txi {
            entries: Vec::new(),
            newline: "\r\n",
        }
    }
}

fn is_multiline(key: &str) -> bool {
    key.eq_ignore_ascii_case("upperleftcoords") || key.eq_ignore_ascii_case("lowerrightcoords")
}

impl Txi {
    /// Parse raw bytes (trailing NULs ignored).
    pub fn parse_bytes(bytes: &[u8]) -> Txi {
        let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        Txi::parse(&text::decode(&bytes[..end]))
    }

    /// Parse text.
    pub fn parse(s: &str) -> Txi {
        let newline = if s.contains("\r\n") || !s.contains('\n') {
            "\r\n"
        } else {
            "\n"
        };
        let mut entries = Vec::new();
        let mut lines = s
            .lines()
            .map(|l| l.trim_matches(|c: char| c.is_whitespace() || c == '\0'));
        while let Some(line) = lines.next() {
            if line.is_empty() {
                continue;
            }
            let (key, value) = match line.split_once(char::is_whitespace) {
                Some((k, v)) => (k, v.trim()),
                None => (line, ""),
            };
            let mut entry = TxiEntry {
                key: key.to_string(),
                value: value.to_string(),
                lines: Vec::new(),
            };
            if is_multiline(key) {
                let n: usize = value
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                for _ in 0..n {
                    match lines.next() {
                        Some(l) => entry.lines.push(l.to_string()),
                        None => break,
                    }
                }
            }
            entries.push(entry);
        }
        Txi { entries, newline }
    }

    /// The value of the last entry with this key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.key.eq_ignore_ascii_case(key))
            .map(|e| e.value.as_str())
    }

    /// The entry with this key.
    pub fn entry(&self, key: &str) -> Option<&TxiEntry> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.key.eq_ignore_ascii_case(key))
    }

    /// First number of a key's value.
    pub fn get_f32(&self, key: &str) -> Option<f32> {
        self.get(key)?.split_whitespace().next()?.parse().ok()
    }

    /// Set a key (replacing every existing entry's value, or appending).
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        let value = value.into();
        let mut found = false;
        for e in self
            .entries
            .iter_mut()
            .filter(|e| e.key.eq_ignore_ascii_case(key))
        {
            e.value.clone_from(&value);
            found = true;
        }
        if !found {
            self.entries.push(TxiEntry {
                key: key.to_string(),
                value,
                lines: Vec::new(),
            });
        }
    }

    /// Remove every entry with this key.
    pub fn remove(&mut self, key: &str) {
        self.entries.retain(|e| !e.key.eq_ignore_ascii_case(key));
    }

    /// Render as text.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        for e in &self.entries {
            s.push_str(&e.key);
            if !e.value.is_empty() {
                s.push(' ');
                s.push_str(&e.value);
            }
            s.push_str(self.newline);
            for l in &e.lines {
                s.push_str(l);
                s.push_str(self.newline);
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_font_txi() {
        let src = "mipmap 0\r\nfilter 0\r\nnumchars 2\r\nfontheight 0.16\r\nupperleftcoords 2\r\n0.0 1.0 0\r\n0.5 1.0 0\r\nlowerrightcoords 2\r\n0.5 0.5 0\r\n1.0 0.5 0\r\nspacingR 0\r\n";
        let t = Txi::parse_bytes(format!("{src}\0").as_bytes());
        assert_eq!(t.get("NUMCHARS"), Some("2"));
        assert_eq!(t.get_f32("fontheight"), Some(0.16));
        assert_eq!(t.entry("upperleftcoords").unwrap().lines.len(), 2);
        assert_eq!(t.get("spacingr"), Some("0"));
        assert_eq!(t.to_text(), src);
    }

    #[test]
    fn edit() {
        let mut t = Txi::parse("mipmap 0\nproceduretype cycle\n");
        assert_eq!(t.newline, "\n");
        t.set("mipmap", "1");
        t.set("numx", "2");
        t.remove("proceduretype");
        assert_eq!(t.to_text(), "mipmap 1\nnumx 2\n");
    }
}
