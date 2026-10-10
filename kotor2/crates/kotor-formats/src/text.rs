//! Byte <-> `String` conversion for on-disk strings.
//!
//! The Odyssey engine stores strings as 8-bit text in the install's code page
//! (Windows-1252 for the English, French, German, Italian and Spanish releases).
//! This crate decodes every byte through a *bijective* Windows-1252 mapping:
//! the five bytes Windows-1252 leaves undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D)
//! map to the C1 control characters of the same value, exactly as the WHATWG
//! encoding standard does. So `encode(decode(b)) == b` for **every** byte
//! sequence, which is what makes byte-exact round trips possible through a
//! plain `String` API.
//!
//! Releases in other code pages (for example the Polish release, Windows-1250)
//! still round-trip exactly; they merely display the wrong characters. Recover
//! the raw bytes with [`encode`] and decode them with the right code page.

use crate::error::{Error, Result};

/// Windows-1252 0x80..=0x9F.
const HIGH: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

/// Decode bytes (never fails).
pub fn decode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0x80..=0x9F => HIGH[usize::from(b - 0x80)],
            _ => char::from(b),
        })
        .collect()
}

fn encode_char(c: char) -> Option<u8> {
    let u = u32::from(c);
    if u < 0x80 || (0xA0..=0xFF).contains(&u) {
        return Some(u as u8);
    }
    HIGH.iter().position(|&h| h == c).map(|i| 0x80 + i as u8)
}

/// Encode a string; fails on a character outside the mapping.
pub fn encode(s: &str, what: &'static str) -> Result<Vec<u8>> {
    s.chars()
        .map(|c| {
            encode_char(c).ok_or_else(|| Error::Encode {
                what,
                message: format!(
                    "character {c:?} (U+{:04X}) has no Windows-1252 byte",
                    u32::from(c)
                ),
            })
        })
        .collect()
}

/// Encode a string, replacing unmappable characters with `?`.
pub fn encode_lossy(s: &str) -> Vec<u8> {
    s.chars().map(|c| encode_char(c).unwrap_or(b'?')).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_byte_round_trips() {
        let all: Vec<u8> = (0..=255u8).collect();
        let s = decode(&all);
        assert_eq!(encode(&s, "test").unwrap(), all);
    }

    #[test]
    fn known_characters() {
        assert_eq!(decode(&[0x80, 0xE9]), "\u{20AC}\u{E9}");
        assert!(encode("\u{4E2D}", "test").is_err());
        assert_eq!(encode_lossy("a\u{4E2D}"), b"a?");
    }
}
