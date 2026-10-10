//! `kpm-tool find` and `kpm-tool disasm`.

use std::fmt::Write as _;

use anyhow::{bail, Result};

use crate::pe::Image;
use crate::x86;

/// One pattern element: a byte, or `??` / `?` for any byte.
pub type Pattern = Vec<Option<u8>>;

/// Parse `"8B 44 24 ?? 85 C0"`. Tokens may also run together
/// (`"8B4424??85C0"`); `0x` prefixes and commas are ignored.
pub fn parse_pattern(text: &str) -> Result<Pattern> {
    let cleaned = text.replace([',', '[', ']'], " ");
    let tokens: Vec<String> = cleaned
        .split_whitespace()
        .map(|t| {
            t.strip_prefix("0x")
                .or_else(|| t.strip_prefix("0X"))
                .unwrap_or(t)
                .to_string()
        })
        .collect();
    let mut out = Vec::new();
    for token in tokens {
        if token == "?" || token == "??" {
            out.push(None);
            continue;
        }
        if token.len() % 2 != 0 {
            bail!("pattern token {token:?} is not whole bytes (write 0F, not F)");
        }
        for pair in token.as_bytes().chunks(2) {
            let pair = std::str::from_utf8(pair).unwrap_or("");
            if pair == "??" {
                out.push(None);
            } else {
                match u8::from_str_radix(pair, 16) {
                    Ok(b) => out.push(Some(b)),
                    Err(_) => bail!("pattern token {pair:?} is not a hex byte or ??"),
                }
            }
        }
    }
    if out.is_empty() {
        bail!("empty pattern");
    }
    if out.iter().all(Option::is_none) {
        bail!("a pattern of only wildcards matches everywhere");
    }
    Ok(out)
}

fn matches_at(hay: &[u8], pattern: &Pattern) -> bool {
    hay.len() >= pattern.len()
        && pattern
            .iter()
            .zip(hay)
            .all(|(p, b)| p.is_none_or(|p| p == *b))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub va: u64,
    pub offset: usize,
    pub section: String,
}

/// Every match in the file-backed bytes of each section (or only `section`).
pub fn find(image: &Image, pattern: &Pattern, section: Option<&str>, max: usize) -> Vec<Hit> {
    let mut hits = Vec::new();
    for s in &image.sections {
        if section.is_some_and(|want| want != s.name) {
            continue;
        }
        let start = s.raw_offset as usize;
        let end = (start + s.file_backed() as usize).min(image.data.len());
        if start >= end {
            continue;
        }
        let bytes = &image.data[start..end];
        for i in 0..bytes.len().saturating_sub(pattern.len() - 1) {
            if matches_at(&bytes[i..], pattern) {
                hits.push(Hit {
                    va: image.image_base + s.rva as u64 + i as u64,
                    offset: start + i,
                    section: s.name.clone(),
                });
                if hits.len() >= max {
                    return hits;
                }
            }
        }
    }
    hits
}

/// Text for `kpm-tool find`.
pub fn render_find(image: &Image, pattern: &Pattern, hits: &[Hit], max: usize) -> String {
    let mut o = String::new();
    for h in hits {
        let first = image
            .read_va_upto(h.va, 16)
            .ok()
            .and_then(|b| x86::decode(b, h.va, 1).into_iter().next())
            .map(|i| i.text)
            .unwrap_or_default();
        let _ = writeln!(
            o,
            "{:#010X}  {:<8} file {:#08X}  {}",
            h.va, h.section, h.offset, first
        );
    }
    let _ = writeln!(
        o,
        "{} match(es) for {} byte(s){}",
        hits.len(),
        pattern.len(),
        if hits.len() >= max {
            format!(" (stopped at --max {max})")
        } else {
            String::new()
        }
    );
    o
}

/// Text for `kpm-tool disasm`.
pub fn disasm(image: &Image, va: u64, count: usize) -> Result<String> {
    let bytes = image.read_va_upto(va, count.saturating_mul(15).max(15))?;
    let insns = x86::decode(bytes, va, count);
    let mut o = String::new();
    for i in &insns {
        let note = match i.relative_target {
            Some(t) => format!("    ; relative -> {t:#010X}"),
            None => String::new(),
        };
        let _ = writeln!(o, "{:#010X}  {:<24} {}{}", i.va, i.hex(), i.text, note);
    }
    // The smallest whole-instruction prefix a detour can steal.
    let mut taken = 0usize;
    let mut relative = false;
    for i in &insns {
        if taken >= 5 || i.invalid {
            break;
        }
        taken += i.len();
        relative |= i.relative_target.is_some();
    }
    if taken >= 5 {
        let stolen = &bytes[..taken];
        let list: Vec<_> = stolen.iter().map(|b| format!("0x{b:02X}")).collect();
        let _ = writeln!(
            o,
            "\nshortest detour site here: {taken} bytes\noriginal_bytes = [{}]{}",
            list.join(", "),
            if relative {
                "\n(contains a relative branch: needs skip_original_bytes = true or another site)"
            } else {
                ""
            }
        );
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert_eq!(
            parse_pattern("8B 44 24 ?? 85 C0").unwrap(),
            vec![
                Some(0x8B),
                Some(0x44),
                Some(0x24),
                None,
                Some(0x85),
                Some(0xC0)
            ]
        );
        assert_eq!(
            parse_pattern("8B44??").unwrap(),
            vec![Some(0x8B), Some(0x44), None]
        );
        assert_eq!(parse_pattern("0x8B, ?").unwrap(), vec![Some(0x8B), None]);
        assert!(parse_pattern("8").is_err());
        assert!(parse_pattern("?? ??").is_err());
        assert!(parse_pattern("ZZ").is_err());
    }
}
