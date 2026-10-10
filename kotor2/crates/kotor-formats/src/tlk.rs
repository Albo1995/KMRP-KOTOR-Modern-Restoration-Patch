//! TLK V3.0 talk tables (`dialog.tlk`).
//!
//! # Layout (from public documentation: BioWare's "Talk Table" PDF, xoreos)
//!
//! A 20-byte header: `"TLK V3.0"`, language id, string count, string-data
//! offset. Then 40 bytes per entry: flags (1 = text present, 2 = sound
//! present, 4 = sound length present), sound resref[16], volume variance,
//! pitch variance, text offset (relative to the string-data offset), text
//! length, sound length (f32). Then the text.
//!
//! The writer packs the text in entry order; it is provided for synthetic
//! tests and new tables, and is not claimed to reproduce the game's
//! `dialog.tlk` byte for byte.

use crate::binio::{us, Bytes, Put};
use crate::error::{Error, Result};
use crate::text;

const FMT: &str = "TLK";

/// Entry flag: the entry has text.
pub const FLAG_TEXT: u32 = 1;
/// Entry flag: the entry has a sound.
pub const FLAG_SOUND: u32 = 2;
/// Entry flag: the entry has a sound length.
pub const FLAG_SOUND_LENGTH: u32 = 4;

/// One string.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct TlkEntry {
    /// Flags (`FLAG_*`).
    pub flags: u32,
    /// Voice-over resref.
    pub sound: String,
    /// Unused by KotOR.
    pub volume_variance: u32,
    /// Unused by KotOR.
    pub pitch_variance: u32,
    /// Sound length in seconds.
    pub sound_length: f32,
    /// The text.
    pub text: String,
}

/// A talk table.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Tlk {
    /// Language id (0 English, 1 French, 2 German, 3 Italian, 4 Spanish, 5 Polish).
    pub language: u32,
    /// Entries, indexed by strref.
    pub entries: Vec<TlkEntry>,
}

impl Tlk {
    /// Parse.
    pub fn read(data: &[u8]) -> Result<Tlk> {
        let b = Bytes::new(data, FMT);
        b.signature("TLK V3.0")?;
        let language = b.u32(8)?;
        let count = us(b.u32(12)?);
        let strings = us(b.u32(16)?);
        b.slice(20, count.saturating_mul(40))?;
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let at = 20 + 40 * i;
            let flags = b.u32(at)?;
            let off = us(b.u32(at + 28)?);
            let len = us(b.u32(at + 32)?);
            let text = if len == 0 {
                String::new()
            } else {
                let start = strings.checked_add(off).ok_or_else(|| {
                    Error::invalid(FMT, format!("entry {i}: text offset overflows"))
                })?;
                text::decode(b.slice(start, len).map_err(|_| {
                    Error::invalid(FMT, format!("entry {i}: {len} bytes of text at {start} run past the end of the file ({} bytes)", data.len()))
                })?)
            };
            entries.push(TlkEntry {
                flags,
                sound: b.fixed_str(at + 4, 16)?,
                volume_variance: b.u32(at + 20)?,
                pitch_variance: b.u32(at + 24)?,
                sound_length: b.f32(at + 36)?,
                text,
            });
        }
        Ok(Tlk { language, entries })
    }

    /// Text of a strref (`None` if out of range, including 0xFFFFFFFF).
    pub fn get(&self, strref: u32) -> Option<&str> {
        self.entries.get(us(strref)).map(|e| e.text.as_str())
    }

    /// Serialize, packing the text in entry order.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let n = self.entries.len();
        let strings = 20 + 40 * n;
        let mut out = Vec::new();
        out.extend_from_slice(b"TLK V3.0");
        out.put_u32(self.language);
        out.put_u32(to32(n)?);
        out.put_u32(to32(strings)?);
        let mut pool = Vec::new();
        for e in &self.entries {
            let t = text::encode(&e.text, "TLK text")?;
            out.put_u32(e.flags);
            out.put_fixed(&e.sound, 16, "TLK sound resref")?;
            out.put_u32(e.volume_variance);
            out.put_u32(e.pitch_variance);
            out.put_u32(if t.is_empty() { 0 } else { to32(pool.len())? });
            out.put_u32(to32(t.len())?);
            out.put_f32(e.sound_length);
            pool.extend_from_slice(&t);
        }
        out.extend_from_slice(&pool);
        Ok(out)
    }
}

fn to32(v: usize) -> Result<u32> {
    crate::binio::to_u32(v, FMT, "size or offset")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let t = Tlk {
            language: 0,
            entries: vec![
                TlkEntry {
                    flags: FLAG_TEXT,
                    text: "Bad Strref".into(),
                    ..Default::default()
                },
                TlkEntry::default(),
                TlkEntry {
                    flags: FLAG_TEXT | FLAG_SOUND | FLAG_SOUND_LENGTH,
                    sound: "n_gendroid_1".into(),
                    sound_length: 2.5,
                    text: "Na\u{ef}ve caf\u{e9}".into(),
                    ..Default::default()
                },
            ],
        };
        let bytes = t.to_bytes().unwrap();
        let back = Tlk::read(&bytes).unwrap();
        assert_eq!(back, t);
        assert_eq!(back.get(2), Some("Na\u{ef}ve caf\u{e9}"));
        assert_eq!(back.get(u32::MAX), None);
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert!(Tlk::read(&bytes[..bytes.len() - 1]).is_err());
    }
}
