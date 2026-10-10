//! Bounds-checked little-endian reads and simple writes.

use crate::error::{Error, Result};
use crate::text;

/// A borrowed byte slice with checked little-endian accessors.
#[derive(Clone, Copy)]
pub(crate) struct Bytes<'a> {
    pub data: &'a [u8],
    pub format: &'static str,
}

impl<'a> Bytes<'a> {
    pub fn new(data: &'a [u8], format: &'static str) -> Self {
        Bytes { data, format }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn slice(&self, offset: usize, len: usize) -> Result<&'a [u8]> {
        let end = offset.checked_add(len);
        match end {
            Some(end) if end <= self.data.len() => Ok(&self.data[offset..end]),
            _ => Err(Error::Truncated {
                format: self.format,
                offset,
                needed: len,
                len: self.data.len(),
            }),
        }
    }

    pub fn array<const N: usize>(&self, offset: usize) -> Result<[u8; N]> {
        let s = self.slice(offset, N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub fn u8(&self, offset: usize) -> Result<u8> {
        Ok(self.slice(offset, 1)?[0])
    }

    pub fn u16(&self, offset: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array(offset)?))
    }

    pub fn u32(&self, offset: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array(offset)?))
    }

    pub fn u64(&self, offset: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array(offset)?))
    }

    pub fn f32(&self, offset: usize) -> Result<f32> {
        Ok(f32::from_bits(self.u32(offset)?))
    }

    /// A fixed-width, NUL-padded string field (trimmed at the first NUL).
    pub fn fixed_str(&self, offset: usize, len: usize) -> Result<String> {
        let raw = self.slice(offset, len)?;
        Ok(text::decode(trim_nul(raw)))
    }

    /// Check the 4-byte type and 4-byte version at offset 0.
    pub fn signature(&self, expected: &'static str) -> Result<()> {
        let want = expected.as_bytes();
        let have = self.data.get(..want.len());
        if have != Some(want) {
            let found = self.data.get(..want.len()).unwrap_or(self.data);
            return Err(Error::BadSignature {
                format: self.format,
                found: String::from_utf8_lossy(found).into_owned(),
                expected,
            });
        }
        Ok(())
    }
}

/// Slice up to (not including) the first NUL.
pub(crate) fn trim_nul(raw: &[u8]) -> &[u8] {
    match raw.iter().position(|&b| b == 0) {
        Some(p) => &raw[..p],
        None => raw,
    }
}

/// `usize` from a `u32` file value (lossless on every target this crate supports).
pub(crate) fn us(v: u32) -> usize {
    v as usize
}

/// Little-endian append helpers for `Vec<u8>`.
pub(crate) trait Put {
    fn put_u8(&mut self, v: u8);
    fn put_u16(&mut self, v: u16);
    fn put_u32(&mut self, v: u32);
    fn put_u64(&mut self, v: u64);
    fn put_f32(&mut self, v: f32);
    /// A NUL-padded fixed-width field; fails if `s` does not fit.
    fn put_fixed(&mut self, s: &str, width: usize, what: &'static str) -> Result<()>;
}

impl Put for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v);
    }
    fn put_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u64(&mut self, v: u64) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_f32(&mut self, v: f32) {
        self.put_u32(v.to_bits());
    }
    fn put_fixed(&mut self, s: &str, width: usize, what: &'static str) -> Result<()> {
        let bytes = text::encode(s, what)?;
        if bytes.len() > width {
            return Err(Error::Encode {
                what,
                message: format!("{s:?} is {} bytes, the field holds {width}", bytes.len()),
            });
        }
        self.extend_from_slice(&bytes);
        self.resize(self.len() + width - bytes.len(), 0);
        Ok(())
    }
}

/// Convert a length or offset to the `u32` the file stores, or fail.
pub(crate) fn to_u32(v: usize, format: &'static str, what: &str) -> Result<u32> {
    u32::try_from(v)
        .map_err(|_| Error::invalid(format, format!("{what} {v} does not fit in 32 bits")))
}

/// Layout information remembered from a source file so a writer can
/// reproduce it. Always compares equal: it never affects `==` on the
/// value it is attached to.
#[derive(Clone, Debug, Default)]
pub(crate) struct Hint<T>(pub T);

impl<T> PartialEq for Hint<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
