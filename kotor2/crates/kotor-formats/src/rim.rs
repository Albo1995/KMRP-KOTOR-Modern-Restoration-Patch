//! RIM V1.0, the read-only module archive (`modules/*.rim`).
//!
//! # Layout (from public documentation: xoreos, PyKotor; not BioWare-documented)
//!
//! `"RIM V1.0"`, a reserved u32 (0), entry count, key-table offset (0x78 in
//! every file the references describe; 0 is treated as 0x78), then reserved
//! bytes up to the key table. Key table: 32 bytes per entry (resref[16], type
//! u32, resource id u32, offset u32, size u32). Then the data.
//!
//! # Round trips
//!
//! The header bytes between the fixed fields and the key table, the data
//! order and any bytes between resources are kept, so an unmodified RIM comes
//! back byte-identical as long as its data follows the key table.

use crate::binio::{us, Bytes, Hint, Put};
use crate::erf::{capture_layout, data_order, DataHint};
use crate::error::{Error, Result};
use crate::restype::ResType;

const FMT: &str = "RIM";
const DEFAULT_KEY_OFFSET: usize = 0x78;

/// One resource.
#[derive(Clone, Debug, PartialEq)]
pub struct RimResource {
    /// Name, at most 16 bytes.
    pub resref: String,
    /// Type (stored as u32; KotOR ids fit in u16).
    pub restype: ResType,
    /// Resource id as stored (normally the entry's index).
    pub res_id: u32,
    /// Contents.
    pub data: Vec<u8>,
    hint: DataHint,
}

/// A RIM archive held in memory.
#[derive(Clone, Debug, PartialEq)]
pub struct Rim {
    /// The reserved u32 at offset 8.
    pub reserved: u32,
    /// Header bytes from offset 20 up to the key table.
    pub header_extra: Vec<u8>,
    /// Resources, in key-table order.
    pub resources: Vec<RimResource>,
    lead: Hint<Vec<u8>>,
}

impl Default for Rim {
    fn default() -> Self {
        Rim {
            reserved: 0,
            header_extra: vec![0; DEFAULT_KEY_OFFSET - 20],
            resources: Vec::new(),
            lead: Hint(Vec::new()),
        }
    }
}

impl Rim {
    /// Parse.
    pub fn read(data: &[u8]) -> Result<Rim> {
        let b = Bytes::new(data, FMT);
        b.signature("RIM V1.0")?;
        let reserved = b.u32(8)?;
        let count = us(b.u32(12)?);
        let mut key_off = us(b.u32(16)?);
        if key_off == 0 {
            key_off = DEFAULT_KEY_OFFSET;
        }
        if key_off < 20 {
            return Err(Error::invalid(
                FMT,
                format!("key table offset {key_off} overlaps the header"),
            ));
        }
        let header_extra = b.slice(20, key_off - 20)?.to_vec();
        b.slice(key_off, count.saturating_mul(32))?;
        let mut resources = Vec::with_capacity(count);
        let mut spans = Vec::with_capacity(count);
        for i in 0..count {
            let k = key_off + 32 * i;
            let resref = b.fixed_str(k, 16)?;
            let type_raw = b.u32(k + 16)?;
            let restype = ResType(u16::try_from(type_raw).map_err(|_| {
                Error::invalid(
                    FMT,
                    format!("{resref}: resource type {type_raw} does not fit 16 bits"),
                )
            })?);
            let res_id = b.u32(k + 20)?;
            let off = us(b.u32(k + 24)?);
            let size = us(b.u32(k + 28)?);
            let bytes = b.slice(off, size).map_err(|_| {
                Error::invalid(FMT, format!("{resref}.{restype}: {size} bytes at {off} run past the end of the file ({} bytes)", data.len()))
            })?;
            spans.push((off, size));
            resources.push(RimResource {
                resref,
                restype,
                res_id,
                data: bytes.to_vec(),
                hint: DataHint::default(),
            });
        }
        let (lead, hints) = capture_layout(data, key_off + 32 * count, &spans);
        for (r, h) in resources.iter_mut().zip(hints) {
            r.hint = h;
        }
        Ok(Rim {
            reserved,
            header_extra,
            resources,
            lead: Hint(lead),
        })
    }

    /// Find a resource (resref compared case-insensitively).
    pub fn get(&self, resref: &str, restype: ResType) -> Option<&[u8]> {
        self.resources
            .iter()
            .find(|r| r.restype == restype && r.resref.eq_ignore_ascii_case(resref))
            .map(|r| r.data.as_slice())
    }

    /// Append or replace a resource.
    pub fn insert(&mut self, resref: &str, restype: ResType, data: Vec<u8>) {
        if let Some(r) = self
            .resources
            .iter_mut()
            .find(|r| r.restype == restype && r.resref.eq_ignore_ascii_case(resref))
        {
            r.data = data;
            return;
        }
        let res_id = self.resources.len() as u32;
        self.resources.push(RimResource {
            resref: resref.to_string(),
            restype,
            res_id,
            data,
            hint: DataHint::default(),
        });
    }

    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let n = self.resources.len();
        let key_off = 20 + self.header_extra.len();
        let tables_end = key_off + 32 * n;
        let hints: Vec<&DataHint> = self.resources.iter().map(|r| &r.hint).collect();
        let order = data_order(&hints);
        let mut offsets = vec![0usize; n];
        let mut pos = tables_end + self.lead.0.len();
        for &i in &order {
            offsets[i] = pos;
            pos += self.resources[i].data.len() + self.resources[i].hint.pad_after.len();
        }
        let mut out = Vec::with_capacity(pos);
        out.extend_from_slice(b"RIM V1.0");
        out.put_u32(self.reserved);
        out.put_u32(to32(n)?);
        out.put_u32(to32(key_off)?);
        out.extend_from_slice(&self.header_extra);
        for (i, r) in self.resources.iter().enumerate() {
            out.put_fixed(&r.resref, 16, "RIM resref")?;
            out.put_u32(u32::from(r.restype.0));
            out.put_u32(r.res_id);
            out.put_u32(to32(offsets[i])?);
            out.put_u32(to32(r.data.len())?);
        }
        out.extend_from_slice(&self.lead.0);
        for &i in &order {
            out.extend_from_slice(&self.resources[i].data);
            out.extend_from_slice(&self.resources[i].hint.pad_after);
        }
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
        let mut r = Rim::default();
        r.insert("m01aa", ResType::ARE, b"are".to_vec());
        r.insert("m01aa", ResType::GIT, vec![1; 17]);
        r.insert("module", ResType::IFO, b"ifo".to_vec());
        let bytes = r.to_bytes().unwrap();
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 0x78);
        let back = Rim::read(&bytes).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.get("M01AA", ResType::GIT).map(<[u8]>::len), Some(17));
        assert_eq!(back.to_bytes().unwrap(), bytes);

        // Append trailing alignment bytes and garbage between entries.
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0; 3]);
        let back = Rim::read(&padded).unwrap();
        assert_eq!(back.to_bytes().unwrap(), padded);
    }

    #[test]
    fn errors() {
        assert!(Rim::read(b"RIM V1.1").is_err());
        let mut r = Rim::default();
        r.insert("x", ResType::ARE, vec![0; 10]);
        let bytes = r.to_bytes().unwrap();
        assert!(Rim::read(&bytes[..bytes.len() - 1]).is_err());
    }
}
