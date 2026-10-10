//! ERF V1.0 and its siblings MOD, SAV and HAK (same layout, different type tag).
//!
//! # Layout (from public documentation: BioWare's "ERF Format" PDF, xoreos, PyKotor)
//!
//! A 160-byte header: type[4], `V1.0`, language count, localized-string
//! section size, entry count, localized-string offset, key-list offset,
//! resource-list offset, build year, build day, description strref, and 116
//! reserved bytes. Localized strings: language id, length, text. Key list: 24
//! bytes per entry (resref[16], resource id u32, type u16, unused u16).
//! Resource list: 8 bytes per entry (offset, size). Then the data.
//!
//! KotOR uses V1.0 with 16-byte resrefs (V1.1 with 32-byte resrefs is NWN2's).
//!
//! # Round trips
//!
//! The writer emits header, localized strings, key list and resource list
//! back to back, then the data. It keeps the reserved header bytes, the
//! source's data order, and any bytes between resources (alignment padding),
//! so an unmodified archive laid out in that conventional order comes back
//! byte-identical.

use crate::binio::{us, Bytes, Hint, Put};
use crate::error::{Error, Result};
use crate::restype::ResType;
use crate::text;

const FMT: &str = "ERF";
const HEADER_LEN: usize = 160;

/// Where a resource's data sat in the source and what followed it.
#[derive(Clone, Debug, Default)]
pub(crate) struct DataHint {
    pub rank: Option<usize>,
    pub pad_after: Vec<u8>,
}

impl PartialEq for DataHint {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

/// Capture data order and inter-resource bytes. Returns the bytes between
/// `tables_end` and the first resource, and a hint per span. If the spans
/// overlap or start inside the tables, returns no hints (canonical layout).
pub(crate) fn capture_layout(
    data: &[u8],
    tables_end: usize,
    spans: &[(usize, usize)],
) -> (Vec<u8>, Vec<DataHint>) {
    let none = (Vec::new(), vec![DataHint::default(); spans.len()]);
    let mut order: Vec<usize> = (0..spans.len()).collect();
    // An empty resource sharing an offset with a non-empty one comes first.
    order.sort_by_key(|&i| (spans[i].0, spans[i].1 > 0, i));
    let mut pos = tables_end;
    let mut hints = vec![DataHint::default(); spans.len()];
    let mut lead = Vec::new();
    for (rank, &i) in order.iter().enumerate() {
        let (off, size) = spans[i];
        if off < pos {
            return none;
        }
        let gap = &data[pos..off];
        if rank == 0 {
            lead = gap.to_vec();
        } else {
            hints[order[rank - 1]].pad_after = gap.to_vec();
        }
        hints[i].rank = Some(rank);
        pos = off + size;
    }
    if pos > data.len() {
        return none;
    }
    match order.last() {
        Some(&last) => hints[last].pad_after = data[pos..].to_vec(),
        None => lead = data[pos.min(data.len())..].to_vec(),
    }
    (lead, hints)
}

/// Data order for writing: source rank first, new resources after.
pub(crate) fn data_order(hints: &[&DataHint]) -> Vec<usize> {
    let mut v: Vec<usize> = (0..hints.len()).collect();
    v.sort_by_key(|&i| (hints[i].rank.unwrap_or(usize::MAX), i));
    v
}

/// A localized description string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErfLocString {
    /// Language id.
    pub language: u32,
    /// Text.
    pub text: String,
}

/// One resource.
#[derive(Clone, Debug, PartialEq)]
pub struct ErfResource {
    /// Name, at most 16 bytes.
    pub resref: String,
    /// Type.
    pub restype: ResType,
    /// Resource id as stored (normally the entry's index).
    pub res_id: u32,
    /// The unused u16 after the type, kept for round trips.
    pub unused: u16,
    /// Contents.
    pub data: Vec<u8>,
    pub(crate) hint: DataHint,
}

/// An ERF-family archive held in memory.
#[derive(Clone, Debug, PartialEq)]
pub struct Erf {
    /// `b"ERF "`, `b"MOD "`, `b"SAV "` or `b"HAK "`.
    pub file_type: [u8; 4],
    /// `b"V1.0"`.
    pub version: [u8; 4],
    /// Build year (since 1900).
    pub build_year: u32,
    /// Build day of year.
    pub build_day: u32,
    /// Description TLK reference (0xFFFFFFFF for none).
    pub description_strref: u32,
    /// Localized descriptions.
    pub loc_strings: Vec<ErfLocString>,
    /// Resources, in key-list order.
    pub resources: Vec<ErfResource>,
    /// The 116 reserved header bytes.
    pub reserved: Vec<u8>,
    lead: Hint<Vec<u8>>,
}

impl Erf {
    /// An empty archive of the given type (`"ERF"`, `"MOD"`, `"SAV"`, `"HAK"`).
    pub fn new(kind: &str) -> Erf {
        let mut t = [b' '; 4];
        for (d, s) in t.iter_mut().zip(kind.bytes()) {
            *d = s;
        }
        Erf {
            file_type: t,
            version: *b"V1.0",
            build_year: 0,
            build_day: 0,
            description_strref: u32::MAX,
            loc_strings: Vec::new(),
            resources: Vec::new(),
            reserved: vec![0; 116],
            lead: Hint(Vec::new()),
        }
    }

    /// Parse.
    pub fn read(data: &[u8]) -> Result<Erf> {
        let b = Bytes::new(data, FMT);
        let file_type = b.array::<4>(0)?;
        let version = b.array::<4>(4)?;
        if !matches!(&file_type, b"ERF " | b"MOD " | b"SAV " | b"HAK ") || &version != b"V1.0" {
            return Err(Error::BadSignature {
                format: FMT,
                found: String::from_utf8_lossy(&data[..8]).into_owned(),
                expected: "ERF V1.0 / MOD V1.0 / SAV V1.0 / HAK V1.0",
            });
        }
        let lang_count = us(b.u32(8)?);
        let entry_count = us(b.u32(16)?);
        let loc_off = us(b.u32(20)?);
        let key_off = us(b.u32(24)?);
        let res_off = us(b.u32(28)?);
        let build_year = b.u32(32)?;
        let build_day = b.u32(36)?;
        let description_strref = b.u32(40)?;
        let reserved = b.slice(44, 116)?.to_vec();

        let mut loc_strings = Vec::with_capacity(lang_count.min(64));
        let mut pos = loc_off;
        for _ in 0..lang_count {
            let language = b.u32(pos)?;
            let len = us(b.u32(pos + 4)?);
            let text = text::decode(b.slice(pos + 8, len)?);
            loc_strings.push(ErfLocString { language, text });
            pos += 8 + len;
        }
        let loc_end = pos;

        b.slice(key_off, entry_count.saturating_mul(24))?;
        b.slice(res_off, entry_count.saturating_mul(8))?;
        let mut resources = Vec::with_capacity(entry_count);
        let mut spans = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let k = key_off + 24 * i;
            let resref = b.fixed_str(k, 16)?;
            let res_id = b.u32(k + 16)?;
            let restype = ResType(b.u16(k + 20)?);
            let unused = b.u16(k + 22)?;
            let off = us(b.u32(res_off + 8 * i)?);
            let size = us(b.u32(res_off + 8 * i + 4)?);
            let bytes = b.slice(off, size).map_err(|_| {
                Error::invalid(FMT, format!("{resref}.{restype}: {size} bytes at {off} run past the end of the file ({} bytes)", data.len()))
            })?;
            spans.push((off, size));
            resources.push(ErfResource {
                resref,
                restype,
                res_id,
                unused,
                data: bytes.to_vec(),
                hint: DataHint::default(),
            });
        }
        let canonical =
            loc_off == HEADER_LEN && key_off == loc_end && res_off == key_off + 24 * entry_count;
        let lead = if canonical {
            let (lead, hints) = capture_layout(data, res_off + 8 * entry_count, &spans);
            for (r, h) in resources.iter_mut().zip(hints) {
                r.hint = h;
            }
            lead
        } else {
            Vec::new()
        };
        Ok(Erf {
            file_type,
            version,
            build_year,
            build_day,
            description_strref,
            loc_strings,
            resources,
            reserved,
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
        self.resources.push(ErfResource {
            resref: resref.to_string(),
            restype,
            res_id,
            unused: 0,
            data,
            hint: DataHint::default(),
        });
    }

    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let n = self.resources.len();
        let mut loc = Vec::new();
        for l in &self.loc_strings {
            let t = text::encode(&l.text, "ERF localized string")?;
            loc.put_u32(l.language);
            loc.put_u32(to32(t.len())?);
            loc.extend_from_slice(&t);
        }
        let key_off = HEADER_LEN + loc.len();
        let res_off = key_off + 24 * n;
        let tables_end = res_off + 8 * n;

        let mut out = Vec::new();
        out.extend_from_slice(&self.file_type);
        out.extend_from_slice(&self.version);
        out.put_u32(to32(self.loc_strings.len())?);
        out.put_u32(to32(loc.len())?);
        out.put_u32(to32(n)?);
        out.put_u32(HEADER_LEN as u32);
        out.put_u32(to32(key_off)?);
        out.put_u32(to32(res_off)?);
        out.put_u32(self.build_year);
        out.put_u32(self.build_day);
        out.put_u32(self.description_strref);
        let mut reserved = self.reserved.clone();
        reserved.resize(116, 0);
        out.extend_from_slice(&reserved);
        out.extend_from_slice(&loc);
        for r in &self.resources {
            out.put_fixed(&r.resref, 16, "ERF resref")?;
            out.put_u32(r.res_id);
            out.put_u16(r.restype.0);
            out.put_u16(r.unused);
        }
        // Data offsets.
        let hints: Vec<&DataHint> = self.resources.iter().map(|r| &r.hint).collect();
        let order = data_order(&hints);
        let mut offsets = vec![0usize; n];
        let mut pos = tables_end + self.lead.0.len();
        for &i in &order {
            offsets[i] = pos;
            pos += self.resources[i].data.len() + self.resources[i].hint.pad_after.len();
        }
        for (i, r) in self.resources.iter().enumerate() {
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

    fn sample() -> Erf {
        let mut e = Erf::new("MOD");
        e.build_year = 103;
        e.description_strref = 1234;
        e.loc_strings.push(ErfLocString {
            language: 0,
            text: "A module".into(),
        });
        e.insert("module", ResType::IFO, b"ifo data".to_vec());
        e.insert("area01", ResType::ARE, vec![7; 33]);
        e.insert("empty", ResType::TXI, Vec::new());
        e
    }

    #[test]
    fn round_trip() {
        let e = sample();
        let bytes = e.to_bytes().unwrap();
        assert_eq!(&bytes[..8], b"MOD V1.0");
        let back = Erf::read(&bytes).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.get("AREA01", ResType::ARE), Some(&[7u8; 33][..]));
        assert_eq!(back.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn padding_and_order_survive() {
        // Hand-place the data in reverse order with 4-byte alignment padding.
        let e = sample();
        let mut bytes = e.to_bytes().unwrap();
        let n = e.resources.len();
        let tables_end = bytes.len() - e.resources.iter().map(|r| r.data.len()).sum::<usize>();
        bytes.truncate(tables_end);
        let res_off = tables_end - 8 * n;
        let mut pos = tables_end + 2; // two lead bytes
        bytes.extend_from_slice(&[0xEE, 0xEE]);
        for i in (0..n).rev() {
            let d = &e.resources[i].data;
            bytes[res_off + 8 * i..res_off + 8 * i + 4]
                .copy_from_slice(&(pos as u32).to_le_bytes());
            bytes.extend_from_slice(d);
            let pad = (4 - d.len() % 4) % 4;
            bytes.extend(std::iter::repeat_n(0u8, pad));
            pos += d.len() + pad;
        }
        let back = Erf::read(&bytes).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn errors() {
        assert!(Erf::read(b"ERF V1.1").is_err());
        let bytes = sample().to_bytes().unwrap();
        assert!(Erf::read(&bytes[..bytes.len() - 1]).is_err());
        let mut e = Erf::new("ERF");
        e.insert("a_name_that_is_far_too_long", ResType::TGA, vec![]);
        assert!(e.to_bytes().is_err());
    }
}
