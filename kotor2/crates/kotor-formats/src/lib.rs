//! Readers and writers for the resource formats of BioWare's Odyssey engine,
//! as used by *Star Wars: Knights of the Old Republic* (KotOR 1) and
//! *KotOR II: The Sith Lords* (KotOR 2).
//!
//! Pure Rust, no `unsafe`, no platform-specific code. Every writer aims for a
//! byte-exact round trip of unmodified data; see each module for exactly what
//! it preserves.
//!
//! | module | format |
//! | --- | --- |
//! | [`gff`] | GFF V3.2 (generic tree) |
//! | [`gui`] | `.gui` controls on top of GFF |
//! | [`key`] | KEY V1 / BIF V1 (`chitin.key` and `data/*.bif`) |
//! | [`erf`] | ERF / MOD / SAV / HAK V1.0 |
//! | [`rim`] | RIM V1.0 |
//! | [`twoda`] | 2DA V2.b (binary) and V2.0 (text) |
//! | [`tlk`] | TLK V3.0 |
//! | [`tpc`] | TPC textures (DXT1, DXT5, uncompressed) with trailing TXI |
//! | [`tga`] | TGA (uncompressed and RLE) |
//! | [`txi`] | TXI texture info text |
//! | [`restype`] | resource type ids |
//! | [`text`] | the byte <-> string mapping all of the above use |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod binio;
pub mod erf;
pub mod error;
pub mod fsutil;
pub mod gff;
pub mod gui;
pub mod key;
pub mod restype;
pub mod rim;
pub mod text;
pub mod tga;
pub mod tlk;
pub mod tpc;
pub mod twoda;
pub mod txi;

pub use error::{Error, Result};
pub use restype::ResType;

/// The kind of archive a file is, by its signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveKind {
    /// ERF V1.0 family (`ERF `, `MOD `, `SAV `, `HAK `).
    Erf,
    /// RIM V1.0.
    Rim,
}

/// Identify an ERF-family or RIM archive from its first 8 bytes.
pub fn archive_kind(head: &[u8]) -> Option<ArchiveKind> {
    let sig = head.get(..8)?;
    match &sig[..4] {
        b"ERF " | b"MOD " | b"SAV " | b"HAK " if &sig[4..] == b"V1.0" => Some(ArchiveKind::Erf),
        b"RIM " if &sig[4..] == b"V1.0" => Some(ArchiveKind::Rim),
        _ => None,
    }
}

/// A resource inside an archive, independent of the archive type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// Resource name (no extension).
    pub resref: String,
    /// Resource type.
    pub restype: ResType,
    /// Size in bytes.
    pub size: usize,
}

/// An ERF-family or RIM archive, opened by signature.
#[derive(Clone, Debug, PartialEq)]
pub enum Archive {
    /// ERF / MOD / SAV / HAK.
    Erf(erf::Erf),
    /// RIM.
    Rim(rim::Rim),
}

impl Archive {
    /// Parse either kind.
    pub fn read(data: &[u8]) -> Result<Archive> {
        match archive_kind(data) {
            Some(ArchiveKind::Erf) => Ok(Archive::Erf(erf::Erf::read(data)?)),
            Some(ArchiveKind::Rim) => Ok(Archive::Rim(rim::Rim::read(data)?)),
            None => Err(Error::BadSignature {
                format: "archive",
                found: String::from_utf8_lossy(data.get(..8).unwrap_or(data)).into_owned(),
                expected: "ERF V1.0, MOD V1.0, SAV V1.0, HAK V1.0 or RIM V1.0",
            }),
        }
    }

    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Archive::Erf(e) => e.to_bytes(),
            Archive::Rim(r) => r.to_bytes(),
        }
    }

    /// The resources, in file order.
    pub fn entries(&self) -> Vec<ArchiveEntry> {
        match self {
            Archive::Erf(e) => e
                .resources
                .iter()
                .map(|r| ArchiveEntry {
                    resref: r.resref.clone(),
                    restype: r.restype,
                    size: r.data.len(),
                })
                .collect(),
            Archive::Rim(r) => r
                .resources
                .iter()
                .map(|r| ArchiveEntry {
                    resref: r.resref.clone(),
                    restype: r.restype,
                    size: r.data.len(),
                })
                .collect(),
        }
    }

    /// Data of a resource (resref compared case-insensitively).
    pub fn get(&self, resref: &str, restype: ResType) -> Option<&[u8]> {
        match self {
            Archive::Erf(e) => e.get(resref, restype),
            Archive::Rim(r) => r.get(resref, restype),
        }
    }

    /// Data by position.
    pub fn data(&self, index: usize) -> Option<&[u8]> {
        match self {
            Archive::Erf(e) => e.resources.get(index).map(|r| r.data.as_slice()),
            Archive::Rim(r) => r.resources.get(index).map(|r| r.data.as_slice()),
        }
    }
}
