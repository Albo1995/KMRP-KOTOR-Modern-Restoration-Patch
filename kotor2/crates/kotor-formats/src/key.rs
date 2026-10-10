//! KEY V1 (`chitin.key`) and BIF V1 (`data/*.bif`), read-only.
//!
//! # Layout (from public documentation: BioWare's "Key and BIF Files" PDF, xoreos)
//!
//! KEY: `"KEY V1  "`, BIF count, key count, file-table offset, key-table offset,
//! build year, build day, 32 reserved bytes. File table: 12 bytes per BIF (file
//! size, name offset, name length u16, drive flags u16); names are
//! NUL-terminated Windows paths relative to the game folder (`data\2da.bif`).
//! Key table: 22 bytes per resource (resref[16], type u16, resource id u32).
//! The resource id packs the BIF index in the top 12 bits and the entry index
//! inside that BIF in the low 20.
//!
//! BIF: `"BIFFV1  "`, variable-resource count, fixed-resource count,
//! variable-table offset. Variable table: 16 bytes per resource (id, offset,
//! size, type u32). KotOR does not use fixed resources.
//!
//! KotOR 2 PC uses the same KEY/BIF V1 layout as KotOR 1. The compressed
//! `BZF` BIFs of the Xbox and mobile releases are not supported.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::binio::{us, Bytes};
use crate::error::{read_file, Error, Result};
use crate::fsutil;
use crate::restype::ResType;

const KEY_FMT: &str = "KEY";
const BIF_FMT: &str = "BIF";

/// One BIF named by the KEY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBif {
    /// File size the KEY records.
    pub size: u32,
    /// Path as stored, e.g. `data\2da.bif`.
    pub filename: String,
    /// Drive flags (unused on PC).
    pub drives: u16,
}

/// One resource named by the KEY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyResource {
    /// Resource name.
    pub resref: String,
    /// Resource type.
    pub restype: ResType,
    /// Packed BIF index and entry index.
    pub res_id: u32,
}

impl KeyResource {
    /// Index into [`KeyFile::bifs`].
    pub fn bif_index(&self) -> usize {
        us(self.res_id >> 20)
    }
    /// Index into the BIF's variable resource table.
    pub fn entry_index(&self) -> usize {
        us(self.res_id & 0xF_FFFF)
    }
}

/// A parsed KEY file.
#[derive(Clone, Debug)]
pub struct KeyFile {
    /// BIF table.
    pub bifs: Vec<KeyBif>,
    /// Resource table, in file order.
    pub resources: Vec<KeyResource>,
    /// Build year (since 1900).
    pub build_year: u32,
    /// Build day of year.
    pub build_day: u32,
    index: HashMap<(String, u16), usize>,
}

impl KeyFile {
    /// Parse a KEY file.
    pub fn read(data: &[u8]) -> Result<KeyFile> {
        let b = Bytes::new(data, KEY_FMT);
        b.signature("KEY V1  ")?;
        let bif_count = us(b.u32(8)?);
        let key_count = us(b.u32(12)?);
        let file_table = us(b.u32(16)?);
        let key_table = us(b.u32(20)?);
        let build_year = b.u32(24)?;
        let build_day = b.u32(28)?;
        b.slice(file_table, bif_count.saturating_mul(12))?;
        b.slice(key_table, key_count.saturating_mul(22))?;
        let mut bifs = Vec::with_capacity(bif_count.min(4096));
        for i in 0..bif_count {
            let at = file_table + 12 * i;
            let size = b.u32(at)?;
            let name_off = us(b.u32(at + 4)?);
            let name_len = usize::from(b.u16(at + 8)?);
            let drives = b.u16(at + 10)?;
            let filename = b.fixed_str(name_off, name_len)?;
            bifs.push(KeyBif {
                size,
                filename,
                drives,
            });
        }
        let mut resources = Vec::with_capacity(key_count.min(1 << 20));
        let mut index = HashMap::with_capacity(key_count.min(1 << 20));
        for i in 0..key_count {
            let at = key_table + 22 * i;
            let resref = b.fixed_str(at, 16)?;
            let restype = ResType(b.u16(at + 16)?);
            let res_id = b.u32(at + 18)?;
            index
                .entry((resref.to_ascii_lowercase(), restype.0))
                .or_insert(i);
            resources.push(KeyResource {
                resref,
                restype,
                res_id,
            });
        }
        Ok(KeyFile {
            bifs,
            resources,
            build_year,
            build_day,
            index,
        })
    }

    /// Find a resource (resref compared case-insensitively). When the KEY
    /// lists a name twice, the first entry wins.
    pub fn lookup(&self, resref: &str, restype: ResType) -> Option<&KeyResource> {
        self.index
            .get(&(resref.to_ascii_lowercase(), restype.0))
            .map(|&i| &self.resources[i])
    }
}

/// One entry of a BIF's variable resource table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BifEntry {
    /// Resource id as stored in the BIF.
    pub id: u32,
    /// Absolute offset of the data.
    pub offset: u32,
    /// Size of the data.
    pub size: u32,
    /// Resource type as stored in the BIF.
    pub restype: u32,
}

/// A BIF file opened for random access.
#[derive(Debug)]
pub struct Bif<R> {
    reader: R,
    len: u64,
    /// Variable resource table.
    pub entries: Vec<BifEntry>,
}

impl Bif<File> {
    /// Open a BIF on disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Bif<File>> {
        let path = path.as_ref();
        let f = File::open(path).map_err(|e| Error::file(path, e))?;
        Bif::new(f).map_err(|e| match e {
            Error::Io(io) => Error::file(path, io),
            other => Error::invalid(BIF_FMT, format!("{}: {other}", path.display())),
        })
    }
}

impl<R: Read + Seek> Bif<R> {
    /// Read the header and resource table.
    pub fn new(mut reader: R) -> Result<Bif<R>> {
        let len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut head = [0u8; 20];
        let got = read_up_to(&mut reader, &mut head)?;
        let b = Bytes::new(&head[..got], BIF_FMT);
        b.signature("BIFFV1  ")?;
        let var_count = us(b.u32(8)?);
        let table = u64::from(b.u32(16)?);
        let table_len = (var_count as u64) * 16;
        if table + table_len > len {
            return Err(Error::invalid(
                BIF_FMT,
                format!("resource table ({var_count} entries at {table}) runs past the end of the file ({len} bytes)"),
            ));
        }
        reader.seek(SeekFrom::Start(table))?;
        let mut raw = vec![0u8; var_count * 16];
        reader.read_exact(&mut raw)?;
        let t = Bytes::new(&raw, BIF_FMT);
        let entries = (0..var_count)
            .map(|i| {
                Ok(BifEntry {
                    id: t.u32(16 * i)?,
                    offset: t.u32(16 * i + 4)?,
                    size: t.u32(16 * i + 8)?,
                    restype: t.u32(16 * i + 12)?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Bif {
            reader,
            len,
            entries,
        })
    }

    /// Find the table entry for a KEY entry index. Normally the entry at that
    /// position; falls back to searching by the id's low 20 bits.
    pub fn entry_for(&self, entry_index: usize) -> Option<BifEntry> {
        match self.entries.get(entry_index) {
            Some(e) if us(e.id & 0xF_FFFF) == entry_index => Some(*e),
            _ => self
                .entries
                .iter()
                .find(|e| us(e.id & 0xF_FFFF) == entry_index)
                .copied(),
        }
    }

    /// Read a resource's bytes by table entry.
    pub fn read_entry(&mut self, e: BifEntry) -> Result<Vec<u8>> {
        let end = u64::from(e.offset) + u64::from(e.size);
        if end > self.len {
            return Err(Error::invalid(
                BIF_FMT,
                format!(
                    "resource {:#x} ({} bytes at {}) runs past the end of the file ({} bytes)",
                    e.id, e.size, e.offset, self.len
                ),
            ));
        }
        self.reader.seek(SeekFrom::Start(u64::from(e.offset)))?;
        let mut buf = vec![0u8; us(e.size)];
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..])? {
            0 => break,
            n => got += n,
        }
    }
    Ok(got)
}

/// `chitin.key` plus its BIFs, resolved relative to the KEY's folder.
#[derive(Debug)]
pub struct Chitin {
    /// The folder holding `chitin.key` (the game folder).
    pub root: PathBuf,
    /// The parsed KEY.
    pub key: KeyFile,
    open: HashMap<usize, Bif<File>>,
}

impl Chitin {
    /// Open a `chitin.key`. BIFs are opened lazily.
    pub fn open(key_path: impl AsRef<Path>) -> Result<Chitin> {
        let key_path = key_path.as_ref();
        let data = read_file(key_path)?;
        let key = KeyFile::read(&data)
            .map_err(|e| Error::invalid(KEY_FMT, format!("{}: {e}", key_path.display())))?;
        let root = key_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(Chitin {
            root,
            key,
            open: HashMap::new(),
        })
    }

    /// The on-disk path of a BIF, resolved case-insensitively.
    pub fn bif_path(&self, bif_index: usize) -> Result<PathBuf> {
        let bif = self.key.bifs.get(bif_index).ok_or_else(|| {
            Error::invalid(
                KEY_FMT,
                format!(
                    "BIF index {bif_index} out of range ({} BIFs)",
                    self.key.bifs.len()
                ),
            )
        })?;
        fsutil::resolve(&self.root, &bif.filename).ok_or_else(|| {
            Error::NotFound(format!(
                "{} (named by chitin.key) under {}",
                bif.filename,
                self.root.display()
            ))
        })
    }

    fn bif(&mut self, bif_index: usize) -> Result<&mut Bif<File>> {
        if !self.open.contains_key(&bif_index) {
            let path = self.bif_path(bif_index)?;
            let bif = Bif::open(&path)?;
            self.open.insert(bif_index, bif);
        }
        Ok(self.open.get_mut(&bif_index).expect("just inserted"))
    }

    /// Read the bytes of a KEY entry.
    pub fn read(&mut self, res: &KeyResource) -> Result<Vec<u8>> {
        let (bi, ei) = (res.bif_index(), res.entry_index());
        let name = self
            .key
            .bifs
            .get(bi)
            .map(|b| b.filename.clone())
            .unwrap_or_default();
        let bif = self.bif(bi)?;
        let entry = bif.entry_for(ei).ok_or_else(|| {
            Error::invalid(
                BIF_FMT,
                format!("{name}: no entry {ei} for {}.{}", res.resref, res.restype),
            )
        })?;
        bif.read_entry(entry)
    }

    /// Look up and read a resource.
    pub fn extract(&mut self, resref: &str, restype: ResType) -> Result<Vec<u8>> {
        let res =
            self.key.lookup(resref, restype).cloned().ok_or_else(|| {
                Error::NotFound(format!("{resref}.{restype} is not in chitin.key"))
            })?;
        self.read(&res)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::binio::Put;
    use std::io::Cursor;

    /// Build a synthetic KEY naming one BIF, and that BIF.
    pub(crate) fn synthetic(files: &[(&str, ResType, &[u8])]) -> (Vec<u8>, Vec<u8>) {
        // BIF
        let mut bif = Vec::new();
        bif.extend_from_slice(b"BIFFV1  ");
        bif.put_u32(files.len() as u32);
        bif.put_u32(0);
        bif.put_u32(20);
        let data_start = 20 + 16 * files.len();
        let mut off = data_start;
        for (i, (_, t, d)) in files.iter().enumerate() {
            bif.put_u32(i as u32); // bif index 0
            bif.put_u32(off as u32);
            bif.put_u32(d.len() as u32);
            bif.put_u32(u32::from(t.0));
            off += d.len();
        }
        for (_, _, d) in files {
            bif.extend_from_slice(d);
        }
        // KEY
        let name = b"data\\test.bif\0";
        let mut key = Vec::new();
        key.extend_from_slice(b"KEY V1  ");
        key.put_u32(1);
        key.put_u32(files.len() as u32);
        key.put_u32(64);
        let key_table = 64 + 12 + name.len();
        key.put_u32(key_table as u32);
        key.put_u32(103);
        key.put_u32(200);
        key.resize(64, 0);
        key.put_u32(bif.len() as u32);
        key.put_u32(76);
        key.put_u16(name.len() as u16);
        key.put_u16(1);
        key.extend_from_slice(name);
        for (i, (r, t, _)) in files.iter().enumerate() {
            key.put_fixed(r, 16, "resref").unwrap();
            key.put_u16(t.0);
            key.put_u32(i as u32);
        }
        (key, bif)
    }

    #[test]
    fn key_and_bif() {
        let files: &[(&str, ResType, &[u8])] = &[
            ("mainmenu", ResType::GUI, b"gui bytes"),
            ("appearance", ResType::TWODA, b"2da bytes!"),
        ];
        let (key, bif) = synthetic(files);
        let k = KeyFile::read(&key).unwrap();
        assert_eq!(k.bifs[0].filename, "data\\test.bif");
        let r = k.lookup("MAINMENU", ResType::GUI).unwrap();
        assert_eq!((r.bif_index(), r.entry_index()), (0, 0));
        let mut b = Bif::new(Cursor::new(bif.clone())).unwrap();
        let e = b.entry_for(1).unwrap();
        assert_eq!(b.read_entry(e).unwrap(), b"2da bytes!");

        // Through Chitin on disk, with a case mismatch on the BIF path.
        let dir = std::env::temp_dir().join(format!("kotor-formats-key-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("Data")).unwrap();
        std::fs::write(dir.join("chitin.key"), &key).unwrap();
        std::fs::write(dir.join("Data").join("TEST.bif"), &bif).unwrap();
        let mut c = Chitin::open(dir.join("chitin.key")).unwrap();
        assert_eq!(c.extract("mainmenu", ResType::GUI).unwrap(), b"gui bytes");
        assert!(matches!(
            c.extract("nothere", ResType::GUI),
            Err(Error::NotFound(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn truncated_key_is_an_error() {
        let (key, _) = synthetic(&[("a", ResType::GUI, b"x")]);
        assert!(KeyFile::read(&key[..key.len() - 1]).is_err());
        assert!(KeyFile::read(b"KEY V2  ").is_err());
    }
}
