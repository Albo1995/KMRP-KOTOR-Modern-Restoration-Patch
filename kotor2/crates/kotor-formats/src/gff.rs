//! GFF V3.2, the Generic File Format used by `.gui`, `.utc`, `.dlg`, `.are`,
//! `.ifo`, `.git` and most other structured resources.
//!
//! # Layout (from public documentation: BioWare's "GFF Format" PDF, xoreos, PyKotor)
//!
//! A 56-byte header (`type[4] version[4]` then six `offset,count` u32 pairs) is
//! followed by six sections: struct array (12 bytes each: id, data-or-offset,
//! field count), field array (12 bytes each: type, label index,
//! data-or-offset), label array (16-byte NUL-padded names), field data (the
//! payload of "complex" fields), field indices (u32 field index lists for
//! structs with more than one field) and list indices (`count` then `count`
//! struct indices, per List field).
//!
//! # Round trips
//!
//! [`Gff::read`] remembers, on every struct and field, where it sat in the
//! source file (struct index, field index, label index, data offset, and the
//! raw inline dword). [`Gff::to_bytes`] lays the sections out in that original
//! order, and only falls back to a canonical depth-first order for nodes that
//! have no such hint (new nodes). Offsets are always recomputed, so the output
//! is valid whatever was edited; when nothing was edited and the source file
//! was densely packed (no unreferenced or shared bytes) the output is
//! byte-identical. The hints are invisible to `==`.
//!
//! Unreferenced bytes in the three variable sections (field data, field
//! indices, list indices) are kept with the block they follow, and blocks the
//! source shared stay shared, so files with dead or shared bytes also come
//! back exactly. [`section_usage`] reports both; [`first_difference`] compares
//! two trees.

use std::collections::HashMap;

use crate::binio::{trim_nul, us, Bytes, Hint, Put};
use crate::error::{Error, Result};
use crate::text;

const FMT: &str = "GFF";
const HEADER_LEN: usize = 56;
const MAX_DEPTH: usize = 512;

/// "No string" value of a [`LocString::strref`].
pub const STRREF_NONE: u32 = u32::MAX;

/// Field type ids as stored on disk.
pub mod field_type {
    #![allow(missing_docs)]
    pub const BYTE: u32 = 0;
    pub const CHAR: u32 = 1;
    pub const WORD: u32 = 2;
    pub const SHORT: u32 = 3;
    pub const DWORD: u32 = 4;
    pub const INT: u32 = 5;
    pub const DWORD64: u32 = 6;
    pub const INT64: u32 = 7;
    pub const FLOAT: u32 = 8;
    pub const DOUBLE: u32 = 9;
    pub const CEXOSTRING: u32 = 10;
    pub const RESREF: u32 = 11;
    pub const CEXOLOCSTRING: u32 = 12;
    pub const VOID: u32 = 13;
    pub const STRUCT: u32 = 14;
    pub const LIST: u32 = 15;
    pub const ORIENTATION: u32 = 16;
    pub const VECTOR: u32 = 17;
}

fn key(v: Option<u32>) -> u64 {
    v.map_or(u64::MAX, u64::from)
}

/// Where a struct sat in the source file. Ignored by `==`.
#[derive(Clone, Copy, Debug, Default)]
struct StructHint {
    index: Option<u32>,
    /// Field-indices offset (multi-field structs).
    indices: Option<u32>,
    /// Raw data dword of a struct that had no fields.
    empty_raw: Option<u32>,
}

impl PartialEq for StructHint {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

/// Where a field sat in the source file. Ignored by `==`.
#[derive(Clone, Copy, Debug, Default)]
struct FieldHint {
    index: Option<u32>,
    label: Option<u32>,
    /// Field-data offset (complex types) or list-indices offset (lists).
    data: Option<u32>,
    /// The raw inline dword, to keep any upper bytes of narrow types.
    raw: Option<u32>,
}

impl PartialEq for FieldHint {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

/// One language/gender variant of a [`LocString`].
#[derive(Clone, Debug, PartialEq)]
pub struct LocSubstring {
    /// `language * 2 + gender` (gender 1 = feminine).
    pub id: u32,
    /// The text.
    pub text: String,
}

impl LocSubstring {
    /// Language id (0 English, 1 French, 2 German, 3 Italian, 4 Spanish, 5 Polish, ...).
    pub fn language(&self) -> u32 {
        self.id / 2
    }
    /// True for the feminine variant.
    pub fn feminine(&self) -> bool {
        self.id % 2 == 1
    }
}

/// A CExoLocString: a talk-table reference plus optional embedded strings.
#[derive(Clone, Debug, PartialEq)]
pub struct LocString {
    /// TLK string reference, or [`STRREF_NONE`].
    pub strref: u32,
    /// Embedded strings.
    pub strings: Vec<LocSubstring>,
}

impl Default for LocString {
    fn default() -> Self {
        LocString {
            strref: STRREF_NONE,
            strings: Vec::new(),
        }
    }
}

impl LocString {
    /// The embedded string for a language and gender.
    pub fn get(&self, language: u32, feminine: bool) -> Option<&str> {
        let id = language * 2 + u32::from(feminine);
        self.strings
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.text.as_str())
    }
}

/// A field value.
#[derive(Clone, Debug, PartialEq)]
pub enum GffValue {
    /// 0: unsigned 8-bit.
    Byte(u8),
    /// 1: signed 8-bit.
    Char(i8),
    /// 2: unsigned 16-bit.
    Word(u16),
    /// 3: signed 16-bit.
    Short(i16),
    /// 4: unsigned 32-bit.
    DWord(u32),
    /// 5: signed 32-bit.
    Int(i32),
    /// 6: unsigned 64-bit.
    DWord64(u64),
    /// 7: signed 64-bit.
    Int64(i64),
    /// 8: 32-bit float.
    Float(f32),
    /// 9: 64-bit float.
    Double(f64),
    /// 10: CExoString (u32 length prefix).
    String(String),
    /// 11: CResRef (u8 length prefix, at most 16 bytes in practice).
    ResRef(String),
    /// 12: CExoLocString.
    LocString(LocString),
    /// 13: raw bytes (u32 length prefix).
    Void(Vec<u8>),
    /// 14: nested struct.
    Struct(GffStruct),
    /// 15: list of structs.
    List(Vec<GffStruct>),
    /// 16: quaternion, four floats (w, x, y, z order as stored).
    Orientation([f32; 4]),
    /// 17: three floats.
    Vector([f32; 3]),
    /// Any other type id; the raw data dword is kept so it round-trips.
    Unknown {
        /// The type id.
        type_id: u32,
        /// The raw data-or-offset dword.
        data: u32,
    },
}

impl GffValue {
    /// The on-disk type id.
    pub fn type_id(&self) -> u32 {
        use field_type::*;
        match self {
            GffValue::Byte(_) => BYTE,
            GffValue::Char(_) => CHAR,
            GffValue::Word(_) => WORD,
            GffValue::Short(_) => SHORT,
            GffValue::DWord(_) => DWORD,
            GffValue::Int(_) => INT,
            GffValue::DWord64(_) => DWORD64,
            GffValue::Int64(_) => INT64,
            GffValue::Float(_) => FLOAT,
            GffValue::Double(_) => DOUBLE,
            GffValue::String(_) => CEXOSTRING,
            GffValue::ResRef(_) => RESREF,
            GffValue::LocString(_) => CEXOLOCSTRING,
            GffValue::Void(_) => VOID,
            GffValue::Struct(_) => STRUCT,
            GffValue::List(_) => LIST,
            GffValue::Orientation(_) => ORIENTATION,
            GffValue::Vector(_) => VECTOR,
            GffValue::Unknown { type_id, .. } => *type_id,
        }
    }

    /// A short type name.
    pub fn type_name(&self) -> &'static str {
        match self {
            GffValue::Byte(_) => "Byte",
            GffValue::Char(_) => "Char",
            GffValue::Word(_) => "Word",
            GffValue::Short(_) => "Short",
            GffValue::DWord(_) => "DWord",
            GffValue::Int(_) => "Int",
            GffValue::DWord64(_) => "DWord64",
            GffValue::Int64(_) => "Int64",
            GffValue::Float(_) => "Float",
            GffValue::Double(_) => "Double",
            GffValue::String(_) => "CExoString",
            GffValue::ResRef(_) => "ResRef",
            GffValue::LocString(_) => "CExoLocString",
            GffValue::Void(_) => "Void",
            GffValue::Struct(_) => "Struct",
            GffValue::List(_) => "List",
            GffValue::Orientation(_) => "Orientation",
            GffValue::Vector(_) => "Vector",
            GffValue::Unknown { .. } => "Unknown",
        }
    }

    fn is_complex(type_id: u32) -> bool {
        use field_type::*;
        matches!(
            type_id,
            DWORD64
                | INT64
                | DOUBLE
                | CEXOSTRING
                | RESREF
                | CEXOLOCSTRING
                | VOID
                | ORIENTATION
                | VECTOR
        )
    }

    /// Any integer variant, widened.
    pub fn as_int(&self) -> Option<i64> {
        Some(match *self {
            GffValue::Byte(v) => v.into(),
            GffValue::Char(v) => v.into(),
            GffValue::Word(v) => v.into(),
            GffValue::Short(v) => v.into(),
            GffValue::DWord(v) => v.into(),
            GffValue::Int(v) => v.into(),
            GffValue::DWord64(v) => v as i64,
            GffValue::Int64(v) => v,
            _ => return None,
        })
    }

    /// Float or Double.
    pub fn as_float(&self) -> Option<f64> {
        match *self {
            GffValue::Float(v) => Some(v.into()),
            GffValue::Double(v) => Some(v),
            _ => None,
        }
    }

    /// CExoString or ResRef text.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            GffValue::String(s) | GffValue::ResRef(s) => Some(s),
            _ => None,
        }
    }

    /// The nested struct.
    pub fn as_struct(&self) -> Option<&GffStruct> {
        match self {
            GffValue::Struct(s) => Some(s),
            _ => None,
        }
    }

    /// The nested struct, mutably.
    pub fn as_struct_mut(&mut self) -> Option<&mut GffStruct> {
        match self {
            GffValue::Struct(s) => Some(s),
            _ => None,
        }
    }

    /// The list.
    pub fn as_list(&self) -> Option<&[GffStruct]> {
        match self {
            GffValue::List(l) => Some(l),
            _ => None,
        }
    }

    /// The list, mutably.
    pub fn as_list_mut(&mut self) -> Option<&mut Vec<GffStruct>> {
        match self {
            GffValue::List(l) => Some(l),
            _ => None,
        }
    }

    /// Store an integer in whatever integer variant this already is. Fails
    /// (returning false, leaving the value untouched) if this is not an
    /// integer or `v` does not fit.
    pub fn set_int(&mut self, v: i64) -> bool {
        macro_rules! fit {
            ($var:ident, $t:ty) => {
                match <$t>::try_from(v) {
                    Ok(x) => {
                        *self = GffValue::$var(x);
                        true
                    }
                    Err(_) => false,
                }
            };
        }
        match self {
            GffValue::Byte(_) => fit!(Byte, u8),
            GffValue::Char(_) => fit!(Char, i8),
            GffValue::Word(_) => fit!(Word, u16),
            GffValue::Short(_) => fit!(Short, i16),
            GffValue::DWord(_) => fit!(DWord, u32),
            GffValue::Int(_) => fit!(Int, i32),
            GffValue::DWord64(_) => fit!(DWord64, u64),
            GffValue::Int64(_) => {
                *self = GffValue::Int64(v);
                true
            }
            _ => false,
        }
    }
}

/// A labelled field.
#[derive(Clone, Debug, PartialEq)]
pub struct GffField {
    /// Label, at most 16 bytes.
    pub label: String,
    /// Value.
    pub value: GffValue,
    hint: FieldHint,
}

impl GffField {
    /// A new field.
    pub fn new(label: impl Into<String>, value: GffValue) -> Self {
        GffField {
            label: label.into(),
            value,
            hint: FieldHint::default(),
        }
    }
}

/// A struct: a type id and an ordered list of fields.
#[derive(Clone, Debug, PartialEq)]
pub struct GffStruct {
    /// Struct id (the root uses 0xFFFFFFFF).
    pub struct_id: u32,
    /// Fields, in file order.
    pub fields: Vec<GffField>,
    hint: StructHint,
}

/// One step of a path: `LABEL` or `LABEL[index]`.
fn parse_segment(seg: &str) -> Option<(&str, Option<usize>)> {
    match seg.find('[') {
        None => Some((seg, None)),
        Some(open) => {
            let rest = seg[open + 1..].strip_suffix(']')?;
            Some((&seg[..open], Some(rest.trim().parse().ok()?)))
        }
    }
}

impl GffStruct {
    /// An empty struct.
    pub fn new(struct_id: u32) -> Self {
        GffStruct {
            struct_id,
            fields: Vec::new(),
            hint: StructHint::default(),
        }
    }

    /// The field with this label (case-sensitive, as the engine is).
    pub fn field(&self, label: &str) -> Option<&GffField> {
        self.fields.iter().find(|f| f.label == label)
    }

    /// The field with this label, mutably.
    pub fn field_mut(&mut self, label: &str) -> Option<&mut GffField> {
        self.fields.iter_mut().find(|f| f.label == label)
    }

    /// The value of a field.
    pub fn get(&self, label: &str) -> Option<&GffValue> {
        self.field(label).map(|f| &f.value)
    }

    /// The value of a field, mutably.
    pub fn get_mut(&mut self, label: &str) -> Option<&mut GffValue> {
        self.field_mut(label).map(|f| &mut f.value)
    }

    /// Set a field, replacing an existing one in place (keeping its position)
    /// or appending a new one. Returns the old value.
    pub fn set(&mut self, label: &str, value: GffValue) -> Option<GffValue> {
        match self.field_mut(label) {
            Some(f) => Some(std::mem::replace(&mut f.value, value)),
            None => {
                self.fields.push(GffField::new(label, value));
                None
            }
        }
    }

    /// Remove a field, returning its value.
    pub fn remove(&mut self, label: &str) -> Option<GffValue> {
        let pos = self.fields.iter().position(|f| f.label == label)?;
        Some(self.fields.remove(pos).value)
    }

    /// Integer field (any integer type).
    pub fn get_int(&self, label: &str) -> Option<i64> {
        self.get(label)?.as_int()
    }

    /// Float or Double field.
    pub fn get_float(&self, label: &str) -> Option<f64> {
        self.get(label)?.as_float()
    }

    /// CExoString or ResRef field.
    pub fn get_str(&self, label: &str) -> Option<&str> {
        self.get(label)?.as_str()
    }

    /// Struct field.
    pub fn get_struct(&self, label: &str) -> Option<&GffStruct> {
        self.get(label)?.as_struct()
    }

    /// Struct field, mutably.
    pub fn get_struct_mut(&mut self, label: &str) -> Option<&mut GffStruct> {
        self.get_mut(label)?.as_struct_mut()
    }

    /// List field.
    pub fn get_list(&self, label: &str) -> Option<&[GffStruct]> {
        self.get(label)?.as_list()
    }

    /// List field, mutably.
    pub fn get_list_mut(&mut self, label: &str) -> Option<&mut Vec<GffStruct>> {
        self.get_mut(label)?.as_list_mut()
    }

    /// Set an integer field. An existing integer field keeps its stored type
    /// (failing if `v` does not fit it); a missing or non-integer field becomes
    /// [`GffValue::Int`].
    pub fn set_int(&mut self, label: &str, v: i64) -> Result<()> {
        if let Some(existing) = self.get_mut(label) {
            if existing.as_int().is_some() {
                return if existing.set_int(v) {
                    Ok(())
                } else {
                    Err(Error::Encode {
                        what: "GFF integer field",
                        message: format!(
                            "{v} does not fit field {label} ({})",
                            existing.type_name()
                        ),
                    })
                };
            }
        }
        let iv = i32::try_from(v).map_err(|_| Error::Encode {
            what: "GFF integer field",
            message: format!("{v} does not fit an Int"),
        })?;
        self.set(label, GffValue::Int(iv));
        Ok(())
    }

    /// The struct a slash-separated path leads to, e.g. `CONTROLS[3]/EXTENT`.
    /// An empty path is `self`.
    pub fn path_struct(&self, path: &str) -> Option<&GffStruct> {
        let mut cur = self;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            let (label, index) = parse_segment(seg)?;
            cur = match index {
                None => cur.get_struct(label)?,
                Some(i) => cur.get_list(label)?.get(i)?,
            };
        }
        Some(cur)
    }

    /// Mutable form of [`GffStruct::path_struct`].
    pub fn path_struct_mut(&mut self, path: &str) -> Option<&mut GffStruct> {
        let mut cur = self;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            let (label, index) = parse_segment(seg)?;
            cur = match index {
                None => cur.get_struct_mut(label)?,
                Some(i) => cur.get_list_mut(label)?.get_mut(i)?,
            };
        }
        Some(cur)
    }

    /// The value at a path whose last segment is a field label, e.g.
    /// `CONTROLS[3]/EXTENT/LEFT`.
    pub fn path(&self, path: &str) -> Option<&GffValue> {
        let (parent, last) = match path.rsplit_once('/') {
            Some((p, l)) => (p, l),
            None => ("", path),
        };
        self.path_struct(parent)?.get(last)
    }

    /// Mutable form of [`GffStruct::path`].
    pub fn path_mut(&mut self, path: &str) -> Option<&mut GffValue> {
        let (parent, last) = match path.rsplit_once('/') {
            Some((p, l)) => (p, l),
            None => ("", path),
        };
        self.path_struct_mut(parent)?.get_mut(last)
    }
}

/// A GFF file.
#[derive(Clone, Debug, PartialEq)]
pub struct Gff {
    /// Four-character content type, e.g. `b"GUI "`, `b"UTC "`.
    pub file_type: [u8; 4],
    /// Version, `b"V3.2"`.
    pub version: [u8; 4],
    /// The root struct.
    pub root: GffStruct,
    /// The source label table (raw 16-byte entries), reused on write.
    labels: Hint<Vec<[u8; 16]>>,
    /// Unreferenced bytes of the field-data, field-indices and list-indices
    /// sections, reproduced on write.
    layout: Hint<[SectionGaps; 3]>,
}

/// Bytes of a variable section that no field or struct references, keyed by
/// the source offset of the block they follow.
#[derive(Clone, Debug, Default)]
struct SectionGaps {
    lead: Vec<u8>,
    after: HashMap<u32, Vec<u8>>,
}

/// Section names of the three variable sections, in [`SectionGaps`] order.
const VAR_SECTIONS: [&str; 3] = ["field data", "field indices", "list indices"];

/// Sort referenced `(start, len)` blocks and collect the bytes between them.
fn capture_gaps(section: &[u8], ranges: &[(usize, usize)]) -> SectionGaps {
    let mut r = ranges.to_vec();
    r.sort_unstable();
    r.dedup_by(|b, a| {
        // Same start: keep the longer extent in `a`.
        if a.0 == b.0 {
            a.1 = a.1.max(b.1);
            true
        } else {
            false
        }
    });
    let mut g = SectionGaps::default();
    let mut pos = 0usize;
    let mut prev: Option<u32> = None;
    for &(start, len) in &r {
        if start >= pos {
            let gap = section.get(pos..start).unwrap_or_default().to_vec();
            match prev {
                None => g.lead = gap,
                Some(p) if !gap.is_empty() => {
                    g.after.insert(p, gap);
                }
                Some(_) => {}
            }
            prev = Some(start as u32);
        }
        pos = pos.max(start + len);
    }
    let tail = section
        .get(pos.min(section.len())..)
        .unwrap_or_default()
        .to_vec();
    match prev {
        None => g.lead = tail,
        Some(p) if !tail.is_empty() => g.after.entry(p).or_default().extend_from_slice(&tail),
        Some(_) => {}
    }
    g
}

/// The first difference between two trees, as `path: description`, or
/// `None` if they are equal (layout hints are ignored, as with `==`).
pub fn first_difference(a: &Gff, b: &Gff) -> Option<String> {
    if a.file_type != b.file_type {
        return Some(format!(
            "file type {:?} vs {:?}",
            a.file_type_str(),
            b.file_type_str()
        ));
    }
    struct_difference(&a.root, &b.root, "(root)")
}

fn struct_difference(a: &GffStruct, b: &GffStruct, path: &str) -> Option<String> {
    if a.struct_id != b.struct_id {
        return Some(format!(
            "{path}: struct id {} vs {}",
            a.struct_id, b.struct_id
        ));
    }
    for (i, (fa, fb)) in a.fields.iter().zip(&b.fields).enumerate() {
        let here = format!("{path}/{}", fa.label);
        if fa.label != fb.label {
            return Some(format!(
                "{path}: field {i} label {:?} vs {:?}",
                fa.label, fb.label
            ));
        }
        match (&fa.value, &fb.value) {
            (GffValue::Struct(x), GffValue::Struct(y)) => {
                if let Some(d) = struct_difference(x, y, &here) {
                    return Some(d);
                }
            }
            (GffValue::List(x), GffValue::List(y)) => {
                if x.len() != y.len() {
                    return Some(format!(
                        "{here}: list of {} vs {} structs",
                        x.len(),
                        y.len()
                    ));
                }
                for (j, (sx, sy)) in x.iter().zip(y).enumerate() {
                    if let Some(d) = struct_difference(sx, sy, &format!("{here}[{j}]")) {
                        return Some(d);
                    }
                }
            }
            (x, y) if x.type_id() != y.type_id() => {
                return Some(format!(
                    "{here}: type {} vs {}",
                    x.type_name(),
                    y.type_name()
                ));
            }
            (x, y) if x != y => {
                let show = |v: &GffValue| {
                    let s = format!("{v:?}");
                    if s.len() > 120 {
                        format!(
                            "{}...",
                            &s[..s.char_indices().nth(117).map_or(s.len(), |c| c.0)]
                        )
                    } else {
                        s
                    }
                };
                return Some(format!("{here}: {} vs {}", show(x), show(y)));
            }
            _ => {}
        }
    }
    if a.fields.len() != b.fields.len() {
        return Some(format!(
            "{path}: {} vs {} fields",
            a.fields.len(),
            b.fields.len()
        ));
    }
    None
}

/// How one section of a GFF is used (see [`section_usage`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionUsage {
    /// Section name.
    pub name: &'static str,
    /// Offset in the file.
    pub offset: usize,
    /// Size in bytes (struct/field/label sections: entries).
    pub size: usize,
    /// Bytes (or entries) reachable from the root struct.
    pub referenced: usize,
    /// Unreferenced byte ranges `(start, len)` relative to the section.
    pub unreferenced: Vec<(usize, usize)>,
    /// Blocks referenced from more than one place.
    pub shared: usize,
    /// Blocks that partly overlap another block.
    pub overlapping: usize,
}

/// Report which parts of each section a GFF actually references. A file is
/// rewritten byte-identically when nothing is shared or overlapping.
pub fn section_usage(data: &[u8]) -> Result<Vec<SectionUsage>> {
    let (_, u) = parse(data)?;
    let mut out = vec![
        counted("structs", u.offsets[0], &u.structs_seen),
        counted("fields", u.offsets[1], &u.fields_seen),
        SectionUsage {
            name: "labels",
            offset: u.offsets[2],
            size: u.label_count,
            referenced: u.labels_seen.iter().filter(|&&x| x).count(),
            unreferenced: Vec::new(),
            shared: 0,
            overlapping: 0,
        },
    ];
    for (i, name) in VAR_SECTIONS.iter().enumerate() {
        let mut r = u.ranges[i].clone();
        r.sort_unstable();
        let mut shared = 0;
        let mut overlapping = 0;
        let mut unref = Vec::new();
        let mut pos = 0usize;
        let mut referenced = 0usize;
        let mut last: Option<(usize, usize)> = None;
        for &(s, l) in &r {
            if last == Some((s, l)) {
                shared += 1;
                continue;
            }
            if s < pos {
                overlapping += 1;
            } else if s > pos {
                unref.push((pos, s - pos));
            }
            referenced += (s + l).saturating_sub(pos.max(s));
            pos = pos.max(s + l);
            last = Some((s, l));
        }
        if pos < u.sizes[i] {
            unref.push((pos, u.sizes[i] - pos));
        }
        out.push(SectionUsage {
            name,
            offset: u.offsets[3 + i],
            size: u.sizes[i],
            referenced,
            unreferenced: unref,
            shared,
            overlapping,
        });
    }
    Ok(out)
}

fn counted(name: &'static str, offset: usize, seen: &[bool]) -> SectionUsage {
    let mut unref = Vec::new();
    let mut i = 0;
    while i < seen.len() {
        if !seen[i] {
            let start = i;
            while i < seen.len() && !seen[i] {
                i += 1;
            }
            unref.push((start, i - start));
        } else {
            i += 1;
        }
    }
    SectionUsage {
        name,
        offset,
        size: seen.len(),
        referenced: seen.iter().filter(|&&x| x).count(),
        unreferenced: unref,
        shared: 0,
        overlapping: 0,
    }
}

/// What the parser saw, for layout capture and [`section_usage`].
struct Usage {
    offsets: [usize; 6],
    sizes: [usize; 3],
    label_count: usize,
    ranges: [Vec<(usize, usize)>; 3],
    structs_seen: Vec<bool>,
    fields_seen: Vec<bool>,
    labels_seen: Vec<bool>,
}

fn parse(data: &[u8]) -> Result<(Gff, Usage)> {
    let b = Bytes::new(data, FMT);
    b.slice(0, HEADER_LEN)?;
    let file_type = b.array::<4>(0)?;
    let version = b.array::<4>(4)?;
    if &version[..3] != b"V3." {
        return Err(Error::BadSignature {
            format: FMT,
            found: String::from_utf8_lossy(&data[..8]).into_owned(),
            expected: "<type>V3.2",
        });
    }
    let h: Vec<usize> = (0..12)
        .map(|i| b.u32(8 + 4 * i).map(us))
        .collect::<Result<_>>()?;
    let section = |off: usize, len: Option<usize>, what: &str| -> Result<&[u8]> {
        let len = len.ok_or_else(|| Error::invalid(FMT, format!("{what} size overflows")))?;
        b.slice(off, len).map_err(|_| {
            Error::invalid(
                FMT,
                format!(
                    "{what} section ({len} bytes at {off}) runs past the end of the file ({} bytes)",
                    data.len()
                ),
            )
        })
    };
    let structs = section(h[0], h[1].checked_mul(12), "struct")?;
    let fields = section(h[2], h[3].checked_mul(12), "field")?;
    let label_bytes = section(h[4], h[5].checked_mul(16), "label")?;
    let field_data = section(h[6], Some(h[7]), "field data")?;
    let field_indices = section(h[8], Some(h[9]), "field indices")?;
    let list_indices = section(h[10], Some(h[11]), "list indices")?;
    if h[1] == 0 {
        return Err(Error::invalid(
            FMT,
            "no structs (a GFF needs a root struct)",
        ));
    }
    let labels: Vec<[u8; 16]> = label_bytes
        .chunks_exact(16)
        .map(|c| {
            let mut a = [0u8; 16];
            a.copy_from_slice(c);
            a
        })
        .collect();
    let mut r = Parser {
        structs: Bytes::new(structs, FMT),
        fields: Bytes::new(fields, FMT),
        labels: &labels,
        field_data: Bytes::new(field_data, FMT),
        field_indices: Bytes::new(field_indices, FMT),
        list_indices: Bytes::new(list_indices, FMT),
        on_stack: vec![false; h[1]],
        depth: 0,
        ranges: Default::default(),
        structs_seen: vec![false; h[1]],
        fields_seen: vec![false; h[3]],
        labels_seen: vec![false; h[5]],
    };
    let root = r.read_struct(0)?;
    let secs = [field_data, field_indices, list_indices];
    let layout = [0, 1, 2].map(|i| capture_gaps(secs[i], &r.ranges[i]));
    let usage = Usage {
        offsets: [h[0], h[2], h[4], h[6], h[8], h[10]],
        sizes: [h[7], h[9], h[11]],
        label_count: h[5],
        ranges: r.ranges,
        structs_seen: r.structs_seen,
        fields_seen: r.fields_seen,
        labels_seen: r.labels_seen,
    };
    Ok((
        Gff {
            file_type,
            version,
            root,
            labels: Hint(labels),
            layout: Hint(layout),
        },
        usage,
    ))
}

impl Gff {
    /// An empty GFF with the given 4-character type (padded with spaces).
    pub fn new(file_type: &str) -> Self {
        let mut t = [b' '; 4];
        for (d, s) in t.iter_mut().zip(file_type.bytes()) {
            *d = s;
        }
        Gff {
            file_type: t,
            version: *b"V3.2",
            root: GffStruct::new(u32::MAX),
            labels: Hint(Vec::new()),
            layout: Hint(Default::default()),
        }
    }

    /// The content type as text, trailing spaces trimmed.
    pub fn file_type_str(&self) -> String {
        String::from_utf8_lossy(&self.file_type)
            .trim_end()
            .to_string()
    }

    /// Parse a GFF V3.x file.
    pub fn read(data: &[u8]) -> Result<Gff> {
        parse(data).map(|(g, _)| g)
    }

    /// Serialize. See the module docs for the layout rules.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Writer::write(self)
    }
}

struct Parser<'a> {
    structs: Bytes<'a>,
    fields: Bytes<'a>,
    labels: &'a [[u8; 16]],
    field_data: Bytes<'a>,
    field_indices: Bytes<'a>,
    list_indices: Bytes<'a>,
    on_stack: Vec<bool>,
    depth: usize,
    /// Referenced `(start, len)` blocks of field data, field indices, list indices.
    ranges: [Vec<(usize, usize)>; 3],
    structs_seen: Vec<bool>,
    fields_seen: Vec<bool>,
    labels_seen: Vec<bool>,
}

impl Parser<'_> {
    fn read_struct(&mut self, index: u32) -> Result<GffStruct> {
        let idx = us(index);
        if idx >= self.on_stack.len() {
            return Err(Error::invalid(
                FMT,
                format!(
                    "struct index {index} out of range ({} structs)",
                    self.on_stack.len()
                ),
            ));
        }
        if self.on_stack[idx] {
            return Err(Error::invalid(
                FMT,
                format!("struct {index} contains itself"),
            ));
        }
        if self.depth >= MAX_DEPTH {
            return Err(Error::invalid(FMT, "structs nested too deeply"));
        }
        let struct_id = self.structs.u32(idx * 12)?;
        let data = self.structs.u32(idx * 12 + 4)?;
        let count = us(self.structs.u32(idx * 12 + 8)?);
        let mut hint = StructHint {
            index: Some(index),
            ..Default::default()
        };
        let field_ids: Vec<u32> = match count {
            0 => {
                hint.empty_raw = Some(data);
                Vec::new()
            }
            1 => vec![data],
            n => {
                hint.indices = Some(data);
                let base = us(data);
                (0..n)
                    .map(|i| self.field_indices.u32(base + 4 * i))
                    .collect::<Result<_>>()
                    .map_err(|_| Error::invalid(FMT, format!("struct {index}: field index list at {data} ({n} entries) runs past its section")))?
            }
        };
        if count > 1 {
            self.ranges[1].push((us(data), 4 * count));
        }
        self.structs_seen[idx] = true;
        self.on_stack[idx] = true;
        self.depth += 1;
        let fields = field_ids
            .into_iter()
            .map(|f| self.read_field(f))
            .collect::<Result<Vec<_>>>();
        self.depth -= 1;
        self.on_stack[idx] = false;
        Ok(GffStruct {
            struct_id,
            fields: fields?,
            hint,
        })
    }

    fn read_field(&mut self, index: u32) -> Result<GffField> {
        use field_type::*;
        let base = us(index)
            .checked_mul(12)
            .filter(|&b| b + 12 <= self.fields.len())
            .ok_or_else(|| Error::invalid(FMT, format!("field index {index} out of range")))?;
        let type_id = self.fields.u32(base)?;
        let label_index = self.fields.u32(base + 4)?;
        let data = self.fields.u32(base + 8)?;
        let label_raw = self.labels.get(us(label_index)).ok_or_else(|| {
            Error::invalid(
                FMT,
                format!("field {index}: label index {label_index} out of range"),
            )
        })?;
        let label = text::decode(trim_nul(label_raw));
        self.fields_seen[us(index)] = true;
        self.labels_seen[us(label_index)] = true;
        let fd = self.field_data;
        let at = us(data);
        let ctx = |e: Error| Error::invalid(FMT, format!("field {label:?} (type {type_id}): {e}"));
        let mut hint = FieldHint {
            index: Some(index),
            label: Some(label_index),
            raw: Some(data),
            data: None,
        };
        if GffValue::is_complex(type_id) || type_id == LIST {
            hint.data = Some(data);
        }
        let value = match type_id {
            BYTE => GffValue::Byte(data as u8),
            CHAR => GffValue::Char(data as u8 as i8),
            WORD => GffValue::Word(data as u16),
            SHORT => GffValue::Short(data as u16 as i16),
            DWORD => GffValue::DWord(data),
            INT => GffValue::Int(data as i32),
            FLOAT => GffValue::Float(f32::from_bits(data)),
            DWORD64 => GffValue::DWord64(fd.u64(at).map_err(ctx)?),
            INT64 => GffValue::Int64(fd.u64(at).map_err(ctx)? as i64),
            DOUBLE => GffValue::Double(f64::from_bits(fd.u64(at).map_err(ctx)?)),
            CEXOSTRING => {
                let len = us(fd.u32(at).map_err(ctx)?);
                GffValue::String(text::decode(fd.slice(at + 4, len).map_err(ctx)?))
            }
            RESREF => {
                let len = usize::from(fd.u8(at).map_err(ctx)?);
                GffValue::ResRef(text::decode(fd.slice(at + 1, len).map_err(ctx)?))
            }
            CEXOLOCSTRING => GffValue::LocString(read_locstring(fd, at).map_err(ctx)?),
            VOID => {
                let len = us(fd.u32(at).map_err(ctx)?);
                GffValue::Void(fd.slice(at + 4, len).map_err(ctx)?.to_vec())
            }
            ORIENTATION => {
                let mut v = [0f32; 4];
                for (i, x) in v.iter_mut().enumerate() {
                    *x = fd.f32(at + 4 * i).map_err(ctx)?;
                }
                GffValue::Orientation(v)
            }
            VECTOR => {
                let mut v = [0f32; 3];
                for (i, x) in v.iter_mut().enumerate() {
                    *x = fd.f32(at + 4 * i).map_err(ctx)?;
                }
                GffValue::Vector(v)
            }
            STRUCT => GffValue::Struct(self.read_struct(data)?),
            LIST => {
                let li = self.list_indices;
                let count = us(li.u32(at).map_err(ctx)?);
                let ids = (0..count)
                    .map(|i| li.u32(at + 4 + 4 * i))
                    .collect::<Result<Vec<_>>>()
                    .map_err(ctx)?;
                self.ranges[2].push((at, 4 + 4 * count));
                let items = ids
                    .into_iter()
                    .map(|s| self.read_struct(s))
                    .collect::<Result<Vec<_>>>()?;
                GffValue::List(items)
            }
            other => GffValue::Unknown {
                type_id: other,
                data,
            },
        };
        if GffValue::is_complex(type_id) {
            self.ranges[0].push((at, complex_len(&value)));
        }
        Ok(GffField { label, value, hint })
    }
}

/// Bytes a complex value occupies in the field data, as this crate writes it.
fn complex_len(v: &GffValue) -> usize {
    match v {
        GffValue::DWord64(_) | GffValue::Int64(_) | GffValue::Double(_) => 8,
        GffValue::String(s) => 4 + s.chars().count(),
        GffValue::ResRef(s) => 1 + s.chars().count(),
        GffValue::LocString(l) => {
            12 + l
                .strings
                .iter()
                .map(|x| 8 + x.text.chars().count())
                .sum::<usize>()
        }
        GffValue::Void(b) => 4 + b.len(),
        GffValue::Orientation(_) => 16,
        GffValue::Vector(_) => 12,
        _ => 0,
    }
}

/// Appends blocks to a variable section, reproducing the source's
/// unreferenced bytes and sharing blocks the source shared.
struct SectionBuilder<'a> {
    out: Vec<u8>,
    gaps: &'a SectionGaps,
    emitted: HashMap<u32, (u32, Vec<u8>)>,
}

impl<'a> SectionBuilder<'a> {
    fn new(gaps: &'a SectionGaps) -> Self {
        SectionBuilder {
            out: gaps.lead.clone(),
            gaps,
            emitted: HashMap::new(),
        }
    }

    /// Add a block that sat at `hint` in the source; returns its offset.
    fn add(&mut self, hint: Option<u32>, block: Vec<u8>, what: &str) -> Result<u32> {
        if let Some(h) = hint {
            if let Some((off, bytes)) = self.emitted.get(&h) {
                if *bytes == block {
                    return Ok(*off);
                }
            }
        }
        let off = len_u32(self.out.len(), what)?;
        self.out.extend_from_slice(&block);
        if let Some(h) = hint {
            if !self.emitted.contains_key(&h) {
                if let Some(gap) = self.gaps.after.get(&h) {
                    self.out.extend_from_slice(gap);
                }
                self.emitted.insert(h, (off, block));
            }
        }
        Ok(off)
    }
}

fn read_locstring(fd: Bytes<'_>, at: usize) -> Result<LocString> {
    let _total = fd.u32(at)?;
    let strref = fd.u32(at + 4)?;
    let count = us(fd.u32(at + 8)?);
    let mut pos = at + 12;
    let mut strings = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let id = fd.u32(pos)?;
        let len = us(fd.u32(pos + 4)?);
        let text = text::decode(fd.slice(pos + 8, len)?);
        pos += 8 + len;
        strings.push(LocSubstring { id, text });
    }
    Ok(LocString { strref, strings })
}

struct SRec<'a> {
    s: &'a GffStruct,
    fields: Vec<usize>,
}

struct FRec<'a> {
    f: &'a GffField,
    children: Vec<usize>,
}

struct Writer<'a> {
    structs: Vec<SRec<'a>>,
    fields: Vec<FRec<'a>>,
}

fn sorted_by<K: Ord>(n: usize, mut k: impl FnMut(usize) -> K) -> Vec<usize> {
    let mut v: Vec<usize> = (0..n).collect();
    v.sort_by_cached_key(|&i| k(i));
    v
}

fn inverse(order: &[usize]) -> Vec<u32> {
    let mut inv = vec![0u32; order.len()];
    for (pos, &i) in order.iter().enumerate() {
        inv[i] = pos as u32;
    }
    inv
}

fn len_u32(len: usize, what: &str) -> Result<u32> {
    crate::binio::to_u32(len, FMT, what)
}

impl<'a> Writer<'a> {
    fn collect(&mut self, s: &'a GffStruct) -> usize {
        let id = self.structs.len();
        self.structs.push(SRec {
            s,
            fields: Vec::new(),
        });
        let mut fids = Vec::with_capacity(s.fields.len());
        for f in &s.fields {
            let fid = self.fields.len();
            self.fields.push(FRec {
                f,
                children: Vec::new(),
            });
            fids.push(fid);
            match &f.value {
                GffValue::Struct(c) => {
                    let c = self.collect(c);
                    self.fields[fid].children.push(c);
                }
                GffValue::List(items) => {
                    for c in items {
                        let c = self.collect(c);
                        self.fields[fid].children.push(c);
                    }
                }
                _ => {}
            }
        }
        self.structs[id].fields = fids;
        id
    }

    fn write(gff: &'a Gff) -> Result<Vec<u8>> {
        let mut w = Writer {
            structs: Vec::new(),
            fields: Vec::new(),
        };
        w.collect(&gff.root);
        let (ns, nf) = (w.structs.len(), w.fields.len());

        // Struct and field order: source position first, new nodes after, root first.
        let sorder = sorted_by(ns, |s| (s != 0, key(w.structs[s].s.hint.index), s));
        let sfinal = inverse(&sorder);
        let forder = sorted_by(nf, |f| (key(w.fields[f].f.hint.index), f));
        let ffinal = inverse(&forder);

        // Labels: reuse the source table, append new ones.
        let mut labels: Vec<[u8; 16]> = gff.labels.0.clone();
        let mut lookup: HashMap<Vec<u8>, u32> = HashMap::new();
        for (i, l) in labels.iter().enumerate() {
            lookup.entry(trim_nul(l).to_vec()).or_insert(i as u32);
        }
        let mut label_of = vec![0u32; nf];
        for &f in &forder {
            let field = w.fields[f].f;
            let enc = text::encode(&field.label, "GFF label")?;
            if enc.len() > 16 || enc.contains(&0) {
                return Err(Error::Encode {
                    what: "GFF label",
                    message: format!("{:?} must be at most 16 bytes with no NUL", field.label),
                });
            }
            let hinted = field.hint.label.filter(|&l| {
                labels
                    .get(us(l))
                    .is_some_and(|raw| trim_nul(raw) == enc.as_slice())
            });
            label_of[f] = match hinted.or_else(|| lookup.get(&enc).copied()) {
                Some(l) => l,
                None => {
                    let mut raw = [0u8; 16];
                    raw[..enc.len()].copy_from_slice(&enc);
                    let l = labels.len() as u32;
                    labels.push(raw);
                    lookup.insert(enc, l);
                    l
                }
            };
        }

        // Field data.
        let [fd_gaps, fi_gaps, li_gaps] = &gff.layout.0;
        let mut field_data = SectionBuilder::new(fd_gaps);
        let mut data_of = vec![0u32; nf];
        let complex: Vec<usize> = (0..nf)
            .filter(|&f| GffValue::is_complex(w.fields[f].f.value.type_id()))
            .collect();
        let mut corder = complex.clone();
        corder.sort_by_key(|&f| (key(w.fields[f].f.hint.data), f));
        for f in corder {
            let mut block = Vec::new();
            write_complex(&mut block, &w.fields[f].f.value)?;
            data_of[f] = field_data.add(w.fields[f].f.hint.data, block, "field data offset")?;
        }
        let field_data = field_data.out;

        // List indices.
        let mut list_indices = SectionBuilder::new(li_gaps);
        let mut lists: Vec<usize> = (0..nf)
            .filter(|&f| matches!(w.fields[f].f.value, GffValue::List(_)))
            .collect();
        lists.sort_by_key(|&f| (key(w.fields[f].f.hint.data), f));
        for f in lists {
            let children = &w.fields[f].children;
            let mut block = Vec::with_capacity(4 + 4 * children.len());
            block.put_u32(len_u32(children.len(), "list length")?);
            for &c in children {
                block.put_u32(sfinal[c]);
            }
            data_of[f] = list_indices.add(w.fields[f].f.hint.data, block, "list indices offset")?;
        }
        let list_indices = list_indices.out;

        // Field indices.
        let mut field_indices = SectionBuilder::new(fi_gaps);
        let mut indices_of = vec![0u32; ns];
        let mut multi: Vec<usize> = (0..ns).filter(|&s| w.structs[s].fields.len() > 1).collect();
        multi.sort_by_key(|&s| (key(w.structs[s].s.hint.indices), s));
        for s in multi {
            let mut block = Vec::with_capacity(4 * w.structs[s].fields.len());
            for &f in &w.structs[s].fields {
                block.put_u32(ffinal[f]);
            }
            indices_of[s] =
                field_indices.add(w.structs[s].s.hint.indices, block, "field indices offset")?;
        }
        let field_indices = field_indices.out;

        // Struct array.
        let mut struct_bytes = Vec::with_capacity(ns * 12);
        for &s in &sorder {
            let rec = &w.structs[s];
            struct_bytes.put_u32(rec.s.struct_id);
            let data = match rec.fields.len() {
                0 => rec.s.hint.empty_raw.unwrap_or(u32::MAX),
                1 => ffinal[rec.fields[0]],
                _ => indices_of[s],
            };
            struct_bytes.put_u32(data);
            struct_bytes.put_u32(len_u32(rec.fields.len(), "field count")?);
        }

        // Field array.
        let mut field_bytes = Vec::with_capacity(nf * 12);
        for &f in &forder {
            let rec = &w.fields[f];
            let v = &rec.f.value;
            let raw = rec.f.hint.raw;
            let narrow = |bits: u32, mask: u32| match raw {
                Some(r) if r & mask == bits & mask => r,
                _ => bits & mask,
            };
            let data = match v {
                GffValue::Byte(x) => narrow(u32::from(*x), 0xFF),
                GffValue::Char(x) => narrow(u32::from(*x as u8), 0xFF),
                GffValue::Word(x) => narrow(u32::from(*x), 0xFFFF),
                GffValue::Short(x) => narrow(u32::from(*x as u16), 0xFFFF),
                GffValue::DWord(x) => *x,
                GffValue::Int(x) => *x as u32,
                GffValue::Float(x) => x.to_bits(),
                GffValue::Struct(_) => sfinal[rec.children[0]],
                GffValue::Unknown { data, .. } => *data,
                _ => data_of[f],
            };
            field_bytes.put_u32(v.type_id());
            field_bytes.put_u32(label_of[f]);
            field_bytes.put_u32(data);
        }

        let label_bytes: Vec<u8> = labels.iter().flatten().copied().collect();
        let mut out = Vec::with_capacity(
            HEADER_LEN
                + struct_bytes.len()
                + field_bytes.len()
                + label_bytes.len()
                + field_data.len()
                + field_indices.len()
                + list_indices.len(),
        );
        out.extend_from_slice(&gff.file_type);
        out.extend_from_slice(&gff.version);
        let mut offset = HEADER_LEN;
        let sections: [(&[u8], usize); 6] = [
            (&struct_bytes, ns),
            (&field_bytes, nf),
            (&label_bytes, labels.len()),
            (&field_data, field_data.len()),
            (&field_indices, field_indices.len()),
            (&list_indices, list_indices.len()),
        ];
        for (bytes, count) in sections {
            out.put_u32(len_u32(offset, "section offset")?);
            out.put_u32(len_u32(count, "section count")?);
            offset += bytes.len();
        }
        for (bytes, _) in sections {
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }
}

fn write_complex(out: &mut Vec<u8>, v: &GffValue) -> Result<()> {
    match v {
        GffValue::DWord64(x) => out.put_u64(*x),
        GffValue::Int64(x) => out.put_u64(*x as u64),
        GffValue::Double(x) => out.put_u64(x.to_bits()),
        GffValue::String(s) => {
            let b = text::encode(s, "GFF CExoString")?;
            out.put_u32(len_u32(b.len(), "string length")?);
            out.extend_from_slice(&b);
        }
        GffValue::ResRef(s) => {
            let b = text::encode(s, "GFF ResRef")?;
            let len = u8::try_from(b.len()).map_err(|_| Error::Encode {
                what: "GFF ResRef",
                message: format!("{s:?} is longer than 255 bytes"),
            })?;
            out.put_u8(len);
            out.extend_from_slice(&b);
        }
        GffValue::LocString(l) => {
            let mut body = Vec::new();
            body.put_u32(l.strref);
            body.put_u32(len_u32(l.strings.len(), "substring count")?);
            for s in &l.strings {
                let b = text::encode(&s.text, "GFF CExoLocString")?;
                body.put_u32(s.id);
                body.put_u32(len_u32(b.len(), "substring length")?);
                body.extend_from_slice(&b);
            }
            out.put_u32(len_u32(body.len(), "locstring size")?);
            out.extend_from_slice(&body);
        }
        GffValue::Void(b) => {
            out.put_u32(len_u32(b.len(), "void length")?);
            out.extend_from_slice(b);
        }
        GffValue::Orientation(q) => q.iter().for_each(|x| out.put_f32(*x)),
        GffValue::Vector(q) => q.iter().for_each(|x| out.put_f32(*x)),
        _ => unreachable!("not a complex field type"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(label: &str, v: i32) -> GffField {
        GffField::new(label, GffValue::Int(v))
    }

    /// A tree that exercises every field type.
    pub(crate) fn sample() -> Gff {
        let mut g = Gff::new("GUI");
        let mut extent = GffStruct::new(0);
        extent.fields = vec![
            int("LEFT", 10),
            int("TOP", -20),
            int("WIDTH", 640),
            int("HEIGHT", 480),
        ];
        let mut child = GffStruct::new(0);
        child.fields = vec![
            GffField::new("TAG", GffValue::String("BTN_OK".into())),
            GffField::new("EXTENT", GffValue::Struct(extent.clone())),
        ];
        let mut lone = GffStruct::new(7);
        lone.fields = vec![GffField::new("ONLY", GffValue::Byte(1))];
        g.root.fields = vec![
            GffField::new("B", GffValue::Byte(200)),
            GffField::new("C", GffValue::Char(-5)),
            GffField::new("W", GffValue::Word(60000)),
            GffField::new("S", GffValue::Short(-30000)),
            GffField::new("DW", GffValue::DWord(0xDEADBEEF)),
            int("I", -123456),
            GffField::new("DW64", GffValue::DWord64(u64::MAX - 1)),
            GffField::new("I64", GffValue::Int64(i64::MIN + 3)),
            GffField::new("F", GffValue::Float(1.5)),
            GffField::new("D", GffValue::Double(-2.25)),
            GffField::new("STR", GffValue::String("caf\u{e9} \u{20ac}".into())),
            GffField::new("RES", GffValue::ResRef("fnt_d16x16".into())),
            GffField::new(
                "LOC",
                GffValue::LocString(LocString {
                    strref: 42,
                    strings: vec![
                        LocSubstring {
                            id: 0,
                            text: "Hello".into(),
                        },
                        LocSubstring {
                            id: 3,
                            text: "Ciao".into(),
                        },
                    ],
                }),
            ),
            GffField::new("VOID", GffValue::Void(vec![1, 2, 3, 0, 255])),
            GffField::new("ORI", GffValue::Orientation([1.0, 0.0, 0.5, -0.5])),
            GffField::new("VEC", GffValue::Vector([1.0, 2.0, 3.0])),
            GffField::new("EXTENT", GffValue::Struct(extent)),
            GffField::new("LONE", GffValue::Struct(lone)),
            GffField::new("EMPTY", GffValue::Struct(GffStruct::new(3))),
            GffField::new(
                "CONTROLS",
                GffValue::List(vec![child.clone(), child, GffStruct::new(9)]),
            ),
            GffField::new("NOTHING", GffValue::List(Vec::new())),
        ];
        g
    }

    #[test]
    fn write_read_write_is_stable() {
        let g = sample();
        let bytes = g.to_bytes().unwrap();
        let back = Gff::read(&bytes).unwrap();
        assert_eq!(back, g);
        assert_eq!(back.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn header_and_sections() {
        let bytes = sample().to_bytes().unwrap();
        assert_eq!(&bytes[..8], b"GUI V3.2");
        let b = Bytes::new(&bytes, FMT);
        assert_eq!(b.u32(8).unwrap(), 56);
        // Sections are contiguous and end at EOF.
        let last_off = b.u32(48).unwrap() as usize;
        let last_len = b.u32(52).unwrap() as usize;
        assert_eq!(last_off + last_len, bytes.len());
        // Root is struct 0 with id 0xFFFFFFFF.
        assert_eq!(b.u32(56).unwrap(), u32::MAX);
    }

    /// Build a file by hand in a *non*-canonical order (field array not in
    /// depth-first order, labels not in first-use order, garbage in a
    /// Byte's upper bits) and check it survives byte-exactly.
    #[test]
    fn foreign_layout_round_trips_exactly() {
        let mut f = Vec::new();
        f.extend_from_slice(b"GFF V3.2");
        f.resize(56, 0); // header offsets filled in below
                         // Struct 0 (root): two fields through the index list at 0.
                         // Struct 1: one field, field 2.
        let structs: [[u32; 3]; 2] = [[u32::MAX, 0, 2], [5, 2, 1]];
        // Field 0: String "B" at data 0. Field 1: Struct "A" -> struct 1.
        // Field 2: Byte "C" = 7 with garbage in the upper bytes.
        let fields: [[u32; 3]; 3] = [[10, 1, 0], [14, 0, 1], [0, 2, 0xAB00_0007]];
        // The label table is A, B, C although B is used first.
        let labels = [b"A", b"B", b"C"];
        let mut fd = Vec::new();
        fd.extend_from_slice(&3u32.to_le_bytes());
        fd.extend_from_slice(b"xyz");
        // The root lists field 1 before field 0.
        let fi: Vec<u8> = [1u32, 0].iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut body = Vec::new();
        let mut header = Vec::new();
        let mut off = 56u32;
        let sb: Vec<u8> = structs
            .iter()
            .flatten()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let fb: Vec<u8> = fields
            .iter()
            .flatten()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let lb: Vec<u8> = labels
            .iter()
            .flat_map(|l| {
                let mut a = [0u8; 16];
                a[..l.len()].copy_from_slice(&l[..]);
                a
            })
            .collect();
        for (bytes, count) in [
            (&sb, 2usize),
            (&fb, 3),
            (&lb, 3),
            (&fd, fd.len()),
            (&fi, fi.len()),
            (&Vec::new(), 0),
        ] {
            header.extend_from_slice(&off.to_le_bytes());
            header.extend_from_slice(&(count as u32).to_le_bytes());
            off += bytes.len() as u32;
            body.extend_from_slice(bytes);
        }
        f[8..56].copy_from_slice(&header);
        f.extend_from_slice(&body);

        let g = Gff::read(&f).unwrap();
        assert_eq!(g.root.get_str("B"), Some("xyz"));
        assert_eq!(g.root.path("A/C"), Some(&GffValue::Byte(7)));
        assert_eq!(
            g.root.fields[0].label, "A",
            "field order follows the struct's index list"
        );
        assert_eq!(g.to_bytes().unwrap(), f);

        // Editing the narrow value drops the stale upper bits.
        let mut g2 = g.clone();
        *g2.root.path_mut("A/C").unwrap() = GffValue::Byte(9);
        let out = g2.to_bytes().unwrap();
        let back = Gff::read(&out).unwrap();
        assert_eq!(back.root.path("A/C"), Some(&GffValue::Byte(9)));
    }

    #[test]
    fn edits_remain_valid() {
        let g = sample();
        let mut back = Gff::read(&g.to_bytes().unwrap()).unwrap();
        // Lengthen a string, add fields and a list element, remove a field.
        back.root.set(
            "STR",
            GffValue::String("a much longer string than before".into()),
        );
        back.root.set("NEWFIELD", GffValue::ResRef("abc".into()));
        back.root.remove("D");
        let list = back.root.get_list_mut("CONTROLS").unwrap();
        let mut extra = list[0].clone();
        extra.set("TAG", GffValue::String("CLONED".into()));
        list.insert(1, extra);
        back.root.set_int("I", 99).unwrap();
        let bytes = back.to_bytes().unwrap();
        let again = Gff::read(&bytes).unwrap();
        assert_eq!(again, back);
        assert_eq!(
            again
                .root
                .path("CONTROLS[1]/TAG")
                .and_then(GffValue::as_str),
            Some("CLONED")
        );
        assert_eq!(again.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn path_helpers() {
        let g = sample();
        assert_eq!(
            g.root
                .path("CONTROLS[1]/EXTENT/WIDTH")
                .and_then(GffValue::as_int),
            Some(640)
        );
        assert!(g.root.path("CONTROLS[3]/EXTENT").is_none());
        assert!(g.root.path("CONTROLS[x]/EXTENT").is_none());
        assert_eq!(g.root.path_struct("LONE").map(|s| s.struct_id), Some(7));
        let mut g = g;
        g.root
            .path_struct_mut("CONTROLS[0]/EXTENT")
            .unwrap()
            .set_int("LEFT", 5)
            .unwrap();
        assert_eq!(
            g.root.path("CONTROLS[0]/EXTENT/LEFT"),
            Some(&GffValue::Int(5))
        );
        // Keeps the stored integer type.
        g.root.set_int("B", 7).unwrap();
        assert_eq!(g.root.get("B"), Some(&GffValue::Byte(7)));
        assert!(g.root.set_int("B", 700).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Gff::read(b"").is_err());
        assert!(Gff::read(&[0u8; 56]).is_err());
        let mut bytes = sample().to_bytes().unwrap();
        bytes.truncate(bytes.len() - 3);
        assert!(Gff::read(&bytes).is_err());
        // Self-referencing struct.
        let mut g = Gff::new("GFF");
        g.root
            .fields
            .push(GffField::new("X", GffValue::Struct(GffStruct::new(0))));
        let mut bytes = g.to_bytes().unwrap();
        // Field 0's data (struct index 1) -> point at root (0).
        let field_off = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        bytes[field_off + 8..field_off + 12].copy_from_slice(&0u32.to_le_bytes());
        let err = Gff::read(&bytes).unwrap_err().to_string();
        assert!(err.contains("contains itself"), "{err}");
    }

    #[test]
    fn unreferenced_section_bytes_round_trip() {
        // Insert dead bytes at the end of each variable section (field data at
        // header slot 3, field indices 4, list indices 5) and fix the header.
        let mut bytes = sample().to_bytes().unwrap();
        let rd = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        for (slot, dead) in [(3usize, 6usize), (4, 8), (5, 12)] {
            let off_at = 8 + 8 * slot;
            let end = (rd(&bytes, off_at) + rd(&bytes, off_at + 4)) as usize;
            bytes.splice(end..end, std::iter::repeat_n(0xAB, dead));
            let count = rd(&bytes, off_at + 4) + dead as u32;
            bytes[off_at + 4..off_at + 8].copy_from_slice(&count.to_le_bytes());
            for later in slot + 1..6 {
                let at = 8 + 8 * later;
                let v = rd(&bytes, at) + dead as u32;
                bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        let g = Gff::read(&bytes).unwrap();
        assert_eq!(g, sample());
        assert_eq!(g.to_bytes().unwrap(), bytes);

        let usage = section_usage(&bytes).unwrap();
        let dead: Vec<usize> = usage[3..]
            .iter()
            .map(|u| u.unreferenced.iter().map(|r| r.1).sum())
            .collect();
        assert_eq!(dead, [6, 8, 12]);
        assert!(usage[..3].iter().all(|u| u.unreferenced.is_empty()));
    }

    #[test]
    fn first_difference_names_the_path() {
        let a = sample();
        assert_eq!(first_difference(&a, &a.clone()), None);
        let mut b = a.clone();
        b.root
            .path_struct_mut("CONTROLS[1]/EXTENT")
            .unwrap()
            .set_int("TOP", 7)
            .unwrap();
        let d = first_difference(&a, &b).unwrap();
        assert!(
            d.starts_with("(root)/CONTROLS[1]/EXTENT/TOP: Int(-20) vs Int(7)"),
            "{d}"
        );
        b.root.get_list_mut("CONTROLS").unwrap().pop();
        assert!(first_difference(&a, &b).unwrap().contains("list of 3 vs 2"));
    }

    #[test]
    fn shared_field_data_is_kept_shared() {
        // Two string fields pointing at one field-data block.
        let mut g = Gff::new("GFF");
        g.root.set("A", GffValue::String("same".into()));
        g.root.set("B", GffValue::String("same".into()));
        let mut bytes = g.to_bytes().unwrap();
        let rd = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let fields = rd(&bytes, 16) as usize;
        // Point field 1 at field 0's data and drop the second copy.
        let first = rd(&bytes, fields + 8);
        bytes[fields + 20..fields + 24].copy_from_slice(&first.to_le_bytes());
        let fd_off = rd(&bytes, 32) as usize;
        let fd_len = rd(&bytes, 36) as usize;
        bytes.drain(fd_off + fd_len / 2..fd_off + fd_len);
        let half = (fd_len / 2) as u32;
        bytes[36..40].copy_from_slice(&half.to_le_bytes());
        for at in [40usize, 48] {
            let v = rd(&bytes, at) - half;
            bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        let back = Gff::read(&bytes).unwrap();
        assert_eq!(back.root.get_str("B"), Some("same"));
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert_eq!(section_usage(&bytes).unwrap()[3].shared, 1);
    }

    #[test]
    fn label_limits() {
        let mut g = Gff::new("GFF");
        g.root.set("ABCDEFGHIJKLMNOPQ", GffValue::Byte(1));
        assert!(g.to_bytes().is_err());
    }
}
