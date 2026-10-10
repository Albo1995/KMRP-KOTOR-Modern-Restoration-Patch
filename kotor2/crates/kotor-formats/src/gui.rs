//! `.gui` layouts: a thin, typed view over a GFF with file type `GUI `.
//!
//! # Structure (from public documentation: PyKotor's GUI reader, xoreos, and
//! the field names KMRP's own `tools/*.py` edit)
//!
//! The root struct is itself a control (usually a panel) with `TAG`,
//! `EXTENT`, `BORDER` and a `CONTROLS` list. Each control may carry:
//!
//! | label | type | meaning |
//! | --- | --- | --- |
//! | `CONTROLTYPE` | Int | see [`ControlType`] |
//! | `TAG` | CExoString | name the engine looks the control up by |
//! | `ID` | Int | numeric id |
//! | `Obj_Parent`, `Obj_ParentID` | CExoString, Int | parent reference |
//! | `EXTENT` | Struct | `LEFT`, `TOP`, `WIDTH`, `HEIGHT` (Int) |
//! | `BORDER`, `HILIGHT`, `SELECTED`, `HILIGHTSELECTED` | Struct | `CORNER`, `EDGE`, `FILL` (ResRef), `FILLSTYLE`, `DIMENSION`, `INNEROFFSET` (Int), `COLOR` (Vector), `PULSING` (Byte) |
//! | `TEXT` | Struct | `TEXT` (CExoString), `STRREF` (DWord), `FONT` (ResRef), `ALIGNMENT` (DWord), `COLOR` (Vector), `PULSING` (Byte) |
//! | `MOVETO` | Struct | `UP`, `DOWN`, `LEFT`, `RIGHT` (Int): controller/keyboard navigation |
//! | `SCROLLBAR` | Struct | a nested scroll-bar control with `DIR` and `THUMB` |
//! | `PROTOITEM` | Struct | the list-box item template |
//! | `PADDING`, `LEFTSCROLLBAR`, `LOOPING` | Int / Byte | list-box options |
//! | `CONTROLS` | List | child controls (panels) |
//!
//! # KotOR 2 differences (from public documentation, not yet measured here)
//!
//! * `HILIGHTSELECTED` (a fourth border state for check boxes and toggle
//!   buttons) and `BORDER/INNEROFFSETY` are described as KotOR 2 additions.
//!   Both are read when present and never required. Confirm against a real
//!   layout with `kfmt gff dump`.
//!
//! Everything here reads fields leniently (a missing field is `None`) and
//! writes them preserving the stored GFF type of an existing field, so a
//! KotOR 1 and a KotOR 2 file both survive an edit with their field types
//! intact.

use crate::error::{Error, Result};
use crate::gff::{Gff, GffStruct, GffValue};

/// A rectangle in GUI coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rect {
    /// `LEFT`.
    pub left: i32,
    /// `TOP`.
    pub top: i32,
    /// `WIDTH`.
    pub width: i32,
    /// `HEIGHT`.
    pub height: i32,
}

/// `CONTROLTYPE` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlType {
    /// -1
    Invalid,
    /// 0
    Control,
    /// 2
    Panel,
    /// 4
    ProtoItem,
    /// 5
    Label,
    /// 6
    Button,
    /// 7
    CheckBox,
    /// 8
    Slider,
    /// 9
    ScrollBar,
    /// 10
    Progress,
    /// 11
    ListBox,
    /// Anything else.
    Other(i64),
}

impl ControlType {
    /// From the stored integer.
    pub fn from_raw(v: i64) -> ControlType {
        match v {
            -1 => ControlType::Invalid,
            0 => ControlType::Control,
            2 => ControlType::Panel,
            4 => ControlType::ProtoItem,
            5 => ControlType::Label,
            6 => ControlType::Button,
            7 => ControlType::CheckBox,
            8 => ControlType::Slider,
            9 => ControlType::ScrollBar,
            10 => ControlType::Progress,
            11 => ControlType::ListBox,
            o => ControlType::Other(o),
        }
    }
}

/// A `BORDER`-style struct.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Border {
    /// `CORNER` texture.
    pub corner: Option<String>,
    /// `EDGE` texture.
    pub edge: Option<String>,
    /// `FILL` texture.
    pub fill: Option<String>,
    /// `FILLSTYLE`.
    pub fill_style: Option<i64>,
    /// `DIMENSION` (edge thickness).
    pub dimension: Option<i64>,
    /// `INNEROFFSET`.
    pub inner_offset: Option<i64>,
    /// `INNEROFFSETY` (KotOR 2).
    pub inner_offset_y: Option<i64>,
    /// `COLOR`.
    pub color: Option<[f32; 3]>,
    /// `PULSING`.
    pub pulsing: Option<i64>,
}

/// The `TEXT` struct.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct TextInfo {
    /// Literal text.
    pub text: Option<String>,
    /// TLK reference.
    pub strref: Option<i64>,
    /// Font resref.
    pub font: Option<String>,
    /// Alignment code.
    pub alignment: Option<i64>,
    /// `COLOR`.
    pub color: Option<[f32; 3]>,
    /// `PULSING`.
    pub pulsing: Option<i64>,
}

/// The `MOVETO` struct (navigation targets by control id).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MoveTo {
    /// `UP`.
    pub up: Option<i64>,
    /// `DOWN`.
    pub down: Option<i64>,
    /// `LEFT`.
    pub left: Option<i64>,
    /// `RIGHT`.
    pub right: Option<i64>,
}

fn vector(s: &GffStruct, label: &str) -> Option<[f32; 3]> {
    match s.get(label)? {
        GffValue::Vector(v) => Some(*v),
        _ => None,
    }
}

/// Read a rectangle from a struct holding `LEFT`/`TOP`/`WIDTH`/`HEIGHT`.
pub fn read_rect(s: &GffStruct) -> Option<Rect> {
    let g = |l| s.get_int(l).and_then(|v| i32::try_from(v).ok());
    Some(Rect {
        left: g("LEFT")?,
        top: g("TOP")?,
        width: g("WIDTH")?,
        height: g("HEIGHT")?,
    })
}

/// Write a rectangle into a struct, keeping existing field types.
pub fn write_rect(s: &mut GffStruct, r: Rect) -> Result<()> {
    s.set_int("LEFT", r.left.into())?;
    s.set_int("TOP", r.top.into())?;
    s.set_int("WIDTH", r.width.into())?;
    s.set_int("HEIGHT", r.height.into())
}

/// Set a resref field, keeping a CExoString if that is what is stored.
fn set_resref(s: &mut GffStruct, label: &str, v: &str) {
    match s.get_mut(label) {
        Some(GffValue::String(x)) => *x = v.to_string(),
        Some(other) => *other = GffValue::ResRef(v.to_string()),
        None => {
            s.set(label, GffValue::ResRef(v.to_string()));
        }
    }
}

/// A read-only view of one control.
#[derive(Clone, Copy, Debug)]
pub struct Control<'a> {
    /// The underlying struct.
    pub s: &'a GffStruct,
}

impl<'a> Control<'a> {
    /// `TAG`.
    pub fn tag(&self) -> Option<&'a str> {
        self.s.get_str("TAG")
    }
    /// `CONTROLTYPE`.
    pub fn control_type(&self) -> Option<ControlType> {
        self.s.get_int("CONTROLTYPE").map(ControlType::from_raw)
    }
    /// `ID`.
    pub fn id(&self) -> Option<i64> {
        self.s.get_int("ID")
    }
    /// `EXTENT`.
    pub fn extent(&self) -> Option<Rect> {
        read_rect(self.s.get_struct("EXTENT")?)
    }
    /// A border-style struct by label (`BORDER`, `HILIGHT`, `SELECTED`, `HILIGHTSELECTED`).
    pub fn border_state(&self, label: &str) -> Option<Border> {
        let b = self.s.get_struct(label)?;
        Some(Border {
            corner: b.get_str("CORNER").map(str::to_string),
            edge: b.get_str("EDGE").map(str::to_string),
            fill: b.get_str("FILL").map(str::to_string),
            fill_style: b.get_int("FILLSTYLE"),
            dimension: b.get_int("DIMENSION"),
            inner_offset: b.get_int("INNEROFFSET"),
            inner_offset_y: b.get_int("INNEROFFSETY"),
            color: vector(b, "COLOR"),
            pulsing: b.get_int("PULSING"),
        })
    }
    /// `BORDER`.
    pub fn border(&self) -> Option<Border> {
        self.border_state("BORDER")
    }
    /// `TEXT`.
    pub fn text(&self) -> Option<TextInfo> {
        let t = self.s.get_struct("TEXT")?;
        Some(TextInfo {
            text: t.get_str("TEXT").map(str::to_string),
            strref: t.get_int("STRREF"),
            font: t.get_str("FONT").map(str::to_string),
            alignment: t.get_int("ALIGNMENT"),
            color: vector(t, "COLOR"),
            pulsing: t.get_int("PULSING"),
        })
    }
    /// `MOVETO`.
    pub fn moveto(&self) -> Option<MoveTo> {
        let m = self.s.get_struct("MOVETO")?;
        Some(MoveTo {
            up: m.get_int("UP"),
            down: m.get_int("DOWN"),
            left: m.get_int("LEFT"),
            right: m.get_int("RIGHT"),
        })
    }
    /// `SCROLLBAR`, as a control.
    pub fn scrollbar(&self) -> Option<Control<'a>> {
        self.s.get_struct("SCROLLBAR").map(|s| Control { s })
    }
    /// `PROTOITEM`, as a control.
    pub fn proto_item(&self) -> Option<Control<'a>> {
        self.s.get_struct("PROTOITEM").map(|s| Control { s })
    }
    /// Direct children (`CONTROLS`).
    pub fn children(&self) -> Vec<Control<'a>> {
        self.s
            .get_list("CONTROLS")
            .map(|l| l.iter().map(|s| Control { s }).collect())
            .unwrap_or_default()
    }
}

/// A mutable view of one control.
#[derive(Debug)]
pub struct ControlMut<'a> {
    /// The underlying struct.
    pub s: &'a mut GffStruct,
}

impl ControlMut<'_> {
    /// Read-only view.
    pub fn view(&self) -> Control<'_> {
        Control { s: self.s }
    }

    fn sub(&mut self, label: &str) -> &mut GffStruct {
        if self.s.get_struct(label).is_none() {
            self.s.set(label, GffValue::Struct(GffStruct::new(0)));
        }
        self.s.get_struct_mut(label).expect("just ensured")
    }

    /// Set `EXTENT` (created if missing).
    pub fn set_extent(&mut self, r: Rect) -> Result<()> {
        write_rect(self.sub("EXTENT"), r)
    }

    /// Move `EXTENT` by an offset.
    pub fn translate(&mut self, dx: i32, dy: i32) -> Result<()> {
        let r = self
            .view()
            .extent()
            .ok_or_else(|| Error::NotFound("control has no complete EXTENT".into()))?;
        self.set_extent(Rect {
            left: r.left + dx,
            top: r.top + dy,
            ..r
        })
    }

    /// Set `TEXT/FONT`.
    pub fn set_font(&mut self, font: &str) {
        set_resref(self.sub("TEXT"), "FONT", font);
    }

    /// Set `TEXT/TEXT`.
    pub fn set_text(&mut self, text: &str) {
        self.sub("TEXT")
            .set("TEXT", GffValue::String(text.to_string()));
    }

    /// Set a texture of a border-style struct: `which` is `CORNER`, `EDGE` or `FILL`.
    pub fn set_border_texture(&mut self, state: &str, which: &str, resref: &str) {
        set_resref(self.sub(state), which, resref);
    }

    /// Set an integer of a border-style struct (`DIMENSION`, `INNEROFFSET`, ...).
    pub fn set_border_int(&mut self, state: &str, field: &str, v: i64) -> Result<()> {
        self.sub(state).set_int(field, v)
    }

    /// Set `MOVETO` targets that are `Some`.
    pub fn set_moveto(&mut self, m: MoveTo) -> Result<()> {
        let s = self.sub("MOVETO");
        for (l, v) in [
            ("UP", m.up),
            ("DOWN", m.down),
            ("LEFT", m.left),
            ("RIGHT", m.right),
        ] {
            if let Some(v) = v {
                s.set_int(l, v)?;
            }
        }
        Ok(())
    }
}

/// A GUI layout.
#[derive(Clone, Debug, PartialEq)]
pub struct Gui {
    /// The underlying GFF.
    pub gff: Gff,
}

fn walk<'a>(s: &'a GffStruct, prefix: &str, out: &mut Vec<(String, Control<'a>)>) {
    if let Some(list) = s.get_list("CONTROLS") {
        for (i, c) in list.iter().enumerate() {
            let path = if prefix.is_empty() {
                format!("CONTROLS[{i}]")
            } else {
                format!("{prefix}/CONTROLS[{i}]")
            };
            out.push((path.clone(), Control { s: c }));
            walk(c, &path, out);
        }
    }
}

impl Gui {
    /// Parse; fails if the GFF type is not `GUI `.
    pub fn read(data: &[u8]) -> Result<Gui> {
        let gff = Gff::read(data)?;
        if &gff.file_type != b"GUI " {
            return Err(Error::invalid(
                "GUI",
                format!("GFF type is {:?}, not \"GUI \"", gff.file_type_str()),
            ));
        }
        Ok(Gui { gff })
    }

    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.gff.to_bytes()
    }

    /// The root control.
    pub fn root(&self) -> Control<'_> {
        Control { s: &self.gff.root }
    }

    /// The root control, mutably.
    pub fn root_mut(&mut self) -> ControlMut<'_> {
        ControlMut {
            s: &mut self.gff.root,
        }
    }

    /// Every control below the root, depth first, with its GFF path
    /// (`CONTROLS[2]/CONTROLS[0]`), usable with [`Gui::control_mut`].
    pub fn controls(&self) -> Vec<(String, Control<'_>)> {
        let mut out = Vec::new();
        walk(&self.gff.root, "", &mut out);
        out
    }

    /// The first control (depth first) with this tag; case-insensitive.
    pub fn find(&self, tag: &str) -> Option<Control<'_>> {
        self.controls()
            .into_iter()
            .map(|(_, c)| c)
            .find(|c| c.tag().is_some_and(|t| t.eq_ignore_ascii_case(tag)))
    }

    /// Path of the first control with this tag.
    pub fn path_of(&self, tag: &str) -> Option<String> {
        self.controls()
            .into_iter()
            .find(|(_, c)| c.tag().is_some_and(|t| t.eq_ignore_ascii_case(tag)))
            .map(|(p, _)| p)
    }

    /// A control by path, mutably (empty path = root).
    pub fn control_mut(&mut self, path: &str) -> Option<ControlMut<'_>> {
        self.gff
            .root
            .path_struct_mut(path)
            .map(|s| ControlMut { s })
    }

    /// The first control with this tag, mutably.
    pub fn find_mut(&mut self, tag: &str) -> Option<ControlMut<'_>> {
        let path = self.path_of(tag)?;
        self.control_mut(&path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gff::GffField;

    fn rect_struct(l: i32, t: i32, w: i32, h: i32) -> GffValue {
        let mut s = GffStruct::new(0);
        for (k, v) in [("LEFT", l), ("TOP", t), ("WIDTH", w), ("HEIGHT", h)] {
            s.fields.push(GffField::new(k, GffValue::Int(v)));
        }
        GffValue::Struct(s)
    }

    fn sample() -> Gui {
        let mut g = Gff::new("GUI");
        g.root.set("TAG", GffValue::String("mainmenu".into()));
        g.root.set("CONTROLTYPE", GffValue::Int(2));
        g.root.set("EXTENT", rect_struct(0, 0, 640, 480));
        let mut btn = GffStruct::new(0);
        btn.set("CONTROLTYPE", GffValue::Int(6));
        btn.set("TAG", GffValue::String("BTN_NEWGAME".into()));
        btn.set("ID", GffValue::Int(3));
        btn.set("EXTENT", rect_struct(100, 200, 180, 30));
        let mut text = GffStruct::new(0);
        text.set("STRREF", GffValue::DWord(42));
        text.set("FONT", GffValue::ResRef("fnt_d16x16b".into()));
        text.set("ALIGNMENT", GffValue::DWord(18));
        text.set("COLOR", GffValue::Vector([0.0, 0.66, 0.9]));
        btn.set("TEXT", GffValue::Struct(text));
        let mut border = GffStruct::new(0);
        border.set("CORNER", GffValue::ResRef("".into()));
        border.set("FILL", GffValue::ResRef("uibit_btn".into()));
        border.set("DIMENSION", GffValue::Int(0));
        btn.set("BORDER", GffValue::Struct(border));
        let mut panel = GffStruct::new(0);
        panel.set("CONTROLTYPE", GffValue::Int(2));
        panel.set("TAG", GffValue::String("PNL_SUB".into()));
        panel.set("EXTENT", rect_struct(0, 0, 10, 10));
        let mut inner = GffStruct::new(0);
        inner.set("TAG", GffValue::String("LBL_INNER".into()));
        inner.set("CONTROLTYPE", GffValue::Int(5));
        panel.set("CONTROLS", GffValue::List(vec![inner]));
        g.root.set("CONTROLS", GffValue::List(vec![btn, panel]));
        Gui { gff: g }
    }

    #[test]
    fn read_controls() {
        let bytes = sample().to_bytes().unwrap();
        let gui = Gui::read(&bytes).unwrap();
        assert_eq!(gui.root().tag(), Some("mainmenu"));
        let all = gui.controls();
        assert_eq!(all.len(), 3);
        assert_eq!(all[2].0, "CONTROLS[1]/CONTROLS[0]");
        let b = gui.find("btn_newgame").unwrap();
        assert_eq!(b.control_type(), Some(ControlType::Button));
        assert_eq!(
            b.extent(),
            Some(Rect {
                left: 100,
                top: 200,
                width: 180,
                height: 30
            })
        );
        let t = b.text().unwrap();
        assert_eq!(t.font.as_deref(), Some("fnt_d16x16b"));
        assert_eq!(t.strref, Some(42));
        assert_eq!(b.border().unwrap().fill.as_deref(), Some("uibit_btn"));
        assert!(b.moveto().is_none());
        assert_eq!(gui.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn edit_controls() {
        let mut gui = Gui::read(&sample().to_bytes().unwrap()).unwrap();
        {
            let mut b = gui.find_mut("BTN_NEWGAME").unwrap();
            b.translate(10, -5).unwrap();
            b.set_font("fnt_d24x24b");
            b.set_border_texture("HILIGHT", "FILL", "uibit_btn_h");
            b.set_moveto(MoveTo {
                down: Some(4),
                ..Default::default()
            })
            .unwrap();
        }
        gui.find_mut("LBL_INNER")
            .unwrap()
            .set_extent(Rect {
                left: 1,
                top: 2,
                width: 3,
                height: 4,
            })
            .unwrap();
        let back = Gui::read(&gui.to_bytes().unwrap()).unwrap();
        let b = back.find("BTN_NEWGAME").unwrap();
        assert_eq!(b.extent().unwrap().left, 110);
        assert_eq!(b.extent().unwrap().top, 195);
        assert_eq!(b.text().unwrap().font.as_deref(), Some("fnt_d24x24b"));
        assert_eq!(
            b.border_state("HILIGHT").unwrap().fill.as_deref(),
            Some("uibit_btn_h")
        );
        assert_eq!(b.moveto().unwrap().down, Some(4));
        assert_eq!(back.find("LBL_INNER").unwrap().extent().unwrap().height, 4);
        // Field types preserved: TEXT/ALIGNMENT stays DWord.
        assert!(matches!(
            b.s.path("TEXT/ALIGNMENT"),
            Some(GffValue::DWord(18))
        ));
    }

    #[test]
    fn rejects_non_gui() {
        let g = Gff::new("UTC");
        assert!(Gui::read(&g.to_bytes().unwrap()).is_err());
    }
}
