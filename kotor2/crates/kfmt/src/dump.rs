//! JSON rendering of a GFF tree.
//!
//! Each struct is `{"struct_id": n, "fields": [...]}` and each field
//! `{"label": ..., "type": ..., "value": ...}`, so the output keeps field
//! order, duplicate labels and the stored type of every value.

use std::fmt::Write;

use kotor_formats::gff::{Gff, GffStruct, GffValue};

pub fn json_string(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 || (0x7F..0xA0).contains(&(c as u32)) => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn float(v: f64) -> String {
    if v.is_finite() {
        format!("{v:?}")
    } else {
        json_string(&v.to_string())
    }
}

fn floats(v: &[f32]) -> String {
    let items: Vec<String> = v.iter().map(|x| float(f64::from(*x))).collect();
    format!("[{}]", items.join(", "))
}

fn pad(depth: usize) -> String {
    "  ".repeat(depth)
}

fn value(v: &GffValue, depth: usize, out: &mut String) {
    match v {
        GffValue::Byte(x) => out.push_str(&x.to_string()),
        GffValue::Char(x) => out.push_str(&x.to_string()),
        GffValue::Word(x) => out.push_str(&x.to_string()),
        GffValue::Short(x) => out.push_str(&x.to_string()),
        GffValue::DWord(x) => out.push_str(&x.to_string()),
        GffValue::Int(x) => out.push_str(&x.to_string()),
        GffValue::DWord64(x) => out.push_str(&x.to_string()),
        GffValue::Int64(x) => out.push_str(&x.to_string()),
        GffValue::Float(x) => out.push_str(&float(f64::from(*x))),
        GffValue::Double(x) => out.push_str(&float(*x)),
        GffValue::String(s) | GffValue::ResRef(s) => out.push_str(&json_string(s)),
        GffValue::LocString(l) => {
            let strref = if l.strref == u32::MAX {
                "-1".to_string()
            } else {
                l.strref.to_string()
            };
            let subs: Vec<String> = l
                .strings
                .iter()
                .map(|s| format!("{{\"id\": {}, \"text\": {}}}", s.id, json_string(&s.text)))
                .collect();
            let _ = write!(
                out,
                "{{\"strref\": {strref}, \"strings\": [{}]}}",
                subs.join(", ")
            );
        }
        GffValue::Void(b) => {
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
            out.push_str(&json_string(&hex));
        }
        GffValue::Struct(s) => strukt(s, depth, out),
        GffValue::List(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, s) in items.iter().enumerate() {
                out.push_str(&pad(depth + 1));
                strukt(s, depth + 1, out);
                out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(depth));
            out.push(']');
        }
        GffValue::Orientation(q) => out.push_str(&floats(q)),
        GffValue::Vector(q) => out.push_str(&floats(q)),
        GffValue::Unknown { type_id, data } => {
            let _ = write!(out, "{{\"type_id\": {type_id}, \"raw\": {data}}}");
        }
    }
}

fn strukt(s: &GffStruct, depth: usize, out: &mut String) {
    let _ = write!(
        out,
        "{{\"struct_id\": {}, \"fields\": [",
        s.struct_id as i32
    );
    if s.fields.is_empty() {
        out.push_str("]}");
        return;
    }
    out.push('\n');
    for (i, f) in s.fields.iter().enumerate() {
        let _ = write!(
            out,
            "{}{{\"label\": {}, \"type\": \"{}\", \"value\": ",
            pad(depth + 1),
            json_string(&f.label),
            f.value.type_name()
        );
        value(&f.value, depth + 1, out);
        out.push('}');
        out.push_str(if i + 1 < s.fields.len() { ",\n" } else { "\n" });
    }
    out.push_str(&pad(depth));
    out.push_str("]}");
}

pub fn gff_json(g: &Gff) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\n  \"file_type\": {},\n  \"version\": {},\n  \"root\": ",
        json_string(&String::from_utf8_lossy(&g.file_type)),
        json_string(&String::from_utf8_lossy(&g.version))
    );
    strukt(&g.root, 1, &mut out);
    out.push_str("\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotor_formats::gff::GffField;

    #[test]
    fn renders() {
        let mut g = Gff::new("GUI");
        g.root
            .fields
            .push(GffField::new("TAG", GffValue::String("a\"b\n".into())));
        g.root
            .fields
            .push(GffField::new("L", GffValue::List(vec![GffStruct::new(0)])));
        g.root
            .fields
            .push(GffField::new("F", GffValue::Float(f32::NAN)));
        let s = gff_json(&g);
        assert!(s.contains(r#""value": "a\"b\n""#), "{s}");
        assert!(s.contains(r#""struct_id": -1"#));
        assert!(s.contains(r#""value": "NaN""#));
    }
}
