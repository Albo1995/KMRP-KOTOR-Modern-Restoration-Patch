//! End-to-end tests of the `kfmt` binary on synthetic files.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kotor_formats::erf::Erf;
use kotor_formats::gff::{Gff, GffField, GffStruct, GffValue};
use kotor_formats::tpc::Tpc;
use kotor_formats::twoda::TwoDa;
use kotor_formats::ResType;

fn kfmt(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kfmt"))
        .args(args)
        .output()
        .expect("run kfmt")
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("kfmt-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
    fn file(&self, name: &str, data: &[u8]) -> String {
        let p = self.0.join(name);
        std::fs::write(&p, data).unwrap();
        p.to_string_lossy().into_owned()
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn gui_bytes() -> Vec<u8> {
    let mut g = Gff::new("GUI");
    g.root.set("TAG", GffValue::String("testmenu".into()));
    let mut extent = GffStruct::new(0);
    for (k, v) in [("LEFT", 1), ("TOP", 2), ("WIDTH", 30), ("HEIGHT", 40)] {
        extent.fields.push(GffField::new(k, GffValue::Int(v)));
    }
    let mut btn = GffStruct::new(0);
    btn.set("CONTROLTYPE", GffValue::Int(6));
    btn.set("TAG", GffValue::String("BTN_OK".into()));
    btn.set("EXTENT", GffValue::Struct(extent));
    g.root.set("CONTROLS", GffValue::List(vec![btn]));
    g.to_bytes().unwrap()
}

#[test]
fn gff_dump_and_roundtrip() {
    let d = Dir::new("gff");
    let f = d.file("test.gui", &gui_bytes());
    let o = kfmt(&["gff", "dump", &f]);
    let (out, _) = text(&o);
    assert!(o.status.success());
    assert!(out.contains("\"BTN_OK\""), "{out}");
    assert!(out.contains("\"type\": \"List\""));

    let o = kfmt(&["gff", "roundtrip", &f, "-o", &d.path("out.gui")]);
    let (_, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert!(err.contains("byte-identical"));
    assert_eq!(std::fs::read(d.path("out.gui")).unwrap(), gui_bytes());

    // Refuses to overwrite.
    let o = kfmt(&["gff", "roundtrip", &f, "-o", &d.path("out.gui")]);
    assert_eq!(o.status.code(), Some(2));

    let o = kfmt(&["gui", "list", &f]);
    let (out, _) = text(&o);
    assert!(
        out.contains("CONTROLS[0]") && out.contains("Button") && out.contains("1,2 30x40"),
        "{out}"
    );
}

#[test]
fn roundtrip_reports_differences() {
    // A GFF with an unreferenced trailing byte cannot come back identical.
    let d = Dir::new("diff");
    let mut bytes = gui_bytes();
    bytes.push(0);
    let f = d.file("padded.gui", &bytes);
    let o = kfmt(&["roundtrip", &f]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("DIFFERS"));
}

#[test]
fn erf_list_extract_and_2da_tpc() {
    let d = Dir::new("erf");
    let mut t = TwoDa::new(&["label", "value"]);
    t.push_row(vec!["a".into(), "1".into()]);
    t.push_row(vec!["b".into(), "".into()]);
    let twoda = t.to_binary().unwrap();
    let tpc = Tpc::from_rgba(2, 2, vec![255; 16], "mipmap 0\r\n")
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut e = Erf::new("ERF");
    e.insert("table", ResType::TWODA, twoda.clone());
    e.insert("tex", ResType::TPC, tpc.clone());
    let f = d.file("pack.erf", &e.to_bytes().unwrap());

    let o = kfmt(&["erf", "list", &f]);
    let (out, _) = text(&o);
    assert!(
        out.contains("table.2da") && out.contains("tex.tpc"),
        "{out}"
    );

    let outdir = d.path("x");
    let o = kfmt(&["erf", "extract", &f, "-o", &outdir]);
    assert!(o.status.success(), "{}", text(&o).1);
    let extracted = Path::new(&outdir).join("table.2da");
    assert_eq!(std::fs::read(&extracted).unwrap(), twoda);

    let o = kfmt(&["2da", "dump", &extracted.to_string_lossy()]);
    let (out, _) = text(&o);
    assert!(out.contains("label") && out.contains("****"), "{out}");

    let tpc_path = Path::new(&outdir).join("tex.tpc");
    let tga = d.path("tex.tga");
    let o = kfmt(&["tpc", "info", &tpc_path.to_string_lossy(), "--tga", &tga]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert!(out.contains("rgba32") && out.contains("mipmap 0"), "{out}");
    assert!(std::fs::metadata(&tga).unwrap().len() > 18);

    for p in [
        f.as_str(),
        &tpc_path.to_string_lossy(),
        &extracted.to_string_lossy(),
    ] {
        let o = kfmt(&["roundtrip", p]);
        assert!(o.status.success(), "{p}: {}", text(&o).1);
    }
}

#[test]
fn clear_errors() {
    let o = kfmt(&["gff", "dump", "/nonexistent/file.gui"]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(2));
    assert!(err.contains("/nonexistent/file.gui"), "{err}");

    let d = Dir::new("err");
    let f = d.file("bad.gui", b"GUI V3.2 too short");
    let o = kfmt(&["gff", "dump", &f]);
    let (_, err) = text(&o);
    assert!(
        err.contains("bad.gui") && err.contains("truncated"),
        "{err}"
    );

    let o = kfmt(&["frobnicate"]);
    assert_eq!(o.status.code(), Some(2));
}
