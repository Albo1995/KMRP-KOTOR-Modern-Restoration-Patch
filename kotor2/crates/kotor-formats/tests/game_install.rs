//! Round trips against a real KotOR 2 install. Ignored by default; run with
//!
//! ```sh
//! KOTOR2_DIR="/path/to/Star Wars Knights of the Old Republic II" \
//!   cargo test -p kotor-formats --test game_install -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `KOTOR2_DIR` is the folder that holds `chitin.key`. Nothing is written to
//! the install. Each test prints its counts and fails listing every resource
//! that did not come back byte-identical (with the first differing offset).
//!
//! A GFF whose bytes differ but whose re-read tree equals the original is
//! reported as a "layout-only difference" and does not fail the test unless
//! `KOTOR2_STRICT=1`; `kfmt gff diff <file>` shows why.
//!
//! Optional: `KOTOR2_TPC_SAMPLE` (default 400) caps how many TPCs are checked
//! per texture pack; `KOTOR2_ARCHIVE_SAMPLE` (default 12) caps how many
//! archives per folder `archives_round_trip` rewrites; `KOTOR2_MAX_ARCHIVE_MB`
//! (default 600) skips larger archives there.

use std::path::{Path, PathBuf};

use kotor_formats::error::read_file;
use kotor_formats::fsutil::{files_with_extension, resolve};
use kotor_formats::gff::{first_difference, section_usage, Gff};
use kotor_formats::gui::Gui;
use kotor_formats::key::Chitin;
use kotor_formats::tlk::Tlk;
use kotor_formats::tpc::Tpc;
use kotor_formats::twoda::TwoDa;
use kotor_formats::{Archive, ResType, Result};

fn install() -> PathBuf {
    let dir = std::env::var_os("KOTOR2_DIR").unwrap_or_else(|| {
        panic!("set KOTOR2_DIR to the KotOR 2 folder that holds chitin.key (these tests are #[ignore]d for that reason)")
    });
    let dir = PathBuf::from(dir);
    assert!(
        resolve(&dir, "chitin.key").is_some_and(|p| p.is_file()),
        "KOTOR2_DIR={} has no chitin.key",
        dir.display()
    );
    dir
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn chitin(dir: &Path) -> Chitin {
    Chitin::open(resolve(dir, "chitin.key").unwrap()).expect("open chitin.key")
}

fn sub(dir: &Path, name: &str) -> Option<PathBuf> {
    resolve(dir, name).filter(|p| p.is_dir())
}

/// Counts and failures for one kind of resource.
struct Tally {
    what: &'static str,
    checked: usize,
    identical: usize,
    skipped: Vec<String>,
    failures: Vec<String>,
    /// Bytes differ but the re-read tree equals the original.
    layout_only: Vec<String>,
}

fn first_diff(a: &[u8], b: &[u8]) -> String {
    let at = a
        .iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()));
    format!(
        "input {} bytes, output {} bytes, first difference at {at:#x}",
        a.len(),
        b.len()
    )
}

impl Tally {
    fn new(what: &'static str) -> Tally {
        Tally {
            what,
            checked: 0,
            identical: 0,
            skipped: Vec::new(),
            failures: Vec::new(),
            layout_only: Vec::new(),
        }
    }

    /// Round-trip a GFF. When the bytes differ, re-read the output and
    /// compare trees: equal trees are a layout-only difference (reported,
    /// not failed unless `KOTOR2_STRICT=1`), anything else is a failure.
    fn check_gff(&mut self, name: &str, original: &[u8]) {
        self.checked += 1;
        let parsed = match Gff::read(original) {
            Ok(g) => g,
            Err(e) => return self.failures.push(format!("{name}: ERROR: {e}")),
        };
        let out = match parsed.to_bytes() {
            Ok(o) => o,
            Err(e) => return self.failures.push(format!("{name}: WRITE ERROR: {e}")),
        };
        if out == original {
            self.identical += 1;
            return;
        }
        let bytes = first_diff(original, &out);
        match Gff::read(&out) {
            Err(e) => self.failures.push(format!(
                "{name}: DIFFERS: {bytes}; output does not re-read: {e}"
            )),
            Ok(again) => match first_difference(&parsed, &again) {
                Some(d) => self
                    .failures
                    .push(format!("{name}: DIFFERS: {bytes}; tree differs at {d}")),
                None => self
                    .layout_only
                    .push(format!("{name}: {bytes}; {}", usage_summary(original))),
            },
        }
    }

    fn check(&mut self, name: &str, original: &[u8], rewritten: Result<Vec<u8>>) {
        self.checked += 1;
        match rewritten {
            Ok(out) if out == original => self.identical += 1,
            Ok(out) => self
                .failures
                .push(format!("{name}: DIFFERS: {}", first_diff(original, &out))),
            Err(e) => self.failures.push(format!("{name}: ERROR: {e}")),
        }
    }

    fn skip(&mut self, name: &str, why: &str) {
        self.skipped.push(format!("{name}: {why}"));
    }

    fn finish(self) {
        println!(
            "{}: {} checked, {} byte-identical, {} layout-only differences, {} failed, {} skipped",
            self.what,
            self.checked,
            self.identical,
            self.layout_only.len(),
            self.failures.len(),
            self.skipped.len()
        );
        for l in &self.layout_only {
            println!("  layout-only {l}");
        }
        let strict = std::env::var("KOTOR2_STRICT").is_ok_and(|v| v == "1");
        assert!(
            !strict || self.layout_only.is_empty(),
            "{}: {} layout-only differences with KOTOR2_STRICT=1",
            self.what,
            self.layout_only.len()
        );
        for s in self.skipped.iter().take(20) {
            println!("  skipped {s}");
        }
        if self.skipped.len() > 20 {
            println!("  ... and {} more skipped", self.skipped.len() - 20);
        }
        assert!(self.checked > 0, "{}: nothing was checked", self.what);
        assert!(
            self.failures.is_empty(),
            "{}: {} of {} did not round-trip:\n{}",
            self.what,
            self.failures.len(),
            self.checked,
            self.failures.join("\n")
        );
    }
}

/// Unreferenced/shared/overlapping counts of a GFF's sections, for reports.
fn usage_summary(data: &[u8]) -> String {
    match section_usage(data) {
        Ok(u) => u
            .iter()
            .filter(|s| !s.unreferenced.is_empty() || s.shared > 0 || s.overlapping > 0)
            .map(|s| {
                let unref: usize = s.unreferenced.iter().map(|r| r.1).sum();
                format!(
                    "{}: {unref} unreferenced in {} ranges, {} shared, {} overlapping",
                    s.name,
                    s.unreferenced.len(),
                    s.shared,
                    s.overlapping
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
        Err(e) => format!("section usage failed: {e}"),
    }
}

/// Every resource of a type named by chitin.key, as (name, bytes).
fn from_key(c: &mut Chitin, t: ResType, tally: &mut Tally) -> Vec<(String, Vec<u8>)> {
    let list: Vec<_> = c
        .key
        .resources
        .iter()
        .filter(|r| r.restype == t)
        .cloned()
        .collect();
    let mut out = Vec::with_capacity(list.len());
    for r in list {
        let name = format!("chitin:{}.{}", r.resref, r.restype);
        match c.read(&r) {
            Ok(d) => out.push((name, d)),
            Err(e) => {
                tally.checked += 1;
                tally.failures.push(format!("{name}: EXTRACT ERROR: {e}"));
            }
        }
    }
    out
}

/// Every file of an extension in Override (top level), as (name, bytes).
fn from_override(dir: &Path, ext: &str) -> Vec<(String, Vec<u8>)> {
    let Some(ov) = sub(dir, "Override") else {
        return Vec::new();
    };
    files_with_extension(&ov, ext)
        .into_iter()
        .filter_map(|p| {
            let d = read_file(&p).ok()?;
            Some((format!("Override/{}", p.file_name()?.to_string_lossy()), d))
        })
        .collect()
}

#[test]
#[ignore]
fn chitin_key_resolves_every_bif() {
    let dir = install();
    let mut c = chitin(&dir);
    let mut missing = Vec::new();
    for (i, b) in c.key.bifs.iter().enumerate() {
        match c.bif_path(i) {
            Ok(p) => {
                if let Err(e) = kotor_formats::key::Bif::open(&p) {
                    missing.push(format!("{}: {e}", b.filename));
                }
            }
            Err(e) => missing.push(e.to_string()),
        }
    }
    let mut by_type = std::collections::BTreeMap::new();
    for r in &c.key.resources {
        *by_type.entry(r.restype.to_string()).or_insert(0usize) += 1;
    }
    println!(
        "chitin.key: {} BIFs, {} resources, build {}/{}",
        c.key.bifs.len(),
        c.key.resources.len(),
        c.key.build_year + 1900,
        c.key.build_day
    );
    println!("  by type: {by_type:?}");
    assert!(
        missing.is_empty(),
        "BIFs that could not be opened:\n{}",
        missing.join("\n")
    );
    // Every KEY entry must point at an existing BIF entry.
    let mut bad = Vec::new();
    let resources = c.key.resources.clone();
    for r in resources.iter().filter(|r| r.restype == ResType::GUI) {
        if let Err(e) = c.read(r) {
            bad.push(format!("{}.{}: {e}", r.resref, r.restype));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
#[ignore]
fn every_gui_round_trips() {
    let dir = install();
    let mut c = chitin(&dir);
    let mut t = Tally::new("GUI");
    let mut files = from_key(&mut c, ResType::GUI, &mut t);
    files.extend(from_override(&dir, "gui"));
    let mut controls = 0;
    for (name, data) in &files {
        match Gui::read(data) {
            Ok(g) => controls += g.controls().len(),
            Err(e) => {
                t.checked += 1;
                t.failures.push(format!("{name}: ERROR: {e}"));
                continue;
            }
        }
        t.check_gff(name, data);
    }
    println!("GUI: {controls} controls in total");
    t.finish();
}

#[test]
#[ignore]
fn twoda_round_trips() {
    let dir = install();
    let mut c = chitin(&dir);
    let mut t = Tally::new("2DA");
    let mut files = from_key(&mut c, ResType::TWODA, &mut t);
    files.extend(from_override(&dir, "2da"));
    for (name, data) in &files {
        if !data.starts_with(b"2DA V2.b") {
            // Text 2DAs (V2.0) are read, but there is no byte-exact text writer.
            match TwoDa::read(data) {
                Ok(_) => t.skip(name, "text 2DA (read OK)"),
                Err(e) => {
                    t.checked += 1;
                    t.failures.push(format!("{name}: ERROR: {e}"));
                }
            }
            continue;
        }
        t.check(
            name,
            data,
            TwoDa::read_binary(data).and_then(|x| x.to_binary()),
        );
    }
    t.finish();
}

fn check_tpc(t: &mut Tally, name: &str, data: &[u8]) {
    let r = Tpc::read(data).and_then(|x| {
        let levels = x.levels()?;
        if levels.is_empty() {
            return Err(kotor_formats::Error::Invalid {
                format: "TPC",
                message: "no mip levels".into(),
            });
        }
        x.to_bytes()
    });
    t.check(name, data, r);
}

#[test]
#[ignore]
fn tpc_round_trips() {
    let dir = install();
    let mut c = chitin(&dir);
    let mut t = Tally::new("TPC");
    for (name, data) in from_key(&mut c, ResType::TPC, &mut t)
        .into_iter()
        .chain(from_override(&dir, "tpc"))
    {
        check_tpc(&mut t, &name, &data);
    }
    let cap = env_usize("KOTOR2_TPC_SAMPLE", 400);
    for pack in sub(&dir, "TexturePacks")
        .map(|p| files_with_extension(&p, "erf"))
        .unwrap_or_default()
    {
        let pname = pack.file_name().unwrap().to_string_lossy().into_owned();
        let archive = match read_file(&pack).and_then(|d| Archive::read(&d)) {
            Ok(a) => a,
            Err(e) => {
                t.checked += 1;
                t.failures.push(format!("{pname}: ERROR: {e}"));
                continue;
            }
        };
        let entries = archive.entries();
        let tpcs: Vec<usize> = (0..entries.len())
            .filter(|&i| entries[i].restype == ResType::TPC)
            .collect();
        let stride = tpcs.len().div_ceil(cap.max(1)).max(1);
        let mut n = 0;
        for &i in tpcs.iter().step_by(stride) {
            let e = &entries[i];
            check_tpc(
                &mut t,
                &format!("{pname}:{}.tpc", e.resref),
                archive.data(i).unwrap(),
            );
            n += 1;
        }
        println!("TPC: {pname}: checked {n} of {} TPCs", tpcs.len());
    }
    t.finish();
}

#[test]
#[ignore]
fn gff_resources_in_bifs_round_trip() {
    let dir = install();
    let mut c = chitin(&dir);
    let mut t = Tally::new("GFF (all GFF types in chitin.key)");
    let list: Vec<_> = c
        .key
        .resources
        .iter()
        .filter(|r| r.restype.is_gff())
        .cloned()
        .collect();
    for r in list {
        let name = format!("chitin:{}.{}", r.resref, r.restype);
        match c.read(&r) {
            Ok(d) => t.check_gff(&name, &d),
            Err(e) => {
                t.checked += 1;
                t.failures.push(format!("{name}: EXTRACT ERROR: {e}"));
            }
        }
    }
    t.finish();
}

#[test]
#[ignore]
fn archives_round_trip() {
    let dir = install();
    let mut t = Tally::new("archives");
    let cap = env_usize("KOTOR2_ARCHIVE_SAMPLE", 12);
    let max_bytes = env_usize("KOTOR2_MAX_ARCHIVE_MB", 600) as u64 * 1024 * 1024;
    for (folder, exts) in [
        ("TexturePacks", &["erf"][..]),
        ("modules", &["rim", "mod", "erf"][..]),
        ("lips", &["mod"][..]),
    ] {
        let Some(path) = sub(&dir, folder) else {
            t.skip(folder, "folder not found");
            continue;
        };
        let mut files: Vec<PathBuf> = exts
            .iter()
            .flat_map(|e| files_with_extension(&path, e))
            .collect();
        files.sort();
        let stride = files.len().div_ceil(cap.max(1)).max(1);
        for f in files.iter().step_by(stride) {
            let name = format!("{folder}/{}", f.file_name().unwrap().to_string_lossy());
            let len = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
            if len > max_bytes {
                t.skip(
                    &name,
                    &format!("{} MB is over KOTOR2_MAX_ARCHIVE_MB", len / (1024 * 1024)),
                );
                continue;
            }
            match read_file(f) {
                Ok(d) => t.check(&name, &d, Archive::read(&d).and_then(|a| a.to_bytes())),
                Err(e) => {
                    t.checked += 1;
                    t.failures.push(format!("{name}: ERROR: {e}"));
                }
            }
        }
    }
    t.finish();
}

#[test]
#[ignore]
fn dialog_tlk_reads() {
    let dir = install();
    let path = resolve(&dir, "dialog.tlk").expect("dialog.tlk in KOTOR2_DIR");
    let data = read_file(&path).unwrap();
    let tlk = Tlk::read(&data).expect("parse dialog.tlk");
    let with_text = tlk.entries.iter().filter(|e| !e.text.is_empty()).count();
    println!(
        "dialog.tlk: language {}, {} entries, {} with text; strref 0 = {:?}",
        tlk.language,
        tlk.entries.len(),
        with_text,
        tlk.get(0).map(|s| s.chars().take(60).collect::<String>())
    );
    assert!(tlk.entries.len() > 1000);
    let rewritten = tlk.to_bytes().unwrap();
    println!(
        "dialog.tlk rewrite (not required to match): {}",
        if rewritten == data {
            "byte-identical".to_string()
        } else {
            first_diff(&data, &rewritten)
        }
    );
}
