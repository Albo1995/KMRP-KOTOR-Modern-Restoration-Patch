//! `kfmt`: inspect and round-trip KotOR resource files.

mod dump;

use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kotor_formats::error::read_file;
use kotor_formats::gff::{self, Gff};
use kotor_formats::gui::Gui;
use kotor_formats::key::Chitin;
use kotor_formats::restype::{parse_resource_name, ResType};
use kotor_formats::tga::Tga;
use kotor_formats::tlk::Tlk;
use kotor_formats::tpc::Tpc;
use kotor_formats::twoda::TwoDa;
use kotor_formats::{Archive, Error};

const USAGE: &str = "\
kfmt - inspect and round-trip KotOR (Odyssey engine) resource files

USAGE:
  kfmt gff dump <file>                       print a GFF (.gui, .utc, ...) as JSON
  kfmt gff roundtrip <file> [-o <out>|-o -]  read, rewrite, report byte-identical or the diff
  kfmt gff diff <a> <b>                      header sections, section usage and the first
                                             semantic difference (pass one file to diff it
                                             against its own rewrite)
  kfmt gui list <file.gui>                   list controls: path, tag, type, extent, font
  kfmt key list <chitin.key> [--type <ext>] [--bifs]
                                             list resources (or the BIF table)
  kfmt key extract <chitin.key> <resref.ext> [-o <out>] [--force]
                                             extract one resource from the BIFs
  kfmt erf list <archive>                    list an ERF/MOD/SAV/HAK/RIM
  kfmt erf extract <archive> [<resref.ext>...] [-o <dir>] [--force]
                                             extract all (or the named) resources
  kfmt 2da dump <file> [--text]              print a 2DA (binary or text) as a table
  kfmt tpc info <file> [--tga <out.tga>]     header, mip levels and TXI; optionally export mip 0
  kfmt roundtrip <file> [-o <out>|-o -]      like gff roundtrip, for any supported format
                                             (GFF, 2DA, ERF/MOD/SAV/HAK, RIM, TPC, TGA, TLK)

Exit status: 0 success (or byte-identical), 1 round trip differs, 2 error.
Existing output files are never overwritten without --force.";

/// A failure with a message for the user.
struct Fail(String);

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        Fail(e.to_string())
    }
}

impl From<io::Error> for Fail {
    fn from(e: io::Error) -> Self {
        Fail(format!("I/O error: {e}"))
    }
}

type Res<T = ()> = Result<T, Fail>;

fn fail<T>(msg: impl Into<String>) -> Res<T> {
    Err(Fail(msg.into()))
}

/// Parsed arguments: positionals plus `-o`/`--type`/`--tga` values and switches.
struct Args {
    pos: Vec<String>,
    out: Option<String>,
    typ: Option<String>,
    tga: Option<String>,
    bifs: bool,
    text: bool,
    force: bool,
}

fn parse_args(raw: Vec<String>) -> Res<Args> {
    let mut a = Args {
        pos: Vec::new(),
        out: None,
        typ: None,
        tga: None,
        bifs: false,
        text: false,
        force: false,
    };
    let mut it = raw.into_iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .ok_or_else(|| Fail(format!("{name} needs a value")))
        };
        match arg.as_str() {
            "-o" | "--out" => a.out = Some(value("-o")?),
            "--type" => a.typ = Some(value("--type")?),
            "--tga" => a.tga = Some(value("--tga")?),
            "--bifs" => a.bifs = true,
            "--text" => a.text = true,
            "--force" | "-f" => a.force = true,
            "-" => a.pos.push(arg),
            s if s.starts_with('-') => return fail(format!("unknown option {s}\n\n{USAGE}")),
            _ => a.pos.push(arg),
        }
    }
    Ok(a)
}

fn need<'a>(a: &'a Args, n: usize, what: &str) -> Res<&'a str> {
    a.pos
        .get(n)
        .map(String::as_str)
        .ok_or_else(|| Fail(format!("missing {what}\n\n{USAGE}")))
}

fn read(path: &str) -> Res<Vec<u8>> {
    Ok(read_file(path)?)
}

/// Prefix an error with the file it came from.
fn ctx<T>(path: &str, r: kotor_formats::Result<T>) -> Res<T> {
    r.map_err(|e| Fail(format!("{path}: {e}")))
}

fn write_new(path: &Path, data: &[u8], force: bool) -> Res {
    if path.exists() && !force {
        return fail(format!(
            "{} already exists (use --force to overwrite)",
            path.display()
        ));
    }
    std::fs::write(path, data).map_err(|e| Fail(format!("{}: {e}", path.display())))
}

/// Report a round trip on stderr; write the output where asked.
fn report_roundtrip(
    path: &str,
    input: &[u8],
    output: &[u8],
    out: Option<&str>,
    force: bool,
) -> Res<ExitCode> {
    match out {
        Some("-") => io::stdout().lock().write_all(output)?,
        Some(p) => write_new(Path::new(p), output, force)?,
        None => {}
    }
    if input == output {
        eprintln!("{path}: byte-identical ({} bytes)", input.len());
        return Ok(ExitCode::SUCCESS);
    }
    let first = input
        .iter()
        .zip(output)
        .position(|(a, b)| a != b)
        .unwrap_or(input.len().min(output.len()));
    let differing = input.iter().zip(output).filter(|(a, b)| a != b).count();
    eprintln!(
        "{path}: DIFFERS: input {} bytes, output {} bytes, first difference at offset {first} ({first:#x}), {differing} differing bytes over the common length",
        input.len(),
        output.len()
    );
    let lo = first.saturating_sub(8);
    let hex = |b: &[u8]| {
        b.iter()
            .skip(lo)
            .take(24)
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    eprintln!("  input  @{lo:#x}: {}", hex(input));
    eprintln!("  output @{lo:#x}: {}", hex(output));
    Ok(ExitCode::from(1))
}

/// Re-serialize any supported format, chosen by signature then extension.
fn rewrite(path: &str, data: &[u8]) -> Res<Vec<u8>> {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let head = data.get(..8).unwrap_or(data);
    let r = if head.len() == 8 && &head[4..7] == b"V3." && ext != "tlk" {
        Gff::read(data).and_then(|g| g.to_bytes())
    } else if data.starts_with(b"2DA V2.b") {
        TwoDa::read_binary(data).and_then(|t| t.to_binary())
    } else if kotor_formats::archive_kind(data).is_some() {
        Archive::read(data).and_then(|a| a.to_bytes())
    } else if data.starts_with(b"TLK V3.0") {
        Tlk::read(data).and_then(|t| t.to_bytes())
    } else if ext == "tpc" {
        Tpc::read(data).and_then(|t| t.to_bytes())
    } else if ext == "tga" {
        Tga::read(data).and_then(|t| t.to_bytes())
    } else if data.starts_with(b"2DA") {
        return fail(format!(
            "{path}: text 2DA (V2.0) has no byte-exact writer; use `kfmt 2da dump`"
        ));
    } else {
        return fail(format!(
            "{path}: unrecognized format (signature {:?}, extension {ext:?})",
            String::from_utf8_lossy(head)
        ));
    };
    ctx(path, r)
}

/// stdout that treats a closed pipe (`kfmt ... | head`) as success.
struct Out(BufWriter<io::StdoutLock<'static>>);

impl Out {
    fn new() -> Out {
        Out(BufWriter::new(io::stdout().lock()))
    }
    fn line(&mut self, s: &str) -> Res {
        writeln!(self.0, "{s}").map_err(Fail::from)
    }
    fn finish(mut self) -> Res {
        self.0.flush().map_err(Fail::from)
    }
}

fn cmd_gff(a: &Args) -> Res<ExitCode> {
    let sub = need(a, 1, "gff subcommand (dump | roundtrip | diff)")?;
    let path = need(a, 2, "file")?;
    let data = read(path)?;
    if sub == "diff" {
        return gff_diff(path, &data, a.pos.get(3).map(String::as_str));
    }
    match sub {
        "dump" => {
            let g = ctx(path, Gff::read(&data))?;
            let mut o = Out::new();
            o.line(dump::gff_json(&g).trim_end())?;
            o.finish()?;
            Ok(ExitCode::SUCCESS)
        }
        "roundtrip" => {
            let g = ctx(path, Gff::read(&data))?;
            let out = ctx(path, g.to_bytes())?;
            report_roundtrip(path, &data, &out, a.out.as_deref(), a.force)
        }
        s => fail(format!("unknown gff subcommand {s:?}\n\n{USAGE}")),
    }
}

fn print_layout(o: &mut Out, label: &str, data: &[u8]) -> Res {
    o.line(&format!(
        "{label}: {} bytes, type {:?}",
        data.len(),
        String::from_utf8_lossy(data.get(..8).unwrap_or(data))
    ))?;
    let usage = ctx(label, gff::section_usage(data))?;
    o.line("  section          offset      size  referenced  unreferenced  shared  overlapping")?;
    for u in &usage {
        let unref: usize = u.unreferenced.iter().map(|r| r.1).sum();
        o.line(&format!(
            "  {:<14} {:>8} {:>9} {:>11} {:>13} {:>7} {:>12}",
            u.name, u.offset, u.size, u.referenced, unref, u.shared, u.overlapping
        ))?;
        for (start, len) in u.unreferenced.iter().take(8) {
            o.line(&format!(
                "      unreferenced: {len} at +{start} ({:#x} in the file)",
                u.offset + start
            ))?;
        }
        if u.unreferenced.len() > 8 {
            o.line(&format!(
                "      ... {} more unreferenced ranges",
                u.unreferenced.len() - 8
            ))?;
        }
    }
    o.line("  (struct, field and label sizes are entry counts; the others are bytes)")
}

fn gff_diff(path_a: &str, a: &[u8], path_b: Option<&str>) -> Res<ExitCode> {
    let ga = ctx(path_a, Gff::read(a))?;
    let (label_b, b) = match path_b {
        Some(p) => (p.to_string(), read(p)?),
        None => (format!("{path_a} (rewritten)"), ctx(path_a, ga.to_bytes())?),
    };
    let gb = ctx(&label_b, Gff::read(&b))?;
    let mut o = Out::new();
    print_layout(&mut o, path_a, a)?;
    print_layout(&mut o, &label_b, &b)?;
    if a == b.as_slice() {
        o.line("bytes: identical")?;
    } else {
        let first = a
            .iter()
            .zip(&b)
            .position(|(x, y)| x != y)
            .unwrap_or(a.len().min(b.len()));
        o.line(&format!(
            "bytes: differ, first at offset {first} ({first:#x}), sizes {} vs {}",
            a.len(),
            b.len()
        ))?;
    }
    let code = match gff::first_difference(&ga, &gb) {
        None => {
            o.line("tree: equal (any byte difference is layout only)")?;
            ExitCode::SUCCESS
        }
        Some(d) => {
            o.line(&format!("tree: first difference: {d}"))?;
            ExitCode::from(1)
        }
    };
    o.finish()?;
    Ok(code)
}

fn cmd_gui(a: &Args) -> Res<ExitCode> {
    let sub = need(a, 1, "gui subcommand (list)")?;
    if sub != "list" {
        return fail(format!("unknown gui subcommand {sub:?}\n\n{USAGE}"));
    }
    let path = need(a, 2, "file")?;
    let gui = ctx(path, Gui::read(&read(path)?))?;
    let mut o = Out::new();
    let describe = |p: &str, c: kotor_formats::gui::Control<'_>| {
        let e = c
            .extent()
            .map(|r| format!("{},{} {}x{}", r.left, r.top, r.width, r.height))
            .unwrap_or_else(|| "-".into());
        let ty = c
            .control_type()
            .map(|t| format!("{t:?}"))
            .unwrap_or_else(|| "-".into());
        let font = c.text().and_then(|t| t.font).unwrap_or_default();
        format!(
            "{p:<28} {:<24} {ty:<10} {e:<22} {font}",
            c.tag().unwrap_or("-")
        )
    };
    o.line(&format!(
        "{:<28} {:<24} {:<10} {:<22} font",
        "path", "tag", "type", "extent"
    ))?;
    o.line(&describe("(root)", gui.root()))?;
    for (p, c) in gui.controls() {
        o.line(&describe(&p, c))?;
    }
    o.finish()?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_key(a: &Args) -> Res<ExitCode> {
    let sub = need(a, 1, "key subcommand (list | extract)")?;
    let key_path = need(a, 2, "chitin.key path")?;
    let mut chitin = Chitin::open(key_path)?;
    match sub {
        "list" => {
            let mut o = Out::new();
            if a.bifs {
                for (i, b) in chitin.key.bifs.iter().enumerate() {
                    let found = match chitin.bif_path(i) {
                        Ok(p) => p.display().to_string(),
                        Err(_) => "MISSING".into(),
                    };
                    o.line(&format!("{i:4} {:>10} {:<28} {found}", b.size, b.filename))?;
                }
                return o.finish().map(|_| ExitCode::SUCCESS);
            }
            let filter = match &a.typ {
                Some(t) => Some(
                    ResType::from_extension(t)
                        .ok_or_else(|| Fail(format!("unknown resource type {t:?}")))?,
                ),
                None => None,
            };
            let mut n = 0usize;
            for r in &chitin.key.resources {
                if filter.is_some_and(|f| f != r.restype) {
                    continue;
                }
                let bif = chitin
                    .key
                    .bifs
                    .get(r.bif_index())
                    .map(|b| b.filename.as_str())
                    .unwrap_or("?");
                o.line(&format!(
                    "{}.{}\t{bif}\t{}",
                    r.resref,
                    r.restype,
                    r.entry_index()
                ))?;
                n += 1;
            }
            o.finish()?;
            eprintln!("{n} resources");
            Ok(ExitCode::SUCCESS)
        }
        "extract" => {
            let name = need(a, 3, "resource name (resref.ext)")?;
            let (resref, restype) = parse_resource_name(name).ok_or_else(|| {
                Fail(format!("{name:?} is not resref.ext with a known extension"))
            })?;
            let data = chitin.extract(&resref, restype).map_err(|e| match e {
                Error::NotFound(m) => Fail(format!(
                    "{m} (it may live in Override, modules/ or TexturePacks/ instead)"
                )),
                other => Fail(other.to_string()),
            })?;
            let out = a
                .out
                .clone()
                .unwrap_or_else(|| format!("{}.{}", resref.to_ascii_lowercase(), restype));
            if out == "-" {
                io::stdout().lock().write_all(&data)?;
            } else {
                write_new(Path::new(&out), &data, a.force)?;
                eprintln!("wrote {out} ({} bytes)", data.len());
            }
            Ok(ExitCode::SUCCESS)
        }
        s => fail(format!("unknown key subcommand {s:?}\n\n{USAGE}")),
    }
}

fn cmd_erf(a: &Args) -> Res<ExitCode> {
    let sub = need(a, 1, "erf subcommand (list | extract)")?;
    let path = need(a, 2, "archive")?;
    let archive = ctx(path, Archive::read(&read(path)?))?;
    let entries = archive.entries();
    match sub {
        "list" => {
            let mut o = Out::new();
            for e in &entries {
                o.line(&format!("{}.{}\t{}", e.resref, e.restype, e.size))?;
            }
            o.finish()?;
            eprintln!("{} resources", entries.len());
            Ok(ExitCode::SUCCESS)
        }
        "extract" => {
            let dir = PathBuf::from(a.out.clone().unwrap_or_else(|| ".".into()));
            std::fs::create_dir_all(&dir).map_err(|e| Fail(format!("{}: {e}", dir.display())))?;
            let wanted: Vec<(String, ResType)> = a.pos[3..]
                .iter()
                .map(|n| {
                    parse_resource_name(n).ok_or_else(|| {
                        Fail(format!("{n:?} is not resref.ext with a known extension"))
                    })
                })
                .collect::<Res<_>>()?;
            let mut written = 0;
            for (i, e) in entries.iter().enumerate() {
                if !wanted.is_empty()
                    && !wanted
                        .iter()
                        .any(|(r, t)| *t == e.restype && r.eq_ignore_ascii_case(&e.resref))
                {
                    continue;
                }
                let name = format!("{}.{}", e.resref, e.restype);
                if name.contains(['/', '\\']) || e.resref.is_empty() || e.resref.starts_with('.') {
                    eprintln!("skipping unsafe name {name:?}");
                    continue;
                }
                write_new(
                    &dir.join(&name),
                    archive.data(i).unwrap_or_default(),
                    a.force,
                )?;
                written += 1;
            }
            for (r, t) in &wanted {
                if archive.get(r, *t).is_none() {
                    eprintln!("not in archive: {r}.{t}");
                }
            }
            eprintln!("extracted {written} resources to {}", dir.display());
            Ok(ExitCode::SUCCESS)
        }
        s => fail(format!("unknown erf subcommand {s:?}\n\n{USAGE}")),
    }
}

fn cmd_2da(a: &Args) -> Res<ExitCode> {
    let sub = need(a, 1, "2da subcommand (dump)")?;
    if sub != "dump" {
        return fail(format!("unknown 2da subcommand {sub:?}\n\n{USAGE}"));
    }
    let path = need(a, 2, "file")?;
    let t = ctx(path, TwoDa::read(&read(path)?))?;
    let mut o = Out::new();
    if a.text {
        o.0.write_all(t.to_text().as_bytes())?;
        o.finish()?;
        return Ok(ExitCode::SUCCESS);
    }
    let shown = |s: &str| {
        if s.is_empty() {
            "****".to_string()
        } else {
            s.to_string()
        }
    };
    let mut widths: Vec<usize> = std::iter::once(
        t.row_labels
            .iter()
            .map(|l| l.chars().count())
            .max()
            .unwrap_or(0),
    )
    .chain(t.columns.iter().map(|c| c.chars().count()))
    .collect();
    for row in &t.rows {
        for (i, c) in row.iter().enumerate() {
            widths[i + 1] = widths[i + 1].max(shown(c).chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        cells
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    o.line(&line(
        std::iter::once(String::new())
            .chain(t.columns.iter().cloned())
            .collect(),
    ))?;
    for (label, row) in t.row_labels.iter().zip(&t.rows) {
        o.line(&line(
            std::iter::once(label.clone())
                .chain(row.iter().map(|c| shown(c)))
                .collect(),
        ))?;
    }
    o.finish()?;
    eprintln!("{} rows x {} columns", t.rows.len(), t.columns.len());
    Ok(ExitCode::SUCCESS)
}

fn cmd_tpc(a: &Args) -> Res<ExitCode> {
    let sub = need(a, 1, "tpc subcommand (info)")?;
    if sub != "info" {
        return fail(format!("unknown tpc subcommand {sub:?}\n\n{USAGE}"));
    }
    let path = need(a, 2, "file")?;
    let data = read(path)?;
    let t = ctx(path, Tpc::read(&data))?;
    let format = ctx(path, t.format())?;
    let levels = ctx(path, t.levels())?;
    let mut o = Out::new();
    o.line(&format!("file:        {path} ({} bytes)", data.len()))?;
    o.line(&format!("size:        {}x{}", t.width, t.height))?;
    o.line(&format!("encoding:    {} ({})", t.encoding, format.name()))?;
    o.line(&format!("data size:   {}", t.data_size))?;
    o.line(&format!("alpha test:  {}", t.alpha_test))?;
    o.line(&format!(
        "mip count:   {} in header, {} per layer present",
        t.mip_count,
        levels.iter().filter(|l| l.layer == 0).count()
    ))?;
    o.line(&format!("kind:        {:?}", t.kind()))?;
    o.line(&format!("image data:  {} bytes", t.data.len()))?;
    let used: usize = levels.iter().map(|l| l.size).sum();
    if used != t.data.len() {
        o.line(&format!(
            "unaccounted: {} bytes of image data not covered by the levels",
            t.data.len() - used
        ))?;
    }
    for l in &levels {
        o.line(&format!(
            "  layer {} level {:2}: {:4}x{:<4} {:8} bytes at {}",
            l.layer, l.level, l.width, l.height, l.size, l.offset
        ))?;
    }
    o.line(&format!("txi:         {} bytes", t.txi.len()))?;
    for line in t.txi_text().lines() {
        o.line(&format!("  | {line}"))?;
    }
    o.finish()?;
    if let Some(out) = &a.tga {
        let l = levels
            .first()
            .ok_or_else(|| Fail(format!("{path}: no image levels")))?;
        let stored = ctx(path, t.decode_rgba(l))?;
        // TPC rows are bottom-up; Tga::pixels is top-down.
        let row = l.width * 4;
        let top_down: Vec<u8> = stored.chunks(row).rev().flatten().copied().collect();
        let (w, h) = (
            u16::try_from(l.width).map_err(|_| Fail("too wide for TGA".into()))?,
            u16::try_from(l.height).map_err(|_| Fail("too tall for TGA".into()))?,
        );
        let tga = Tga::new_rgba(w, h, top_down, false)?;
        write_new(Path::new(out), &tga.to_bytes()?, a.force)?;
        eprintln!("wrote {out} ({}x{}, layer 0 level 0)", l.width, l.height);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_roundtrip(a: &Args) -> Res<ExitCode> {
    let path = need(a, 1, "file")?;
    let data = read(path)?;
    let out = rewrite(path, &data)?;
    report_roundtrip(path, &data, &out, a.out.as_deref(), a.force)
}

fn run(raw: Vec<String>) -> Res<ExitCode> {
    let a = parse_args(raw)?;
    let Some(cmd) = a.pos.first().map(String::as_str) else {
        println!("{USAGE}");
        return Ok(ExitCode::from(2));
    };
    match cmd {
        "gff" => cmd_gff(&a),
        "gui" => cmd_gui(&a),
        "key" => cmd_key(&a),
        "erf" | "rim" | "mod" => cmd_erf(&a),
        "2da" => cmd_2da(&a),
        "tpc" => cmd_tpc(&a),
        "roundtrip" => cmd_roundtrip(&a),
        "help" | "-h" | "--help" => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        s => fail(format!("unknown command {s:?}\n\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match run(raw) {
        Ok(code) => code,
        Err(Fail(msg)) if msg.contains("Broken pipe") => ExitCode::SUCCESS,
        Err(Fail(msg)) => {
            eprintln!("kfmt: error: {msg}");
            ExitCode::from(2)
        }
    }
}
