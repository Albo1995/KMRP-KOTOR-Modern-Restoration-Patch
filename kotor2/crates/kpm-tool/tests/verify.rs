//! `verify`, `find`, `disasm` and `pack` against synthetic PE32 images built
//! in code (no game files).

use std::path::PathBuf;
use std::process::Command;

use kpm_sdk::process::{hex_upper, sha256};
use kpm_tool::pe::Image;
use kpm_tool::sources::{self, HookSet};
use kpm_tool::testpe::{PeBuilder, DATA, RDATA, TEXT};
use kpm_tool::verify::{self, Options, Report, Status};
use kpm_tool::{find, pack};

/// .text layout (offsets):
/// 0x00 8B 44 24 08     mov eax,[esp+8]
/// 0x04 85 C0           test eax,eax
/// 0x06 55              push ebp
/// 0x10 E8 10 00 00 00  call rel32
/// 0x15 90 90 90
/// 0x20 8B 4E 10        mov ecx,[esi+0x10]
/// 0x23 85 C9           test ecx,ecx
/// 0x30 B8 78 56 34 12  mov eax,0x12345678
/// 0x35 C3              ret
/// 0x40 6A 00           push 0
/// 0x42 8B 4E 10        mov ecx,[esi+0x10]
fn builder() -> PeBuilder {
    let mut text = vec![0xCCu8; 0x200];
    let put = |t: &mut Vec<u8>, at: usize, b: &[u8]| t[at..at + b.len()].copy_from_slice(b);
    put(&mut text, 0x00, &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0, 0x55]);
    put(
        &mut text,
        0x10,
        &[0xE8, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90],
    );
    put(&mut text, 0x20, &[0x8B, 0x4E, 0x10, 0x85, 0xC9]);
    put(&mut text, 0x30, &[0xB8, 0x78, 0x56, 0x34, 0x12, 0xC3]);
    put(&mut text, 0x40, &[0x6A, 0x00, 0x8B, 0x4E, 0x10]);
    PeBuilder::new()
        .section(".text", text, TEXT)
        .section(".rdata", b"Hello, rdata!\0\0\0".repeat(4), RDATA)
        .section_with_vsize(".data", vec![0x11; 0x200], 0x1000, DATA)
}

const T: u64 = 0x0040_1000; // .text
const R: u64 = 0x0040_2000; // .rdata
const D: u64 = 0x0040_3000; // .data

fn exe() -> Vec<u8> {
    builder().build()
}

fn sha(bytes: &[u8]) -> String {
    hex_upper(&sha256(bytes))
}

fn header(target: &str) -> String {
    format!("[metadata]\ntarget_versions = [\"{target}\"]\n\n")
}

fn detour(address: u64, function: &str, bytes: &[u8], extra: &str) -> String {
    let list: Vec<_> = bytes.iter().map(|b| format!("0x{b:02X}")).collect();
    format!(
        "[[hooks]]\naddress = 0x{address:08X}\ntype = \"detour\"\nfunction = \"{function}\"\n\
         original_bytes = [{}]\n{extra}\n",
        list.join(", ")
    )
}

fn sets(label: &str, text: &str) -> Vec<HookSet> {
    sources::load_text(label, text).unwrap()
}

fn run(exe: Vec<u8>, sets: &[HookSet], opts: Options) -> Report {
    let report = verify::verify("synthetic.exe", exe, sets, &opts).unwrap();
    eprintln!("{}", report.render(true));
    report
}

fn messages(report: &Report) -> Vec<String> {
    report
        .sets
        .iter()
        .flat_map(|s| &s.hooks)
        .flat_map(|h| &h.findings)
        .filter(|f| f.status >= Status::Warn)
        .map(|f| f.text.clone())
        .collect()
}

#[test]
fn image_layout_is_as_the_tests_assume() {
    let b = builder();
    assert_eq!(b.va(0, 0), T);
    assert_eq!(b.va(1, 0), R);
    assert_eq!(b.va(2, 0), D);
    let image = Image::parse(exe()).unwrap();
    assert!(image.is_i386() && !image.is_dll());
    assert_eq!(image.image_base, 0x40_0000);
    assert_eq!(image.read_va(T, 2).unwrap(), &[0x8B, 0x44]);
    assert_eq!(image.offset_to_va(0x400), Some((T, Some(0))));
}

#[test]
fn passing_detour() {
    let bytes = exe();
    let text = header(&sha(&bytes))
        + &detour(
            T,
            "Hook",
            &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0],
            "[[hooks.parameters]]\nsource = \"ecx\"\ntype = \"pointer\"\n\n\
             [[hooks.parameters]]\nsource = \"esp+4\"\ntype = \"pointer\"\n",
        );
    let report = run(bytes, &sets("ok.hooks.toml", &text), Options::default());
    assert!(!report.failed());
    assert_eq!(report.counts(), (1, 0, 0, 0));
    assert!(report
        .render(false)
        .contains("mov eax, [esp+0x8] ; test eax, eax"));
}

#[test]
fn hash_mismatch_fails() {
    let text =
        header(&"AB".repeat(32)) + &detour(T, "Hook", &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0], "");
    let report = run(exe(), &sets("other.hooks.toml", &text), Options::default());
    assert!(report.failed());
    assert_eq!(report.sets[0].status(), Status::Fail);
    assert!(matches!(
        report.sets[0].hash,
        verify::HashCheck::Mismatch(_)
    ));
    // The hook itself still checks out, so the failure is the hash alone.
    assert_eq!(report.sets[0].hooks[0].status(), Status::Pass);
}

#[test]
fn byte_mismatch_fails() {
    let bytes = exe();
    let text = header(&sha(&bytes)) + &detour(T, "Hook", &[0x8B, 0x44, 0x24, 0x0C, 0x85, 0xC0], "");
    let report = run(bytes, &sets("bad.hooks.toml", &text), Options::default());
    assert!(report.failed());
    let m = messages(&report);
    assert!(
        m.iter()
            .any(|t| t.contains("expected [8B 44 24 0C 85 C0], found [8B 44 24 08 85 C0]")),
        "{m:?}"
    );
}

#[test]
fn split_instruction_fails() {
    let bytes = exe();
    // Five bytes cut test eax,eax (2 bytes at +4) in half.
    let text = header(&sha(&bytes)) + &detour(T, "Hook", &[0x8B, 0x44, 0x24, 0x08, 0x85], "");
    let report = run(bytes, &sets("split.hooks.toml", &text), Options::default());
    assert!(report.failed());
    let m = messages(&report);
    assert!(
        m.iter()
            .any(|t| t.contains("end inside the instruction at 0x00401004")
                && t.contains("use 4 or 6 bytes")),
        "{m:?}"
    );
}

#[test]
fn short_detour_fails() {
    let bytes = exe();
    let text = header(&sha(&bytes)) + &detour(T, "Hook", &[0x8B, 0x44, 0x24, 0x08], "");
    let report = run(bytes, &sets("short.hooks.toml", &text), Options::default());
    assert!(report.failed());
    assert!(messages(&report).iter().any(|t| t.contains("at least 5")));
}

#[test]
fn overlaps_across_files_fail() {
    let bytes = exe();
    let h = header(&sha(&bytes));
    let a = h.clone() + &detour(T, "A", &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0], "");
    let b = h + &detour(T + 4, "B", &[0x85, 0xC0, 0x55, 0xCC, 0xCC], "");
    let mut all = sets("a.hooks.toml", &a);
    all.extend(sets("b.hooks.toml", &b));
    let report = run(bytes, &all, Options::default());
    assert!(report.failed());
    assert_eq!(report.overlaps.len(), 1);
    assert_eq!(report.overlaps[0].status, Status::Fail);
    assert!(report.overlaps[0]
        .detail
        .contains("0x00401000+6 overlaps 0x00401004+5"));
}

#[test]
fn overlaps_in_one_file() {
    let bytes = exe();
    let h = header(&sha(&bytes));
    let same = h.clone()
        + &detour(T, "A", &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0], "")
        + &detour(T, "B", &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0], "");
    let report = run(
        bytes.clone(),
        &sets("same.hooks.toml", &same),
        Options::default(),
    );
    assert!(report.failed(), "identical selectors: a real overlap");
    let report = run(
        bytes.clone(),
        &sets("same.hooks.toml", &same),
        Options {
            allow_overlap_in_file: true,
        },
    );
    assert!(!report.failed());
    assert_eq!(report.overlaps[0].status, Status::Warn);
    // KMRP-style alternatives: the controller hook and its core stand-in.
    let alternatives = h
        + &detour(T, "A", &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0], "")
        + &detour(
            T,
            "B",
            &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0],
            "install = \"no-controller\"\n",
        );
    let report = run(
        bytes,
        &sets("alt.hooks.toml", &alternatives),
        Options::default(),
    );
    assert!(!report.failed());
    assert_eq!(report.overlaps[0].status, Status::Warn);
}

#[test]
fn relative_branch_in_stolen_bytes() {
    let bytes = exe();
    let call = [0xE8, 0x10, 0x00, 0x00, 0x00];
    let text = header(&sha(&bytes)) + &detour(T + 0x10, "Hook", &call, "");
    let report = run(
        bytes.clone(),
        &sets("rel.hooks.toml", &text),
        Options::default(),
    );
    assert!(report.failed());
    assert!(messages(&report)
        .iter()
        .any(|t| t.contains("relative branch")));
    let text =
        header(&sha(&bytes)) + &detour(T + 0x10, "Hook", &call, "skip_original_bytes = true\n");
    let report = run(bytes, &sets("rel.hooks.toml", &text), Options::default());
    assert!(!report.failed());
}

#[test]
fn consumed_exit_rules() {
    let bytes = exe();
    let h = header(&sha(&bytes));
    // mov eax,imm32 touches EAX before the consumed-exit test.
    let text = h.clone()
        + &detour(
            T + 0x30,
            "Hook",
            &[0xB8, 0x78, 0x56, 0x34, 0x12],
            &format!(
                "exclude_from_restore = [\"eax\"]\nconsumed_exit_address = 0x{:08X}\n",
                T + 0x35
            ),
        );
    let report = run(
        bytes.clone(),
        &sets("ce.hooks.toml", &text),
        Options::default(),
    );
    assert!(messages(&report).iter().any(|t| t.contains("touch EAX")));
    // push 0 moves ESP before the exit.
    let text = h.clone()
        + &detour(
            T + 0x40,
            "Hook",
            &[0x6A, 0x00, 0x8B, 0x4E, 0x10],
            &format!(
                "exclude_from_restore = [\"eax\"]\nconsumed_exit_address = 0x{:08X}\n",
                T + 0x35
            ),
        );
    let report = run(
        bytes.clone(),
        &sets("ce.hooks.toml", &text),
        Options::default(),
    );
    assert!(messages(&report).iter().any(|t| t.contains("move ESP")));
    // Clean: mov ecx,[esi+0x10] ; test ecx,ecx, eax excluded, exit in code.
    let text = h.clone()
        + &detour(
            T + 0x20,
            "Hook",
            &[0x8B, 0x4E, 0x10, 0x85, 0xC9],
            &format!(
                "exclude_from_restore = [\"eax\"]\nconsumed_exit_address = 0x{:08X}\n",
                T + 0x35
            ),
        );
    let report = run(
        bytes.clone(),
        &sets("ce.hooks.toml", &text),
        Options::default(),
    );
    assert!(!report.failed());
    // Without "eax" excluded KPM's manager refuses the hook.
    let text = h.clone()
        + &detour(
            T + 0x20,
            "Hook",
            &[0x8B, 0x4E, 0x10, 0x85, 0xC9],
            &format!("consumed_exit_address = 0x{:08X}\n", T + 0x35),
        );
    let report = run(
        bytes.clone(),
        &sets("ce.hooks.toml", &text),
        Options::default(),
    );
    assert!(messages(&report)
        .iter()
        .any(|t| t.contains("requires \"eax\"")));
    // A stolen read of an excluded register.
    let text = h + &detour(
        T + 0x20,
        "Hook",
        &[0x8B, 0x4E, 0x10, 0x85, 0xC9],
        "exclude_from_restore = [\"esi\"]\n",
    );
    let report = run(bytes, &sets("ex.hooks.toml", &text), Options::default());
    assert!(messages(&report).iter().any(|t| t.contains("read esi")));
}

#[test]
fn replace_and_static_and_data() {
    let bytes = exe();
    let h = header(&sha(&bytes));
    // A replace whose block jumps back relatively (escapes the block).
    let replace = format!(
        "[[hooks]]\naddress = 0x{T:08X}\ntype = \"replace\"\n\
         original_bytes = [0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0]\n\
         replacement_bytes = [0x85, 0xC0, 0xE9, 0x00, 0x10, 0x00, 0x00]\n\n"
    );
    let report = run(
        bytes.clone(),
        &sets("r.hooks.toml", &(h.clone() + &replace)),
        Options::default(),
    );
    assert!(messages(&report)
        .iter()
        .any(|t| t.contains("out of its block")));
    // Static, already applied; and a simple patch in .rdata; and the header.
    let applied = format!(
        "[[hooks]]\naddress = 0x{R:08X}\ntype = \"static\"\n\
         original_bytes = [0x00, 0x00]\nreplacement_bytes = [0x48, 0x65]\n\n\
         [[hooks]]\naddress = 0x{:08X}\ntype = \"simple\"\n\
         original_bytes = [0x6C, 0x6C]\nreplacement_bytes = [0x00, 0x00]\n\n\
         [[hooks]]\naddress = 0x00400000\ntype = \"static\"\n\
         original_bytes = [0x4D, 0x5A]\nreplacement_bytes = [0x4D, 0x5A]\n\n",
        R + 2
    );
    let report = run(
        bytes.clone(),
        &sets("s.hooks.toml", &(h.clone() + &applied)),
        Options::default(),
    );
    assert!(!report.failed());
    assert!(report.render(true).contains("already applied"));
    // The zero-filled tail of .data and an address outside every section.
    let outside = format!(
        "[[hooks]]\naddress = 0x{:08X}\ntype = \"simple\"\n\
         original_bytes = [0x00]\nreplacement_bytes = [0x01]\n\n\
         [[hooks]]\naddress = 0x00500000\ntype = \"simple\"\n\
         original_bytes = [0x00]\nreplacement_bytes = [0x01]\n\n",
        D + 0x400
    );
    let report = run(
        bytes,
        &sets("o.hooks.toml", &(h + &outside)),
        Options::default(),
    );
    let m = messages(&report);
    assert!(m.iter().any(|t| t.contains("zero-filled tail")), "{m:?}");
    assert!(
        m.iter().any(|t| t.contains("not inside any section")),
        "{m:?}"
    );
}

#[test]
fn steamstub_packed_skips_code_bytes() {
    let b = builder().section(".bind", vec![0; 0x200], TEXT);
    let bytes = b.build();
    let text = header(&sha(&bytes)) + &detour(T, "Hook", &[1, 2, 3, 4, 5], "");
    let report = run(bytes, &sets("p.hooks.toml", &text), Options::default());
    assert!(report.packed);
    assert!(!report.failed());
    assert_eq!(report.counts(), (0, 0, 0, 1));
}

#[test]
fn patch_config_layout() {
    let bytes = exe();
    let text = format!(
        "target_version_sha = \"{}\"\n[[patches]]\nid = \"x\"\ndll = \"patches/x.dll\"\n\
         [[patches.hooks]]\naddress = \"0x{T:08X}\"\nfunction = \"Hook\"\ntype = \"detour\"\n\
         original_bytes = [139, 68, 36, 8, 133, 192]\n",
        sha(&bytes)
    );
    let s = sets("patch_config.toml", &text);
    assert_eq!(s[0].label, "patch_config.toml#x");
    let report = run(bytes, &s, Options::default());
    assert!(!report.failed());
    // The string address is legal at run time, flagged for a .kpatch.
    assert_eq!(report.counts().1, 1);
}

#[test]
fn find_and_disasm() {
    let image = Image::parse(exe()).unwrap();
    let pattern = find::parse_pattern("8B 4E ?? 85").unwrap();
    let hits = find::find(&image, &pattern, Some(".text"), 10);
    assert_eq!(
        hits.iter().map(|h| h.va).collect::<Vec<_>>(),
        vec![T + 0x20]
    );
    let pattern = find::parse_pattern("8B 4E 10").unwrap();
    assert_eq!(find::find(&image, &pattern, None, 10).len(), 2);
    assert_eq!(find::find(&image, &pattern, None, 1).len(), 1);
    let text = find::disasm(&image, T + 0x10, 2).unwrap();
    assert!(text.contains("relative -> 0x00401025"), "{text}");
    let text = find::disasm(&image, T, 3).unwrap();
    assert!(
        text.contains("original_bytes = [0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0]"),
        "{text}"
    );
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kpm-tool-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const MANIFEST: &str = "[patch]\nid = \"synthetic\"\nname = \"Synthetic\"\nversion = \"0.1.0\"\n\
                        author = \"tests\"\ndescription = \"test patch\"\nrequires = []\nconflicts = []\n\n\
                        [patch.supported_versions]\n";

#[test]
fn pack_then_verify_the_kpatch() {
    let dir = scratch("pack");
    let bytes = exe();
    let target = sha(&bytes);
    std::fs::write(
        dir.join("manifest.toml"),
        format!("{MANIFEST}synthetic = \"{target}\"\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("synthetic.hooks.toml"),
        header(&target) + &detour(T, "Hook", &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0], ""),
    )
    .unwrap();
    std::fs::write(
        dir.join("other.hooks.toml"),
        header(&"AB".repeat(32)) + &detour(T, "Hook", &[1, 2, 3, 4, 5], ""),
    )
    .unwrap();
    let dll = PeBuilder::new()
        .section(".text", vec![0xC3; 0x40], TEXT)
        .dll(&["Hook", "Other"])
        .build();
    std::fs::write(dir.join("module.dll"), &dll).unwrap();
    let input = pack::PackInput {
        manifest: dir.join("manifest.toml"),
        hooks: vec![
            dir.join("synthetic.hooks.toml"),
            dir.join("other.hooks.toml"),
        ],
        dll: Some(dir.join("module.dll")),
        extra_binaries: vec![],
        out: dir.join("out/Synthetic.kpatch"),
    };
    let summary = pack::pack(&input).unwrap();
    assert_eq!(
        summary.entries,
        vec![
            "manifest.toml",
            "other.hooks.toml",
            "synthetic.hooks.toml",
            "binaries/windows_x86.dll"
        ]
    );
    // Deterministic.
    let again = pack::pack(&input).unwrap();
    assert_eq!(summary.sha256, again.sha256);

    let s = sources::load(&input.out).unwrap();
    assert_eq!(s.len(), 2);
    let report = run(bytes, &s, Options::default());
    assert!(
        !report.failed(),
        "the non-matching member is skipped, not failed"
    );
    assert_eq!(report.counts(), (1, 0, 0, 0));

    // The module must export every detour function.
    let mut missing = input.clone();
    std::fs::write(
        dir.join("module.dll"),
        PeBuilder::new()
            .section(".text", vec![0xC3; 0x40], TEXT)
            .dll(&["Other"])
            .build(),
    )
    .unwrap();
    missing.out = dir.join("missing.kpatch");
    let err = pack::pack(&missing).unwrap_err().to_string();
    assert!(err.contains("\"Hook\" is not exported"), "{err}");
    // A detour patch needs a module at all.
    let mut no_dll = input.clone();
    no_dll.dll = None;
    assert!(pack::pack(&no_dll)
        .unwrap_err()
        .to_string()
        .contains("need a module"));
    // An executable is not a module.
    std::fs::write(dir.join("module.dll"), exe()).unwrap();
    assert!(pack::pack(&input)
        .unwrap_err()
        .to_string()
        .contains("not a 32-bit i386 DLL"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_exit_codes() {
    let dir = scratch("cli");
    let bytes = exe();
    std::fs::write(dir.join("game.exe"), &bytes).unwrap();
    std::fs::write(
        dir.join("good.hooks.toml"),
        header(&sha(&bytes)) + &detour(T, "Hook", &[0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0], ""),
    )
    .unwrap();
    std::fs::write(
        dir.join("bad.hooks.toml"),
        header(&sha(&bytes)) + &detour(T, "Hook", &[0x8B, 0x44, 0x24, 0x08, 0x85], ""),
    )
    .unwrap();
    let tool = env!("CARGO_BIN_EXE_kpm-tool");
    let status = |args: &[&str]| {
        Command::new(tool)
            .args(args)
            .current_dir(&dir)
            .output()
            .unwrap()
            .status
            .code()
    };
    assert_eq!(
        status(&["verify", "--exe", "game.exe", "--hooks", "good.hooks.toml"]),
        Some(0)
    );
    assert_eq!(
        status(&["verify", "--exe", "game.exe", "--hooks", "bad.hooks.toml"]),
        Some(1)
    );
    assert_eq!(
        status(&[
            "verify",
            "--exe",
            "missing.exe",
            "--hooks",
            "good.hooks.toml"
        ]),
        Some(2)
    );
    assert_eq!(
        status(&["find", "--exe", "game.exe", "--pattern", "85 C9"]),
        Some(0)
    );
    assert_eq!(
        status(&["disasm", "--exe", "game.exe", "--va", "0x401000"]),
        Some(0)
    );
    assert_eq!(status(&["hash", "--exe", "game.exe"]), Some(0));
    std::fs::remove_dir_all(&dir).unwrap();
}
