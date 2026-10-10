//! `kpm-tool verify`: every check that can be made offline of a set of hooks
//! against an executable, before KPM's runtime makes them in memory.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use anyhow::Result;
use kpm_sdk::model::{Hook, HookType, Severity};
use kpm_sdk::process::{hex_upper, sha256};

use crate::known;
use crate::pe::Image;
use crate::sources::{HookSet, SourceKind};
use crate::x86::{self, Boundary};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Pass,
    Skip,
    Warn,
    Fail,
}

impl Status {
    pub fn tag(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Skip => "SKIP",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Report overlapping hooks inside one file as warnings, not failures
    /// (for KMRP-style source tables that hold alternative hooks for one site).
    pub allow_overlap_in_file: bool,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub status: Status,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct HookResult {
    pub label: String,
    pub address: u64,
    pub kind: String,
    pub len: usize,
    pub summary: String,
    pub findings: Vec<Finding>,
}

impl HookResult {
    pub fn status(&self) -> Status {
        let worst = self
            .findings
            .iter()
            .map(|f| f.status)
            .filter(|s| *s != Status::Skip)
            .max()
            .unwrap_or(Status::Pass);
        if worst == Status::Pass && self.findings.iter().any(|f| f.status == Status::Skip) {
            Status::Skip
        } else {
            worst
        }
    }

    fn add(&mut self, status: Status, text: impl Into<String>) {
        self.findings.push(Finding {
            status,
            text: text.into(),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashCheck {
    Match,
    NoTargets,
    /// A plain hooks file / config whose targets do not list this exe.
    Mismatch(Vec<String>),
    /// A `.kpatch` member KPM would not pick for this exe.
    NotSelected(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct SetResult {
    pub label: String,
    pub hash: HashCheck,
    pub set_findings: Vec<Finding>,
    pub hooks: Vec<HookResult>,
}

impl SetResult {
    pub fn status(&self) -> Status {
        let hash = match self.hash {
            HashCheck::Mismatch(_) => Status::Fail,
            HashCheck::NotSelected(_) => return Status::Skip,
            _ => Status::Pass,
        };
        self.hooks
            .iter()
            .map(HookResult::status)
            .chain(self.set_findings.iter().map(|f| f.status))
            .chain([hash])
            .max()
            .unwrap_or(Status::Pass)
    }
}

#[derive(Debug, Clone)]
pub struct Overlap {
    pub status: Status,
    pub a: String,
    pub b: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub exe_label: String,
    pub exe_len: usize,
    pub exe_sha256: String,
    pub image_summary: String,
    pub packed: bool,
    pub origin_findings: Vec<Finding>,
    pub sets: Vec<SetResult>,
    pub overlaps: Vec<Overlap>,
}

impl Report {
    pub fn failed(&self) -> bool {
        self.sets.iter().any(|s| s.status() == Status::Fail)
            || self.overlaps.iter().any(|o| o.status == Status::Fail)
            || self
                .origin_findings
                .iter()
                .any(|f| f.status == Status::Fail)
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut c = (0, 0, 0, 0);
        for s in &self.sets {
            if matches!(s.hash, HashCheck::NotSelected(_)) {
                continue;
            }
            for h in &s.hooks {
                match h.status() {
                    Status::Pass => c.0 += 1,
                    Status::Warn => c.1 += 1,
                    Status::Fail => c.2 += 1,
                    Status::Skip => c.3 += 1,
                }
            }
        }
        c
    }

    pub fn render(&self, verbose: bool) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "exe:     {}", self.exe_label);
        let _ = writeln!(o, "size:    {} bytes", self.exe_len);
        let _ = writeln!(o, "sha256:  {}", self.exe_sha256);
        match known::lookup(&self.exe_sha256) {
            Some(k) => {
                let _ = writeln!(o, "build:   {} ({})", k.key, k.description);
            }
            None => {
                let _ = writeln!(o, "build:   not one KPM's address databases list");
            }
        }
        let _ = writeln!(o, "image:   {}", self.image_summary);
        if self.packed {
            let _ = writeln!(
                o,
                "         SteamStub-packed (.bind): on-disk code is encrypted; byte checks skipped"
            );
        }
        for f in &self.origin_findings {
            let _ = writeln!(o, "{}  {}", f.status.tag(), f.text);
        }
        for s in &self.sets {
            let _ = writeln!(o, "\n== {} ({} hooks)", s.label, s.hooks.len());
            let hash = match &s.hash {
                HashCheck::Match => "target_versions: MATCH".to_string(),
                HashCheck::NoTargets => {
                    "target_versions: none listed (applies to every build)".to_string()
                }
                HashCheck::Mismatch(t) => format!(
                    "FAIL  target_versions does not list this executable ({} listed: {})",
                    t.len(),
                    t.iter().map(|x| short(x)).collect::<Vec<_>>().join(", ")
                ),
                HashCheck::NotSelected(t) => format!(
                    "SKIP  KPM would not use this file for this executable (targets {})",
                    t.iter().map(|x| short(x)).collect::<Vec<_>>().join(", ")
                ),
            };
            let _ = writeln!(o, "   {hash}");
            if matches!(s.hash, HashCheck::NotSelected(_)) && !verbose {
                continue;
            }
            for f in &s.set_findings {
                let _ = writeln!(o, "   {}  {}", f.status.tag(), f.text);
            }
            for h in &s.hooks {
                let status = h.status();
                let _ = writeln!(
                    o,
                    "   {}  {:#010X}  {:<7}  {:<40} {:>3} bytes  {}",
                    status.tag(),
                    h.address,
                    h.kind,
                    h.label,
                    h.len,
                    h.summary
                );
                for f in &h.findings {
                    if verbose || f.status != Status::Pass {
                        let _ = writeln!(
                            o,
                            "         - {}: {}",
                            f.status.tag().to_lowercase(),
                            f.text
                        );
                    }
                }
            }
        }
        if !self.overlaps.is_empty() {
            let _ = writeln!(o, "\n== overlapping hooks");
            for ov in &self.overlaps {
                let _ = writeln!(
                    o,
                    "   {}  {}  <->  {}  ({})",
                    ov.status.tag(),
                    ov.a,
                    ov.b,
                    ov.detail
                );
            }
        }
        let (pass, warn, fail, skip) = self.counts();
        let _ = writeln!(
            o,
            "\n{} hooks checked: {pass} passed, {warn} with warnings, {fail} failed, {skip} skipped; {} overlap(s)",
            pass + warn + fail + skip,
            self.overlaps.len()
        );
        let _ = writeln!(o, "RESULT: {}", if self.failed() { "FAIL" } else { "PASS" });
        o
    }
}

fn short(sha: &str) -> String {
    match known::lookup(sha) {
        Some(k) => format!("{}...({})", &sha[..sha.len().min(8)], k.key),
        None => format!("{}...", &sha[..sha.len().min(8)]),
    }
}

/// Register families for the stolen-byte rules.
fn family(reg: &str) -> String {
    match reg.to_ascii_lowercase().as_str() {
        "ax" | "al" | "ah" => "eax".into(),
        "bx" | "bl" | "bh" => "ebx".into(),
        "cx" | "cl" | "ch" => "ecx".into(),
        "dx" | "dl" | "dh" => "edx".into(),
        "si" => "esi".into(),
        "di" => "edi".into(),
        "bp" => "ebp".into(),
        "sp" => "esp".into(),
        other => other.into(),
    }
}

fn check_hook(image: &Image, packed: bool, hook: &Hook) -> HookResult {
    let original = &hook.original_bytes.bytes;
    let kind = hook.kind.effective();
    let mut r = HookResult {
        label: hook
            .function
            .clone()
            .filter(|f| !f.trim().is_empty())
            .unwrap_or_else(|| format!("<{}>", hook.kind)),
        address: hook.address(),
        kind: hook.kind.name().to_string(),
        len: original.len(),
        summary: String::new(),
        findings: Vec::new(),
    };

    for issue in hook.issues() {
        let status = match issue.severity {
            Severity::Error => Status::Fail,
            Severity::Warning => Status::Warn,
        };
        r.add(status, issue.message);
    }
    if original.is_empty() {
        return r;
    }

    // Where it is.
    let mapped = match image.map(hook.address(), original.len()) {
        Ok(m) => m,
        Err(e) => {
            r.add(Status::Fail, format!("cannot map the site: {e}"));
            return r;
        }
    };
    let section = mapped.section.map(|i| &image.sections[i]);
    let section_name = image.section_name(mapped.section).to_string();
    let executable = section.is_some_and(|s| s.is_executable());
    if matches!(kind, HookType::Detour | HookType::Replace) && !executable {
        r.add(
            Status::Fail,
            format!("a {kind} hook must be in code, but {section_name} is not executable"),
        );
    }
    r.add(
        Status::Pass,
        format!("file offset {:#X} in {section_name}", mapped.offset),
    );

    if let Some(exit) = hook
        .consumed_exit_address
        .map(|a| a.value)
        .filter(|v| *v != 0)
    {
        match image.section_of_va(exit) {
            Some(i) if image.sections[i].is_executable() => r.add(
                Status::Pass,
                format!(
                    "consumed exit {exit:#010X} is in {}",
                    image.sections[i].name
                ),
            ),
            Some(i) => r.add(
                Status::Fail,
                format!(
                    "consumed_exit_address {exit:#010X} is in non-executable {}",
                    image.sections[i].name
                ),
            ),
            None => r.add(
                Status::Fail,
                format!("consumed_exit_address {exit:#010X} is outside the image's sections"),
            ),
        }
    }

    if packed && section.is_some_and(|s| s.is_executable()) {
        r.add(
            Status::Skip,
            "on-disk code is SteamStub-encrypted; KPM verifies these bytes in memory",
        );
        return r;
    }

    // What is there.
    let actual = &image.data[mapped.offset..mapped.offset + original.len()];
    let replacement = hook.replacement();
    if actual == original.as_slice() {
        r.add(Status::Pass, "original_bytes match the executable");
    } else if kind == HookType::Static && actual == replacement {
        r.add(
            Status::Pass,
            "the static patch is already applied (bytes equal replacement_bytes)",
        );
        return r;
    } else {
        r.add(
            Status::Fail,
            format!(
                "original_bytes do not match: expected [{}], found [{}]",
                x86::hex(original),
                x86::hex(actual)
            ),
        );
        return r;
    }

    if !executable {
        r.summary = "(data)".into();
        return r;
    }

    // Instruction boundaries.
    let window = image
        .read_va_upto(hook.address(), original.len() + 15)
        .unwrap_or(actual);
    let stolen = match x86::boundary(window, hook.address(), original.len()) {
        Boundary::Exact(insns) => {
            r.summary = x86::join(&insns);
            Some(insns)
        }
        Boundary::Split {
            covered,
            straddling,
        } => {
            let status = if matches!(kind, HookType::Detour | HookType::Replace) {
                Status::Fail
            } else {
                Status::Warn
            };
            r.summary = x86::join(&covered);
            let cut = hook.address() + original.len() as u64 - straddling.va;
            r.add(
                status,
                format!(
                    "original_bytes end inside the instruction at {:#010X} ({}: {}): {cut} of its {} bytes are taken; \
                     use {} or {} bytes",
                    straddling.va,
                    straddling.hex(),
                    straddling.text,
                    straddling.len(),
                    straddling.va - hook.address(),
                    straddling.va - hook.address() + straddling.len() as u64
                ),
            );
            None
        }
        Boundary::Invalid { covered, at } => {
            r.summary = x86::join(&covered);
            r.add(
                Status::Fail,
                format!("bytes at {at:#010X} do not decode as x86 (is the address an instruction start?)"),
            );
            None
        }
    };

    match kind {
        HookType::Detour => {
            if let Some(insns) = &stolen {
                let branches: Vec<_> = insns
                    .iter()
                    .filter(|i| i.relative_target.is_some())
                    .map(|i| format!("{} @ {:#010X}", i.text, i.va))
                    .collect();
                if !branches.is_empty() {
                    if hook.skip_original_bytes {
                        r.add(
                            Status::Pass,
                            format!(
                                "relative branch never re-executed (skip_original_bytes): {}",
                                branches.join(", ")
                            ),
                        );
                    } else {
                        r.add(
                            Status::Fail,
                            format!(
                                "stolen bytes hold a relative branch, which jumps elsewhere when the wrapper \
                                 re-executes it: {}",
                                branches.join(", ")
                            ),
                        );
                    }
                }
            }
            if !hook.skip_original_bytes {
                let (reads, writes) = x86::register_use(original, hook.address());
                if hook.consumed_exit_address.is_some_and(|a| a.value != 0) {
                    if reads.contains("eax") || writes.contains("eax") {
                        r.add(
                            Status::Fail,
                            "stolen bytes touch EAX, which holds the handler's answer until the \
                             consumed-exit test after them",
                        );
                    }
                    if writes.contains("esp") {
                        r.add(
                            Status::Fail,
                            "stolen bytes move ESP before the consumed exit, which then sees a \
                             different stack",
                        );
                    }
                }
                let excluded: BTreeSet<String> = hook
                    .exclude_from_restore
                    .iter()
                    .map(|x| family(x))
                    .collect();
                for reg in excluded.intersection(&reads) {
                    if reg == "ebx" || reg == "esp" {
                        continue; // always restored / never popped
                    }
                    r.add(
                        Status::Fail,
                        format!(
                            "stolen bytes read {reg}, which is excluded from restore and so holds \
                             the handler's value, not the game's"
                        ),
                    );
                }
            }
        }
        HookType::Replace => {
            let block = x86::decode(replacement, 0, usize::MAX);
            if block.last().is_some_and(|i| i.invalid) {
                r.add(
                    Status::Fail,
                    "replacement_bytes end in an undecodable or truncated instruction",
                );
            }
            let escaping: Vec<_> = block
                .iter()
                .filter(|i| {
                    i.relative_target
                        .is_some_and(|t| t >= replacement.len() as u64)
                })
                .map(|i| format!("{} at block+{:#X}", i.text, i.va))
                .collect();
            if !escaping.is_empty() {
                r.add(
                    Status::Fail,
                    format!(
                        "replacement branches relatively out of its block, which KPM places at an \
                         arbitrary address: {}",
                        escaping.join(", ")
                    ),
                );
            }
        }
        _ => {}
    }
    r
}

/// Run every check. Fails only if `exe` is not a parseable PE.
pub fn verify(exe_label: &str, exe: Vec<u8>, sets: &[HookSet], opts: &Options) -> Result<Report> {
    let exe_len = exe.len();
    let exe_sha256 = hex_upper(&sha256(&exe));
    let image = Image::parse(exe)?;
    let packed = image.is_steamstub_packed();
    let mut origin_findings = Vec::new();
    if !image.is_i386() {
        origin_findings.push(Finding {
            status: Status::Fail,
            text:
                "not a 32-bit i386 image: KPM's Windows runtime and these checks are for PE32 x86"
                    .into(),
        });
    }

    // A .kpatch must have at least one hooks file KPM would pick, and its
    // manifest must list the build.
    let mut origins: Vec<&str> = sets
        .iter()
        .filter(|s| s.kind == SourceKind::KpatchMember)
        .map(|s| s.origin.as_str())
        .collect();
    origins.dedup();
    for origin in origins {
        let members: Vec<_> = sets.iter().filter(|s| s.origin == origin).collect();
        if !members.iter().any(|s| s.applies_to(&exe_sha256)) {
            origin_findings.push(Finding {
                status: Status::Fail,
                text: format!("{origin}: no hooks file inside targets this executable"),
            });
        }
        if let Some(m) = members.first().and_then(|s| s.manifest.as_ref()) {
            if !m.supports(&exe_sha256) {
                origin_findings.push(Finding {
                    status: Status::Fail,
                    text: format!(
                        "{origin}: manifest [patch.supported_versions] does not list this executable"
                    ),
                });
            }
        }
    }

    let mut results = Vec::new();
    for set in sets {
        let hash = if set.target_versions.is_empty() {
            HashCheck::NoTargets
        } else if set.applies_to(&exe_sha256) {
            HashCheck::Match
        } else if set.kind == SourceKind::KpatchMember {
            HashCheck::NotSelected(set.target_versions.clone())
        } else {
            HashCheck::Mismatch(set.target_versions.clone())
        };
        let set_findings = set
            .file_issues
            .iter()
            .map(|i| Finding {
                status: match i.severity {
                    Severity::Error => Status::Fail,
                    Severity::Warning => Status::Warn,
                },
                text: i.message.clone(),
            })
            .collect();
        let hooks = set
            .hooks
            .iter()
            .map(|h| check_hook(&image, packed, h))
            .collect();
        results.push(SetResult {
            label: set.label.clone(),
            hash,
            set_findings,
            hooks,
        });
    }

    let overlaps = find_overlaps(sets, &results, opts);
    Ok(Report {
        exe_label: exe_label.to_string(),
        exe_len,
        exe_sha256,
        image_summary: image.summary(),
        packed,
        origin_findings,
        sets: results,
        overlaps,
    })
}

fn selectors(h: &Hook) -> (Option<&str>, Option<&str>, Option<&str>) {
    (
        h.install.as_deref(),
        h.kpm_patch.as_deref(),
        h.when.as_deref(),
    )
}

fn find_overlaps(sets: &[HookSet], results: &[SetResult], opts: &Options) -> Vec<Overlap> {
    let mut all: Vec<(usize, &Hook)> = Vec::new();
    for (i, (set, result)) in sets.iter().zip(results).enumerate() {
        if matches!(result.hash, HashCheck::NotSelected(_)) {
            continue;
        }
        for h in &set.hooks {
            if !h.original_bytes.bytes.is_empty() {
                all.push((i, h));
            }
        }
    }
    all.sort_by_key(|(_, h)| (h.address(), h.original_bytes.bytes.len()));
    let mut out = Vec::new();
    for (ai, (sa, a)) in all.iter().enumerate() {
        for (sb, b) in all.iter().skip(ai + 1) {
            if b.address() >= a.range().end {
                break;
            }
            let same_file = sets[*sa].label == sets[*sb].label;
            let status =
                if same_file && (opts.allow_overlap_in_file || selectors(a) != selectors(b)) {
                    Status::Warn
                } else {
                    Status::Fail
                };
            let detail = if a.address() == b.address() {
                "same address".to_string()
            } else {
                format!(
                    "{:#010X}+{} overlaps {:#010X}+{}",
                    a.address(),
                    a.original_bytes.bytes.len(),
                    b.address(),
                    b.original_bytes.bytes.len()
                )
            };
            let detail = if status == Status::Warn && same_file {
                format!("{detail}; same file, alternatives by install/kpm_patch/when or --allow-overlap-in-file")
            } else {
                detail
            };
            out.push(Overlap {
                status,
                a: format!("{} ({})", a.label(), sets[*sa].label),
                b: format!("{} ({})", b.label(), sets[*sb].label),
                detail,
            });
        }
    }
    out
}
