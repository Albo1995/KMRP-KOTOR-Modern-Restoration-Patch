//! `kpm-tool pack`: a `.kpatch` laid out as KPM's `Patches/create-patch.py`
//! writes one -- a deflated zip of `manifest.toml`, each `*hooks.toml` at the
//! root under its own file name (sorted), the module as
//! `binaries/windows_x86.dll`, then any other `binaries/` files -- after the
//! checks KPM's manager would make when it scans the archive.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use kpm_sdk::model::{HookType, HooksFile, Manifest, Severity};
use kpm_sdk::process::{hex_upper, sha256};

use crate::pe::Image;

/// `DeploymentPolicy.PatchBinaryFileName` for Windows x86.
pub const MODULE_ENTRY: &str = "binaries/windows_x86.dll";

#[derive(Debug, Clone)]
pub struct PackInput {
    pub manifest: PathBuf,
    pub hooks: Vec<PathBuf>,
    pub dll: Option<PathBuf>,
    pub extra_binaries: Vec<PathBuf>,
    pub out: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PackSummary {
    pub out: PathBuf,
    pub entries: Vec<String>,
    pub bytes: u64,
    pub sha256: String,
    pub detours: usize,
    pub warnings: Vec<String>,
}

fn file_name(p: &Path) -> Result<String> {
    Ok(p.file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no usable file name", p.display()))?
        .to_string())
}

/// Validate the inputs and write the archive.
pub fn pack(input: &PackInput) -> Result<PackSummary> {
    let mut warnings = Vec::new();

    let manifest_text = std::fs::read_to_string(&input.manifest)
        .with_context(|| format!("cannot read {}", input.manifest.display()))?;
    let manifest = Manifest::parse(&manifest_text)
        .with_context(|| format!("{}: not a KPM manifest", input.manifest.display()))?;
    let mut errors = Vec::new();
    for issue in manifest.issues() {
        match issue.severity {
            Severity::Error => errors.push(format!("manifest.toml: {}", issue.message)),
            Severity::Warning => warnings.push(format!("manifest.toml: {}", issue.message)),
        }
    }

    if input.hooks.is_empty() {
        bail!("at least one --hooks file is needed (an empty one makes a DLL-only patch)");
    }
    let mut hooks_entries = Vec::new();
    let mut functions = Vec::new();
    let mut detours = 0;
    for path in &input.hooks {
        let name = file_name(path)?;
        if !name.to_ascii_lowercase().ends_with("hooks.toml") {
            bail!("{name}: KPM only reads archive entries ending in \"hooks.toml\"");
        }
        if hooks_entries
            .iter()
            .any(|(n, _): &(String, Vec<u8>)| n == &name)
        {
            bail!("two hooks files are named {name}");
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let file = HooksFile::parse(&text).with_context(|| format!("{name}: not a hooks file"))?;
        for issue in file.issues() {
            match issue.severity {
                Severity::Error => errors.push(format!("{name}: {}", issue.message)),
                Severity::Warning => warnings.push(format!("{name}: {}", issue.message)),
            }
        }
        for t in file.target_versions() {
            if !manifest.supports(t) {
                warnings.push(format!(
                    "{name}: target {t} is not in the manifest's supported_versions"
                ));
            }
        }
        for h in &file.hooks {
            for issue in h.issues() {
                let text = format!("{name}: {}: {}", h.label(), issue.message);
                match issue.severity {
                    Severity::Error => errors.push(text),
                    Severity::Warning => warnings.push(text),
                }
            }
            if h.kind.effective() == HookType::Detour {
                detours += 1;
                if let Some(f) = &h.function {
                    functions.push((name.clone(), f.clone()));
                }
            }
        }
        hooks_entries.push((name, text.into_bytes()));
    }
    hooks_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let module = match &input.dll {
        Some(path) => {
            let bytes =
                std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
            let image = Image::parse(bytes.clone())
                .with_context(|| format!("{}: not a PE file", path.display()))?;
            // create-patch.py's binary_target: i386 machine and the DLL flag.
            if !image.is_i386() || !image.is_dll() {
                errors.push(format!(
                    "{}: is {}, not a 32-bit i386 DLL",
                    path.display(),
                    image.summary()
                ));
            }
            for (hooks, f) in &functions {
                if !image.exports.iter().any(|e| e == f) {
                    errors.push(format!(
                        "{hooks}: detour function {f:?} is not exported by {} (exports: {})",
                        path.display(),
                        image.exports.join(", ")
                    ));
                }
            }
            Some(bytes)
        }
        None => {
            if detours > 0 {
                errors.push(format!(
                    "{detours} detour hook(s) need a module: pass --dll (KPM refuses a DETOUR patch without {MODULE_ENTRY})"
                ));
            }
            None
        }
    };
    let only_empty_hooks = hooks_entries.iter().all(|(_, text)| {
        HooksFile::parse(std::str::from_utf8(text).unwrap_or(""))
            .map(|f| f.hooks.is_empty())
            .unwrap_or(false)
    });
    if module.is_none() && only_empty_hooks {
        errors.push("no hooks and no module: the patch would do nothing".into());
    }

    if !errors.is_empty() {
        bail!("refusing to pack:\n  - {}", errors.join("\n  - "));
    }

    let mut extras = Vec::new();
    for path in &input.extra_binaries {
        let name = file_name(path)?;
        if name == "windows_x86.dll" && module.is_some() {
            bail!("--binary {name} would replace the module passed with --dll");
        }
        extras.push((format!("binaries/{name}"), std::fs::read(path)?));
    }
    extras.sort_by(|a, b| a.0.cmp(&b.0));

    // Write.
    if let Some(parent) = input.out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut entries: Vec<(String, Vec<u8>)> =
        vec![("manifest.toml".to_string(), manifest_text.into_bytes())];
    entries.extend(hooks_entries);
    if let Some(bytes) = module {
        entries.push((MODULE_ENTRY.to_string(), bytes));
    }
    entries.extend(extras);

    let file = std::fs::File::create(&input.out)
        .with_context(|| format!("cannot create {}", input.out.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    // A fixed timestamp, as KMRP's own builders use, so the same inputs make
    // the same bytes.
    let stamp = zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0)
        .map_err(|_| anyhow::anyhow!("bad zip timestamp"))?;
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(stamp)
        .unix_permissions(0o644);
    for (name, bytes) in &entries {
        zip.start_file(name.as_str(), options)?;
        zip.write_all(bytes)?;
    }
    zip.finish()?;

    // Re-read what was written.
    let written = std::fs::read(&input.out)?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&written))?;
    for (name, bytes) in &entries {
        let mut e = archive.by_name(name)?;
        let mut back = Vec::new();
        e.read_to_end(&mut back)?;
        if &back != bytes {
            bail!("{name} reads back differently from what was written");
        }
    }
    if archive.len() != entries.len() {
        bail!(
            "archive holds {} entries, expected {}",
            archive.len(),
            entries.len()
        );
    }

    Ok(PackSummary {
        out: input.out.clone(),
        entries: entries.into_iter().map(|(n, _)| n).collect(),
        bytes: written.len() as u64,
        sha256: hex_upper(&sha256(&written)),
        detours,
        warnings,
    })
}
