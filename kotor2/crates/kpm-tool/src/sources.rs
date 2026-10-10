//! Loading hook sets from the three places they live: a `*hooks.toml`, an
//! installed `patch_config.toml`, or the hooks files inside a `.kpatch`.

use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use kpm_sdk::model::{Hook, HooksFile, Issue, Manifest, PatchConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    /// A hooks file given directly: its `target_versions` must match.
    HooksFile,
    /// A `patch_config.toml`: `target_version_sha` must match.
    PatchConfig,
    /// A hooks file inside a `.kpatch`: KPM only uses it if it matches, so a
    /// non-matching one is skipped rather than failed.
    KpatchMember,
}

#[derive(Debug, Clone)]
pub struct HookSet {
    /// `path`, `path#patch-id`, or `archive.kpatch!member.hooks.toml`.
    pub label: String,
    /// Groups the sets of one `.kpatch` or one config file.
    pub origin: String,
    pub kind: SourceKind,
    pub target_versions: Vec<String>,
    pub hooks: Vec<Hook>,
    pub file_issues: Vec<Issue>,
    /// The `.kpatch` manifest, when there is one.
    pub manifest: Option<Manifest>,
}

impl HookSet {
    pub fn applies_to(&self, sha256: &str) -> bool {
        self.target_versions.is_empty()
            || self
                .target_versions
                .iter()
                .any(|t| t.eq_ignore_ascii_case(sha256))
    }
}

fn from_hooks_file(
    label: String,
    origin: String,
    kind: SourceKind,
    file: HooksFile,
    manifest: Option<Manifest>,
) -> HookSet {
    HookSet {
        label,
        origin,
        kind,
        target_versions: file.target_versions().to_vec(),
        file_issues: file.issues(),
        hooks: file.hooks,
        manifest,
    }
}

/// Parse TOML text as a `patch_config.toml` (if it has `[[patches]]`) or a
/// hooks file.
pub fn load_text(label: &str, text: &str) -> Result<Vec<HookSet>> {
    let value: toml::Table =
        toml::from_str(text).with_context(|| format!("{label}: not valid TOML"))?;
    if value.contains_key("patches") {
        let config = PatchConfig::parse(text)
            .with_context(|| format!("{label}: not a patch_config.toml"))?;
        let targets: Vec<String> = config.target_version_sha.iter().cloned().collect();
        return Ok(config
            .patches
            .into_iter()
            .map(|p| HookSet {
                label: format!("{label}#{}", p.id),
                origin: label.to_string(),
                kind: SourceKind::PatchConfig,
                target_versions: targets.clone(),
                hooks: p.hooks,
                file_issues: Vec::new(),
                manifest: None,
            })
            .collect());
    }
    let file = HooksFile::parse(text).with_context(|| format!("{label}: not a hooks file"))?;
    Ok(vec![from_hooks_file(
        label.to_string(),
        label.to_string(),
        SourceKind::HooksFile,
        file,
        None,
    )])
}

/// Every hooks file in a `.kpatch` (zip), the way `PatchRepository` finds
/// them: any entry whose name ends in `hooks.toml`, case-insensitively.
pub fn load_kpatch(label: &str, bytes: &[u8]) -> Result<Vec<HookSet>> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .with_context(|| format!("{label}: not a zip archive"))?;
    let mut read = |name: &str| -> Result<String> {
        let mut entry = zip.by_name(name)?;
        let mut text = String::new();
        entry
            .read_to_string(&mut text)
            .with_context(|| format!("{label}!{name}: not UTF-8"))?;
        Ok(text)
    };
    let manifest = match read("manifest.toml") {
        Ok(text) => Some(Manifest::parse(&text).with_context(|| format!("{label}!manifest.toml"))?),
        Err(_) => None,
    };
    let names: Vec<String> = zip
        .file_names()
        .filter(|n| n.to_ascii_lowercase().ends_with("hooks.toml"))
        .map(str::to_string)
        .collect();
    let mut names = names;
    names.sort();
    if names.is_empty() {
        bail!("{label}: no *hooks.toml inside");
    }
    let mut sets = Vec::new();
    for name in names {
        let text = {
            let mut entry = zip.by_name(&name)?;
            let mut text = String::new();
            entry.read_to_string(&mut text)?;
            text
        };
        let member = format!("{label}!{name}");
        let file = HooksFile::parse(&text).with_context(|| member.clone())?;
        sets.push(from_hooks_file(
            member,
            label.to_string(),
            SourceKind::KpatchMember,
            file,
            manifest.clone(),
        ));
    }
    Ok(sets)
}

/// Load a path of any of the three kinds.
pub fn load(path: &Path) -> Result<Vec<HookSet>> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let label = path.display().to_string();
    if bytes.starts_with(b"PK\x03\x04") {
        return load_kpatch(&label, &bytes);
    }
    let text = String::from_utf8(bytes).with_context(|| format!("{label}: not UTF-8 text"))?;
    load_text(&label, &text)
}
