//! Typed model of KPM's TOML files:
//!
//! * `*hooks.toml` inside a `.kpatch` -- read by KPatchCore's `HooksParser`
//!   (`[metadata] target_versions`, `[[hooks]]`, `[[hooks.parameters]]`);
//! * `manifest.toml` -- KPatchCore's `ManifestParser` (`[patch]`);
//! * `patch_config.toml` in the game folder -- the runtime's `config_reader.cpp`
//!   (`target_version_sha`, `[[patches]]` each with `id`, `dll`, `[[patches.hooks]]`).
//!
//! Both readers are accommodated: addresses may be TOML integers (what
//! KPatchCore requires and `ConfigGenerator` writes) or hex strings
//! (`"0x401234"`, which only the runtime reader accepts -- [`Hook::issues`]
//! warns about them), and byte arrays may hold integers or `"0x55"` strings.
//!
//! KMRP's own keys (`install`, `kpm_patch`, `kpm_provided_by`, `when`) are
//! modelled; KPM ignores them. Any other unknown key is kept in `extra` and
//! reported as a warning, so a typo such as `skip_orginal_bytes` is not
//! silently dropped.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::abi::{ParamSource, ParamType, RESTORABLE_REGISTERS};

/// A parse or validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Error,
}

impl Issue {
    fn error(message: impl Into<String>) -> Issue {
        Issue {
            severity: Severity::Error,
            message: message.into(),
        }
    }
    fn warning(message: impl Into<String>) -> Issue {
        Issue {
            severity: Severity::Warning,
            message: message.into(),
        }
    }
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = match self.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        write!(f, "{tag}: {}", self.message)
    }
}

// ---------------------------------------------------------------------------
// Number and byte-array forms

/// How a number was written, kept so validation can say which reader accepts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NumberForm {
    #[default]
    Integer,
    HexString,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawNumber {
    Int(i64),
    Str(String),
}

fn parse_hex_string(s: &str) -> Option<u64> {
    // config_reader.cpp ParseHexValue: optional 0x/0X, then strtoull base 16
    // with the whole string consumed.
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if body.is_empty() || !body.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(body, 16).ok()
}

fn number_from_raw<E: de::Error>(raw: RawNumber) -> Result<(u64, NumberForm), E> {
    match raw {
        RawNumber::Int(i) if i >= 0 => Ok((i as u64, NumberForm::Integer)),
        RawNumber::Int(i) => Err(E::custom(format!("negative address {i}"))),
        RawNumber::Str(s) => parse_hex_string(&s)
            .map(|v| (v, NumberForm::HexString))
            .ok_or_else(|| E::custom(format!("invalid hex address {s:?}"))),
    }
}

/// An address as written in TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Address {
    pub value: u64,
    pub form: NumberForm,
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (value, form) = number_from_raw(RawNumber::deserialize(d)?)?;
        Ok(Address { value, form })
    }
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(self.value as i64)
    }
}

impl From<u64> for Address {
    fn from(value: u64) -> Self {
        Address {
            value,
            form: NumberForm::Integer,
        }
    }
}

/// A byte array as written in TOML (`[0x8B, 0x44]` or `["0x8B", "0x44"]`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bytes {
    pub bytes: Vec<u8>,
    /// True if any element was a hex string (runtime reader only).
    pub has_strings: bool,
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Vec::<RawNumber>::deserialize(d)?;
        let mut out = Bytes::default();
        for item in raw {
            let (v, form) = number_from_raw::<D::Error>(item)?;
            if v > 0xFF {
                return Err(de::Error::custom(format!(
                    "byte value {v:#x} out of range (0-255)"
                )));
            }
            out.has_strings |= form == NumberForm::HexString;
            out.bytes.push(v as u8);
        }
        Ok(out)
    }
}

impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.bytes.serialize(s)
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Bytes {
            bytes,
            has_strings: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Hook

/// A hook's `type`. KPM compares case-insensitively and treats an unknown
/// type as `detour` (with a log line); [`HookType::Other`] keeps the text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HookType {
    /// Trampoline to KPM's wrapper, which calls `function` in the patch module.
    #[default]
    Detour,
    /// `replacement_bytes` written over the site in memory, same length.
    Simple,
    /// JMP to an allocated block holding `replacement_bytes` + `JMP back`.
    Replace,
    /// Written into the executable file at install time (manager only;
    /// never reaches `patch_config.toml`).
    Static,
    Other(String),
}

impl HookType {
    pub fn parse(text: &str) -> HookType {
        match text.to_ascii_lowercase().as_str() {
            "detour" => HookType::Detour,
            "simple" => HookType::Simple,
            "replace" => HookType::Replace,
            "static" => HookType::Static,
            _ => HookType::Other(text.to_string()),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            HookType::Detour => "detour",
            HookType::Simple => "simple",
            HookType::Replace => "replace",
            HookType::Static => "static",
            HookType::Other(s) => s,
        }
    }

    /// What KPM actually does with it.
    pub fn effective(&self) -> HookType {
        match self {
            HookType::Other(_) => HookType::Detour,
            t => t.clone(),
        }
    }
}

impl fmt::Display for HookType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl<'de> Deserialize<'de> for HookType {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(HookType::parse(&String::deserialize(d)?))
    }
}

impl Serialize for HookType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

/// One `[[hooks.parameters]]` entry.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Parameter {
    pub source: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Parameter {
    pub fn param_type(&self) -> Option<ParamType> {
        ParamType::parse(&self.kind)
    }

    /// The source as the x86 wrapper would read it.
    pub fn resolve(&self) -> Result<(ParamType, ParamSource), String> {
        let ty = self
            .param_type()
            .ok_or_else(|| format!("unknown parameter type {:?}", self.kind))?;
        let source = ParamSource::parse(&self.source, ty).map_err(|e| e.to_string())?;
        Ok((ty, source))
    }
}

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One `[[hooks]]` entry.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Hook {
    pub address: Address,
    #[serde(rename = "type", default)]
    pub kind: HookType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    pub original_bytes: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_bytes: Option<Bytes>,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub preserve_registers: bool,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub preserve_flags: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_from_restore: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub skip_original_bytes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_exit_address: Option<Address>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<Parameter>,

    /// KMRP: which install a hook belongs to (`always`, `controller`,
    /// `no-controller`; absent means `controller`). KPM ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<String>,
    /// KMRP: which KPM-edition patch carries the hook (`""` = none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kpm_patch: Option<String>,
    /// KMRP: the KPM patch that makes the same change (declared as a conflict).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kpm_provided_by: Option<String>,
    /// KMRP (manager with patch options): the option that gates the hook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,

    /// Keys neither KPM nor KMRP defines.
    #[serde(flatten)]
    pub extra: toml::Table,
}

/// KPM's plausible-address windows (`HookValidator.IsPlausibleImageAddress`).
pub fn is_plausible_image_address(address: u64) -> bool {
    (0x0040_0000..=0x7FFF_FFFF).contains(&address)
        || (0x1_0000_0000..=0x1_FFFF_FFFF).contains(&address)
}

/// KPM's `HookValidator.IsValidFunctionName`.
pub fn is_valid_function_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

impl Hook {
    pub fn address(&self) -> u64 {
        self.address.value
    }

    /// Bytes the hook claims at its site: `[address, address + len)`.
    pub fn range(&self) -> std::ops::Range<u64> {
        self.address.value..self.address.value + self.original_bytes.bytes.len() as u64
    }

    pub fn replacement(&self) -> &[u8] {
        self.replacement_bytes
            .as_ref()
            .map(|b| b.bytes.as_slice())
            .unwrap_or(&[])
    }

    /// A short label: `Function @ 0x00401234 (detour)`.
    pub fn label(&self) -> String {
        match &self.function {
            Some(f) if !f.trim().is_empty() => {
                format!("{f} @ {:#010X} ({})", self.address.value, self.kind)
            }
            _ => format!("{} hook @ {:#010X}", self.kind, self.address.value),
        }
    }

    /// True if `reg` is in `exclude_from_restore` (case-insensitive).
    pub fn excludes(&self, reg: &str) -> bool {
        self.exclude_from_restore
            .iter()
            .any(|r| r.eq_ignore_ascii_case(reg))
    }

    /// Every rule KPatchCore (`Hook.IsValid`, `HookValidator`, `Parameter`)
    /// and the runtime (`config_reader.cpp`, `wrapper_x86.cpp`) apply to a
    /// hook on its own, for the 32-bit Windows target. Errors are what would
    /// make KPM refuse or drop the hook; warnings are legal but suspicious.
    pub fn issues(&self) -> Vec<Issue> {
        let mut out = Vec::new();
        let address = self.address.value;
        let original = &self.original_bytes.bytes;
        let kind = self.kind.effective();
        let function = self.function.as_deref().map(str::trim).unwrap_or("");

        if address == 0 {
            out.push(Issue::error("address cannot be zero"));
        } else if !is_plausible_image_address(address) {
            out.push(Issue::error(format!(
                "address {address:#X} is outside 0x00400000-0x7FFFFFFF (KPM's plausible range)"
            )));
        }
        if address > u32::MAX as u64 {
            out.push(Issue::error(
                "address does not fit a 32-bit target (the runtime rejects it)",
            ));
        }
        if self.address.form == NumberForm::HexString {
            out.push(Issue::warning(
                "address is a string: the runtime accepts that, but KPM's manager \
                 (KPatchCore) requires an integer in a .kpatch hooks file",
            ));
        }
        if self.original_bytes.has_strings
            || self
                .replacement_bytes
                .as_ref()
                .is_some_and(|b| b.has_strings)
        {
            out.push(Issue::warning(
                "byte array holds strings: only the runtime reader accepts them; \
                 KPatchCore requires integers",
            ));
        }
        if original.is_empty() {
            out.push(Issue::error(
                "original_bytes must contain at least one byte",
            ));
        }
        if let HookType::Other(t) = &self.kind {
            out.push(Issue::warning(format!(
                "unknown hook type {t:?}: KPM treats it as \"detour\""
            )));
        }

        let replacement = self.replacement_bytes.as_ref().map(|b| b.bytes.len());
        let no_function_or_params = |out: &mut Vec<Issue>, what: &str| {
            if !function.is_empty() {
                out.push(Issue::error(format!(
                    "{what} hooks should not have a function name"
                )));
            }
            if !self.parameters.is_empty() {
                out.push(Issue::error(format!("{what} hooks cannot have parameters")));
            }
        };

        match kind {
            HookType::Detour => {
                if function.is_empty() {
                    out.push(Issue::error("detour hook needs a non-empty `function`"));
                } else if !is_valid_function_name(function) {
                    out.push(Issue::warning(format!(
                        "function {function:?} is not a plain identifier; GetProcAddress \
                         must find exactly this export name"
                    )));
                }
                if original.len() < 5 {
                    out.push(Issue::error(format!(
                        "detour original_bytes is {} byte(s); it must be at least 5 \
                         (the JMP rel32 written over the site)",
                        original.len()
                    )));
                }
                if self.consumed_exit_address.is_some_and(|a| a.value != 0) && !self.excludes("eax")
                {
                    out.push(Issue::error(
                        "consumed_exit_address requires \"eax\" in exclude_from_restore \
                         (the wrapper tests the handler's EAX after restoring registers)",
                    ));
                }
                if replacement.is_some() {
                    out.push(Issue::warning(
                        "replacement_bytes is ignored on a detour hook",
                    ));
                }
                for (i, p) in self.parameters.iter().enumerate() {
                    if let Err(e) = p.resolve() {
                        out.push(Issue::error(format!(
                            "parameter {i} ({:?}, {:?}): {e} -- the runtime drops the whole hook",
                            p.source, p.kind
                        )));
                    }
                }
                for r in &self.exclude_from_restore {
                    let lower = r.to_ascii_lowercase();
                    if lower == "ebx" || lower == "esp" {
                        out.push(Issue::warning(format!(
                            "exclude_from_restore {r:?} has no effect (the wrapper always \
                             restores EBX and never pops ESP)"
                        )));
                    } else if !RESTORABLE_REGISTERS.contains(&lower.as_str()) {
                        out.push(Issue::warning(format!(
                            "exclude_from_restore {r:?} is not an x86 general-purpose register"
                        )));
                    }
                }
                if !self.preserve_registers && !self.exclude_from_restore.is_empty() {
                    out.push(Issue::warning(
                        "preserve_registers = false already leaves every register but EBX \
                         unrestored; exclude_from_restore is redundant",
                    ));
                }
            }
            HookType::Simple | HookType::Static => {
                let what = kind.name();
                match replacement {
                    None | Some(0) => {
                        out.push(Issue::error(format!("{what} hook needs replacement_bytes")))
                    }
                    Some(n) if n != original.len() => out.push(Issue::error(format!(
                        "replacement_bytes length ({n}) must match original_bytes length ({})",
                        original.len()
                    ))),
                    _ => {}
                }
                no_function_or_params(&mut out, what);
            }
            HookType::Replace => {
                if replacement.unwrap_or(0) == 0 {
                    out.push(Issue::error(
                        "replace hook needs non-empty replacement_bytes",
                    ));
                }
                if original.len() < 5 {
                    out.push(Issue::error(format!(
                        "replace original_bytes is {} byte(s); it must be at least 5",
                        original.len()
                    )));
                }
                no_function_or_params(&mut out, "replace");
            }
            HookType::Other(_) => unreachable!("effective() maps Other to Detour"),
        }

        if kind != HookType::Detour {
            if self.consumed_exit_address.is_some() {
                out.push(Issue::warning(format!(
                    "consumed_exit_address is ignored on a {} hook",
                    kind.name()
                )));
            }
            if self.skip_original_bytes || !self.exclude_from_restore.is_empty() {
                out.push(Issue::warning(format!(
                    "wrapper options are ignored on a {} hook",
                    kind.name()
                )));
            }
        }

        for key in self.extra.keys() {
            out.push(Issue::warning(format!(
                "unknown key {key:?} (ignored by KPM)"
            )));
        }
        for (i, p) in self.parameters.iter().enumerate() {
            for key in p.extra.keys() {
                out.push(Issue::warning(format!(
                    "parameter {i}: unknown key {key:?} (ignored by KPM)"
                )));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// hooks.toml

/// `[metadata]` of a hooks file.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
pub struct Metadata {
    /// SHA-256 (hex, any case) of each executable these hooks are for. Empty
    /// or absent: the file applies to every version the manifest supports.
    #[serde(default)]
    pub target_versions: Vec<String>,
    #[serde(flatten)]
    pub extra: toml::Table,
}

/// A `*hooks.toml` file.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
pub struct HooksFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(default)]
    pub hooks: Vec<Hook>,
    #[serde(flatten)]
    pub extra: toml::Table,
}

/// True for 64 hex digits.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

impl HooksFile {
    pub fn parse(text: &str) -> Result<HooksFile, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    pub fn target_versions(&self) -> &[String] {
        self.metadata
            .as_ref()
            .map(|m| m.target_versions.as_slice())
            .unwrap_or(&[])
    }

    /// Whether KPM would pick this file for an executable with `sha256`
    /// (`PatchRepository`: no targets, or a case-insensitive match).
    pub fn applies_to(&self, sha256: &str) -> bool {
        let targets = self.target_versions();
        targets.is_empty() || targets.iter().any(|t| t.eq_ignore_ascii_case(sha256))
    }

    /// File-level findings (per-hook findings come from [`Hook::issues`]).
    pub fn issues(&self) -> Vec<Issue> {
        let mut out = Vec::new();
        for t in self.target_versions() {
            if !is_sha256_hex(t) {
                out.push(Issue::error(format!(
                    "target_versions entry {t:?} is not a SHA-256"
                )));
            }
        }
        if let Some(m) = &self.metadata {
            for key in m.extra.keys() {
                out.push(Issue::warning(format!("[metadata] unknown key {key:?}")));
            }
        }
        for key in self.extra.keys() {
            out.push(Issue::warning(format!("unknown top-level key {key:?}")));
        }
        // KPM's DetectOverlappingHooks: two hooks at one start address.
        let mut seen = BTreeMap::new();
        for (i, h) in self.hooks.iter().enumerate() {
            if let Some(j) = seen.insert(h.address.value, i) {
                out.push(Issue::warning(format!(
                    "hooks {j} and {i} share address {:#010X} (KPM refuses that within one \
                     installed patch)",
                    h.address.value
                )));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// patch_config.toml

/// One `[[patches]]` entry of the runtime's `patch_config.toml`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
pub struct ConfigPatch {
    #[serde(default)]
    pub id: String,
    /// Relative to the game folder, e.g. `patches/kmrp.dll`.
    #[serde(default)]
    pub dll: String,
    #[serde(default)]
    pub hooks: Vec<Hook>,
    #[serde(flatten)]
    pub extra: toml::Table,
}

/// `patch_config.toml`, as `ConfigGenerator` writes it and `config_reader.cpp`
/// reads it. A patch with a `dll` and no hooks is loaded as DLL-only.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
pub struct PatchConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version_sha: Option<String>,
    #[serde(default)]
    pub patches: Vec<ConfigPatch>,
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl PatchConfig {
    pub fn parse(text: &str) -> Result<PatchConfig, toml::de::Error> {
        toml::from_str(text)
    }
}

// ---------------------------------------------------------------------------
// manifest.toml

/// One `[[patch.options]]` entry (KMRP's patch options; stock KPM 0.7.1 ignores them).
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
pub struct PatchOption {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub default: Option<toml::Value>,
    #[serde(flatten)]
    pub extra: toml::Table,
}

/// `[patch]` of `manifest.toml`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
pub struct ManifestPatch {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<PatchOption>,
    /// Version key (e.g. `kotor2_gog_aspyr`) to executable SHA-256.
    #[serde(default)]
    pub supported_versions: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: toml::Table,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
pub struct Manifest {
    pub patch: ManifestPatch,
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Manifest, toml::de::Error> {
        toml::from_str(text)
    }

    /// `ManifestParser`'s required fields, plus hash sanity.
    pub fn issues(&self) -> Vec<Issue> {
        let p = &self.patch;
        let mut out = Vec::new();
        for (key, value) in [
            ("id", &p.id),
            ("name", &p.name),
            ("version", &p.version),
            ("author", &p.author),
            ("description", &p.description),
        ] {
            if value.trim().is_empty() {
                out.push(Issue::error(format!(
                    "manifest missing required field: patch.{key}"
                )));
            }
        }
        for (key, sha) in &p.supported_versions {
            if !is_sha256_hex(sha) {
                out.push(Issue::error(format!(
                    "supported_versions.{key} = {sha:?} is not a SHA-256"
                )));
            }
        }
        if p.supported_versions.is_empty() {
            out.push(Issue::warning(
                "no [patch.supported_versions]: KPM cannot match this patch to a game",
            ));
        }
        if p.conflicts.iter().any(|c| c == &p.id) {
            out.push(Issue::error("a patch cannot conflict with itself"));
        }
        out
    }

    pub fn supports(&self, sha256: &str) -> bool {
        self.patch
            .supported_versions
            .values()
            .any(|v| v.eq_ignore_ascii_case(sha256))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[metadata]
target_versions = ["777BEE235A9E8BDD9863F6741BC3AC54BB6A113B62B1D2E4D12BBE6DB963A914"]

[[hooks]]
address = 0x0041A9D0
type = "detour"
install = "always"
function = "KeyboardNavigateK1"
original_bytes = [0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0]
skip_original_bytes = false
exclude_from_restore = []

[[hooks.parameters]]
source = "ecx"
type = "pointer"

[[hooks.parameters]]
source = "esp+4"
type = "pointer"

[[hooks]]
address = "0x0046BE64"
type = "Replace"
kpm_provided_by = "texture-bucket-safety"
original_bytes = ["0xC3", 0x90, 0x90, 0x90, 0x90]
replacement_bytes = [0x3D, 0x88, 0x13, 0x00, 0x00, 0xC3]
"#;

    #[test]
    fn parses_both_reader_forms() {
        let f = HooksFile::parse(SAMPLE).unwrap();
        assert_eq!(f.hooks.len(), 2);
        let d = &f.hooks[0];
        assert_eq!(d.address.value, 0x0041_A9D0);
        assert_eq!(d.kind, HookType::Detour);
        assert_eq!(d.install.as_deref(), Some("always"));
        assert_eq!(d.parameters.len(), 2);
        assert!(d.preserve_registers && d.preserve_flags);
        assert!(d.issues().is_empty(), "{:?}", d.issues());
        let r = &f.hooks[1];
        assert_eq!(r.kind, HookType::Replace);
        assert_eq!(r.address.form, NumberForm::HexString);
        assert_eq!(r.original_bytes.bytes[0], 0xC3);
        assert!(r.issues().iter().all(|i| i.severity == Severity::Warning));
        assert!(f.applies_to("777bee235a9e8bdd9863f6741bc3ac54bb6a113b62b1d2e4d12bbe6db963a914"));
        assert!(!f.applies_to("00"));
    }

    #[test]
    fn rules() {
        let mut h: Hook = toml::from_str(
            "address = 0x401000\nfunction = \"F\"\noriginal_bytes = [1,2,3,4]\n\
             consumed_exit_address = 0x401234\n",
        )
        .unwrap();
        let errors: Vec<_> = h
            .issues()
            .into_iter()
            .filter(|i| i.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 2, "{errors:?}"); // < 5 bytes, eax not excluded
        h.original_bytes = vec![1, 2, 3, 4, 5].into();
        h.exclude_from_restore = vec!["EAX".into()];
        assert!(h.issues().is_empty(), "{:?}", h.issues());

        let s: Hook = toml::from_str(
            "address = 0x401000\ntype = \"simple\"\noriginal_bytes = [1,2]\n\
             replacement_bytes = [3]\nskip_orginal_bytes = true\n",
        )
        .unwrap();
        let msgs: Vec<_> = s.issues().into_iter().map(|i| i.message).collect();
        assert!(msgs.iter().any(|m| m.contains("must match")));
        assert!(msgs.iter().any(|m| m.contains("skip_orginal_bytes")));
    }

    #[test]
    fn byte_out_of_range_is_a_parse_error() {
        assert!(toml::from_str::<Hook>("address = 1\noriginal_bytes = [256]\n").is_err());
        assert!(toml::from_str::<Hook>("address = -1\noriginal_bytes = [1]\n").is_err());
    }

    #[test]
    fn round_trip() {
        let f = HooksFile::parse(SAMPLE).unwrap();
        let again = HooksFile::parse(&f.to_toml().unwrap()).unwrap();
        assert_eq!(again.hooks.len(), 2);
        assert_eq!(
            again.hooks[1].original_bytes.bytes,
            f.hooks[1].original_bytes.bytes
        );
        assert_eq!(again.hooks[0].parameters, f.hooks[0].parameters);
    }

    #[test]
    fn patch_config_and_manifest() {
        let c = PatchConfig::parse(
            "target_version_sha = \"AB\"\n[[patches]]\nid = \"x\"\ndll = \"patches/x.dll\"\n\
             [[patches.hooks]]\naddress = \"0x401000\"\nfunction = \"F\"\n\
             original_bytes = [\"0x55\", 1, 2, 3, 4]\n",
        )
        .unwrap();
        assert_eq!(c.patches[0].hooks[0].original_bytes.bytes[0], 0x55);
        let m = Manifest::parse(
            "[patch]\nid = \"a\"\nname = \"A\"\nversion = \"1\"\nauthor = \"x\"\n\
             description = \"d\"\n[patch.supported_versions]\nk = \"zz\"\n",
        )
        .unwrap();
        assert_eq!(m.issues().len(), 1);
    }
}
