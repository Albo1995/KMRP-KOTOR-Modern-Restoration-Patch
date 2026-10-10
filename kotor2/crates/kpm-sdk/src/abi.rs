//! The calling contract between KPM's 32-bit x86 detour wrapper and a patch
//! module's hook function, read from `src/KotorPatcher/src/core/wrapper_x86.cpp`,
//! `patcher.cpp`, `config_reader.cpp` and `include/wrappers/wrapper_base.h`
//! (submodule `third_party/Kotor-Patch-Manager` at `2a784bf`).
//!
//! The crate README restates this as prose; this module is the machine-checked
//! half: the parameter-source grammar the wrapper accepts, the parameter types
//! and how each is widened into its stack slot, and the layout of the saved
//! register block.
//!
//! # What the wrapper does, in order
//!
//! The hook site is overwritten with `E9 rel32` (JMP, not CALL) to a stub, and
//! the rest of `original_bytes` with `0x90`. The stub:
//!
//! 1. `LEA ESP,[ESP-528]` reserves an FXSAVE area (512 bytes + 16 slack).
//! 2. `PUSHAD`, `PUSHFD`, `MOV EBX,ESP`: EBX anchors the saved block
//!    ([`SavedRegisters`]); the game's ESP is `EBX + 564`.
//! 3. `FXSAVE` of x87/MMX/SSE state into the 16-aligned slot of the area.
//! 4. `AND ESP,-16`, then `SUB ESP,pad` so that after the parameter pushes ESP
//!    is 16-byte aligned at the CALL.
//! 5. Pushes each `[[hooks.parameters]]` entry right-to-left (so parameter 0
//!    is the first C argument), one 4-byte slot each, via ECX.
//! 6. `CALL patch_function`, then `MOV ESP,EBX`. Because ESP is reloaded from
//!    EBX, the callee may be cdecl *or* stdcall; KPM resolves the symbol with
//!    `GetProcAddress(name)`, so use `extern "C"` (cdecl, undecorated export).
//!    The callee must preserve EBX, ESI, EDI, EBP -- every Windows x86
//!    convention does.
//! 7. With `preserve_registers` (default true): `FXRSTOR`. Any x87 `ST(0)`
//!    return value is therefore discarded.
//! 8. With `preserve_flags` (default true): `POPFD`, else skip the slot.
//! 9. `POPAD` if `preserve_registers` and nothing is excluded; otherwise one
//!    `POP` per register, skipping (LEA ESP,[ESP+4]) the ESP slot always and
//!    every register in `exclude_from_restore`. EBX is restored regardless,
//!    because the wrapper used it as its anchor. With `preserve_registers =
//!    false` only EBX is restored.
//! 10. `LEA ESP,[ESP+528]`: back to the game's ESP.
//! 11. Unless `skip_original_bytes`, the stolen `original_bytes` run verbatim
//!     in the stub (so they must be position independent -- no rel8/rel32
//!     branch or call).
//! 12. If `consumed_exit_address` is set: `PUSHFD; TEST EAX,EAX; JZ +6;
//!     POPFD; JMP consumed_exit; POPFD`. A non-zero EAX takes the consumed
//!     exit. This happens *after* step 11, so the stolen bytes must not touch
//!     EAX, and `"eax"` must be excluded from restore (KPM's manager refuses
//!     the hook otherwise).
//! 13. `JMP hook_address + len(original_bytes)`.
//!
//! # Return values
//!
//! The hook's return value lands in EAX (EDX:EAX for 64-bit). It reaches the
//! game only for registers listed in `exclude_from_restore`; otherwise POPAD
//! overwrites it. ECX and EDX are caller-saved, so excluding them hands the
//! game whatever the hook left there, which is garbage unless the hook wrote
//! them through [`SavedRegisters`] (see below) -- prefer that.
//!
//! # Changing registers other than EAX
//!
//! KPM offers no official way, but the parameter grammar makes one: the source
//! `"esp-564"` (type `pointer`) is `LEA ECX,[EBX+0]`, the address of the saved
//! block, laid out as [`SavedRegisters`]. Writing a slot changes what POPAD /
//! POPFD restore. This depends on KPM's private constant `kFpAreaSize = 528`
//! and the PUSHAD/PUSHFD order; re-check [`SAVED_STATE_FROM_GAME_ESP`] against
//! `wrapper_x86.cpp` whenever the KPM runtime is updated.

use core::fmt;

/// Bytes the wrapper reserves for FXSAVE below the game's ESP (`kFpAreaSize`).
pub const FP_AREA_SIZE: i32 = 512 + 16;
/// Bytes of PUSHAD (32) + PUSHFD (4) (`savedStateSize`).
pub const SAVED_STATE_SIZE: i32 = 4 + 32;
/// Distance from the saved block (EBX) up to the game's ESP at the hook site.
pub const SAVED_STATE_FROM_GAME_ESP: i32 = SAVED_STATE_SIZE + FP_AREA_SIZE;
/// The parameter source whose value is a `*mut SavedRegisters`.
pub const SAVED_REGISTERS_SOURCE: &str = "esp-564";

/// KPM's sanity bound on a signed offset (`kMaxOffsetMagnitude`).
pub const MAX_OFFSET_MAGNITUDE: u64 = 0x7FFF_0000;

/// The block the wrapper pushes, as it sits at EBX during the call.
///
/// Only reachable through the [`SAVED_REGISTERS_SOURCE`] parameter trick; see
/// the module documentation for the caveats.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SavedRegisters {
    pub eflags: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    /// The wrapper's ESP at PUSHAD time; POPAD never restores it.
    pub esp_wrapper: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
}

const _: () = assert!(core::mem::size_of::<SavedRegisters>() == SAVED_STATE_SIZE as usize);

/// A general-purpose register the x86 wrapper has a saved copy of.
///
/// ESP is deliberately absent: by the time the hook runs it points into the
/// wrapper's frame. A hook that wants the game's stack asks for `esp+0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reg {
    Eax,
    Ecx,
    Edx,
    Ebx,
    Esi,
    Edi,
    Ebp,
}

impl Reg {
    pub const ALL: [Reg; 7] = [
        Reg::Eax,
        Reg::Ecx,
        Reg::Edx,
        Reg::Ebx,
        Reg::Esi,
        Reg::Edi,
        Reg::Ebp,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Reg::Eax => "eax",
            Reg::Ecx => "ecx",
            Reg::Edx => "edx",
            Reg::Ebx => "ebx",
            Reg::Esi => "esi",
            Reg::Edi => "edi",
            Reg::Ebp => "ebp",
        }
    }

    pub fn from_name(name: &str) -> Option<Reg> {
        Reg::ALL.into_iter().find(|r| r.name() == name)
    }

    /// Offset of this register's saved copy from EBX (`kSavedRegisters`).
    pub fn saved_offset(self) -> i32 {
        match self {
            Reg::Edi => 4,
            Reg::Esi => 8,
            Reg::Ebp => 12,
            Reg::Ebx => 20,
            Reg::Edx => 24,
            Reg::Ecx => 28,
            Reg::Eax => 32,
        }
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Register names `exclude_from_restore` can meaningfully name. `"esp"` and
/// `"ebx"` are accepted by KPM but have no effect (ESP is never popped, EBX is
/// always restored).
pub const RESTORABLE_REGISTERS: [&str; 6] = ["eax", "ecx", "edx", "esi", "edi", "ebp"];

/// A `[[hooks.parameters]]` `type`, and how the wrapper fills its 4-byte slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamType {
    /// 32-bit; Rust `i32`.
    Int,
    /// 32-bit; Rust `u32`.
    Uint,
    /// Pointer width (32 bits here); Rust `*mut T` / `usize`.
    Pointer,
    /// Four raw bytes in the slot; Rust `f32` (a cdecl f32 argument is a
    /// plain stack slot).
    Float,
    /// Zero-extended 8-bit (`MOVZX`); Rust `u8`.
    Byte,
    /// Zero-extended 16-bit; Rust `u16`.
    Short,
    /// Sign-extended 8-bit (`MOVSX`); Rust `i8`.
    Sbyte,
    /// Sign-extended 16-bit; Rust `i16`.
    Sshort,
    /// x86_64 only: refused by the 32-bit wrapper.
    Int64,
    /// x86_64 only: refused by the 32-bit wrapper.
    Uint64,
    /// x86_64 only: refused by the 32-bit wrapper.
    Double,
}

impl ParamType {
    /// Case-insensitive, as `config_reader.cpp` (`StrICmp`) and KPatchCore read it.
    pub fn parse(text: &str) -> Option<ParamType> {
        Some(match text.to_ascii_lowercase().as_str() {
            "int" => ParamType::Int,
            "uint" => ParamType::Uint,
            "pointer" => ParamType::Pointer,
            "float" => ParamType::Float,
            "byte" => ParamType::Byte,
            "short" => ParamType::Short,
            "sbyte" => ParamType::Sbyte,
            "sshort" => ParamType::Sshort,
            "int64" => ParamType::Int64,
            "uint64" => ParamType::Uint64,
            "double" => ParamType::Double,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ParamType::Int => "int",
            ParamType::Uint => "uint",
            ParamType::Pointer => "pointer",
            ParamType::Float => "float",
            ParamType::Byte => "byte",
            ParamType::Short => "short",
            ParamType::Sbyte => "sbyte",
            ParamType::Sshort => "sshort",
            ParamType::Int64 => "int64",
            ParamType::Uint64 => "uint64",
            ParamType::Double => "double",
        }
    }

    /// The Rust type a hook function should declare for this slot.
    pub fn rust_type(self) -> &'static str {
        match self {
            ParamType::Int => "i32",
            ParamType::Uint => "u32",
            ParamType::Pointer => "*mut c_void",
            ParamType::Float => "f32",
            ParamType::Byte => "u8",
            ParamType::Short => "u16",
            ParamType::Sbyte => "i8",
            ParamType::Sshort => "i16",
            ParamType::Int64 => "i64",
            ParamType::Uint64 => "u64",
            ParamType::Double => "f64",
        }
    }

    fn is_64_bit_only(self) -> bool {
        matches!(
            self,
            ParamType::Int64 | ParamType::Uint64 | ParamType::Double
        )
    }

    fn is_narrow_or_float(self) -> bool {
        matches!(
            self,
            ParamType::Byte
                | ParamType::Short
                | ParamType::Sbyte
                | ParamType::Sshort
                | ParamType::Float
        )
    }

    /// The widest constant the type can carry on x86 (`ConstantLimit`).
    fn constant_limit(self) -> u64 {
        match self {
            ParamType::Byte | ParamType::Sbyte => 0xFF,
            ParamType::Short | ParamType::Sshort => 0xFFFF,
            ParamType::Int | ParamType::Uint | ParamType::Pointer => 0xFFFF_FFFF,
            ParamType::Float | ParamType::Int64 | ParamType::Uint64 | ParamType::Double => 0,
        }
    }
}

impl fmt::Display for ParamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where a parameter's value comes from, as the x86 wrapper reads `source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamSource {
    /// `"ecx"`: the register's value at the hook site.
    Register(Reg),
    /// `"esp+8"`, `"esp-4"`: the *address* of a slot on the game's stack
    /// (`LEA`), not the value in it. At a function entry hook, `esp+4` is a
    /// pointer to the first stack argument.
    StackAddress(i32),
    /// `"esi+0x10"`: the register's value plus the offset (an address).
    RegisterAddress(Reg, i32),
    /// `"[esp+4]"`: the value stored at that stack slot.
    StackValue(i32),
    /// `"[esi+0x10]"`: the value at register + offset (a field load).
    Dereference(Reg, i32),
    /// `"const:0xBC"`: an immediate, widened per the declared type.
    Constant(u64),
}

/// Why the wrapper would refuse a parameter (the hook is then dropped whole).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamError {
    SixtyFourBitType(ParamType),
    MalformedConstant(String),
    FloatConstant,
    ConstantTooWide { value: u64, ty: ParamType },
    MalformedDereference(String),
    UnsupportedRegister(String),
    MalformedOffset(String),
    AddressAsNarrowType { source: String, ty: ParamType },
    Unsupported(String),
}

impl fmt::Display for ParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamError::SixtyFourBitType(t) => write!(
                f,
                "type {t} needs two stack slots, which the 32-bit wrapper does not pass"
            ),
            ParamError::MalformedConstant(s) => {
                write!(f, "constant parameter is not a number: {s}")
            }
            ParamError::FloatConstant => f.write_str("a constant parameter cannot be a float"),
            ParamError::ConstantTooWide { value, ty } => {
                write!(f, "constant {value:#x} does not fit its declared type {ty}")
            }
            ParamError::MalformedDereference(s) => write!(f, "cannot read a register out of {s}"),
            ParamError::UnsupportedRegister(s) => write!(f, "unsupported register in {s}"),
            ParamError::MalformedOffset(s) => write!(f, "invalid offset in {s}"),
            ParamError::AddressAsNarrowType { source, ty } => write!(
                f,
                "{source} yields an address, so it cannot be read as {ty} (use pointer/int/uint)"
            ),
            ParamError::Unsupported(s) => write!(
                f,
                "unsupported parameter source: {s} (the x86 wrapper reads eax, ecx, edx, ebx, \
                 esi, edi, ebp, each with or without an offset; esp only with an offset)"
            ),
        }
    }
}

impl std::error::Error for ParamError {}

/// `ParseDigits`: decimal, or hex after a `0x`/`0X` prefix (only when at least
/// one character follows it). No sign, no whitespace, no octal.
pub fn parse_digits(text: &str) -> Option<u64> {
    let (digits, radix) = match text.as_bytes() {
        [b'0', b'x' | b'X', _, ..] => (&text[2..], 16),
        _ => (text, 10),
    };
    if digits.is_empty() {
        return None;
    }
    let valid = digits.bytes().all(|c| {
        if radix == 16 {
            c.is_ascii_hexdigit()
        } else {
            c.is_ascii_digit()
        }
    });
    if !valid {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// `ParseSignedOffset`: a required sign, then [`parse_digits`], bounded by
/// [`MAX_OFFSET_MAGNITUDE`].
pub fn parse_signed_offset(text: &str) -> Option<i32> {
    let (negative, rest) = match text.as_bytes().first()? {
        b'+' => (false, &text[1..]),
        b'-' => (true, &text[1..]),
        _ => return None,
    };
    let magnitude = parse_digits(rest)?;
    if magnitude > MAX_OFFSET_MAGNITUDE {
        return None;
    }
    let value = magnitude as i32;
    Some(if negative { -value } else { value })
}

/// The outcome of `ParseConstantSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstantSource {
    None,
    Malformed,
    Parsed(u64),
}

pub fn parse_constant_source(source: &str) -> ConstantSource {
    match source.strip_prefix("const:") {
        None => ConstantSource::None,
        Some(rest) => match parse_digits(rest) {
            Some(v) => ConstantSource::Parsed(v),
            None => ConstantSource::Malformed,
        },
    }
}

/// `SplitRegisterOffset`: `"esi+0x10"` -> (`esi`, 16); `"eax"` -> (`eax`, 0).
fn split_register_offset(text: &str) -> Option<(&str, i32)> {
    let sign = text.find(['+', '-']);
    let name = &text[..sign.unwrap_or(text.len())];
    if name.is_empty() {
        return None;
    }
    match sign {
        None => Some((name, 0)),
        Some(at) => parse_signed_offset(&text[at..]).map(|off| (name, off)),
    }
}

fn widen_constant(value: u64, ty: ParamType) -> u64 {
    match ty {
        ParamType::Sbyte => (value as u8 as i8 as i32 as u32) as u64,
        ParamType::Sshort => (value as u16 as i16 as i32 as u32) as u64,
        _ => value,
    }
}

impl ParamSource {
    /// Parse `source` exactly as `ExtractAndPushParameter` in `wrapper_x86.cpp`
    /// does, for a parameter declared as `ty`. The text is trimmed and
    /// lowercased first (KPatchCore trims before writing `patch_config.toml`;
    /// the wrapper lowercases).
    pub fn parse(source: &str, ty: ParamType) -> Result<ParamSource, ParamError> {
        let source = source.trim().to_ascii_lowercase();

        if ty.is_64_bit_only() {
            return Err(ParamError::SixtyFourBitType(ty));
        }

        match parse_constant_source(&source) {
            ConstantSource::Malformed => return Err(ParamError::MalformedConstant(source)),
            ConstantSource::Parsed(value) => {
                if ty == ParamType::Float {
                    return Err(ParamError::FloatConstant);
                }
                if value > ty.constant_limit() {
                    return Err(ParamError::ConstantTooWide { value, ty });
                }
                return Ok(ParamSource::Constant(widen_constant(value, ty)));
            }
            ConstantSource::None => {}
        }

        if let Some(reg) = Reg::from_name(&source) {
            return Ok(ParamSource::Register(reg));
        }

        // Bracketed: a dereference.
        if source.len() > 2 && source.starts_with('[') && source.ends_with(']') {
            let inner = &source[1..source.len() - 1];
            let Some((name, offset)) = split_register_offset(inner) else {
                return Err(ParamError::MalformedDereference(source));
            };
            if name == "esp" {
                return Ok(ParamSource::StackValue(offset));
            }
            return match Reg::from_name(name) {
                Some(reg) => Ok(ParamSource::Dereference(reg, offset)),
                None => Err(ParamError::UnsupportedRegister(source)),
            };
        }

        // Signed: an address.
        if source.contains(['+', '-']) {
            let Some((name, offset)) = split_register_offset(&source) else {
                return Err(ParamError::MalformedOffset(source));
            };
            if ty.is_narrow_or_float() {
                return Err(ParamError::AddressAsNarrowType { source, ty });
            }
            if name == "esp" {
                return Ok(ParamSource::StackAddress(offset));
            }
            if let Some(reg) = Reg::from_name(name) {
                return Ok(ParamSource::RegisterAddress(reg, offset));
            }
        }

        Err(ParamError::Unsupported(source))
    }

    /// A one-line description of what the hook function receives.
    pub fn describe(&self) -> String {
        match *self {
            ParamSource::Register(r) => format!("value of {r}"),
            ParamSource::StackAddress(o) => {
                format!("address of game stack slot esp{}", signed_hex(o))
            }
            ParamSource::RegisterAddress(r, o) => format!("{r}{} (an address)", signed_hex(o)),
            ParamSource::StackValue(o) => format!("value at [esp{}]", signed_hex(o)),
            ParamSource::Dereference(r, o) => format!("value at [{r}{}]", signed_hex(o)),
            ParamSource::Constant(v) => format!("constant {v:#x}"),
        }
    }
}

/// `+0x10` / `-0x8`.
fn signed_hex(value: i32) -> String {
    if value < 0 {
        format!("-{:#x}", value.unsigned_abs())
    } else {
        format!("+{value:#x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_follow_kpm() {
        assert_eq!(parse_digits("0"), Some(0));
        assert_eq!(parse_digits("010"), Some(10));
        assert_eq!(parse_digits("0xBC"), Some(188));
        assert_eq!(parse_digits("0X10"), Some(16));
        assert_eq!(parse_digits("0x"), None);
        assert_eq!(parse_digits(""), None);
        assert_eq!(parse_digits(" 5"), None);
        assert_eq!(parse_digits("-1"), None);
        assert_eq!(parse_digits("18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_digits("18446744073709551616"), None);
    }

    #[test]
    fn offsets_follow_kpm() {
        assert_eq!(parse_signed_offset("+0x7FFF0000"), Some(0x7FFF_0000));
        assert_eq!(parse_signed_offset("-0x10"), Some(-16));
        assert_eq!(parse_signed_offset("+0x7FFF0001"), None);
        assert_eq!(parse_signed_offset("8"), None);
        assert_eq!(parse_signed_offset("+-8"), None);
        assert_eq!(parse_signed_offset("+0x0x10"), None);
    }

    #[test]
    fn sources() {
        use ParamSource::*;
        let p = |s| ParamSource::parse(s, ParamType::Pointer);
        assert_eq!(p("ecx"), Ok(Register(Reg::Ecx)));
        assert_eq!(p(" ECX "), Ok(Register(Reg::Ecx)));
        assert_eq!(p("esp+4"), Ok(StackAddress(4)));
        assert_eq!(p("esp-564"), Ok(StackAddress(-564)));
        assert_eq!(p("esi+0x10"), Ok(RegisterAddress(Reg::Esi, 16)));
        assert_eq!(p("[esp+4]"), Ok(StackValue(4)));
        assert_eq!(p("[eax]"), Ok(Dereference(Reg::Eax, 0)));
        assert_eq!(p("const:0xBC"), Ok(Constant(188)));
        assert!(matches!(p("esp"), Err(ParamError::Unsupported(_))));
        assert!(matches!(
            p("[esx+4]"),
            Err(ParamError::UnsupportedRegister(_))
        ));
        assert!(matches!(p("[]"), Err(ParamError::Unsupported(_))));
        assert!(matches!(
            p("[+4]"),
            Err(ParamError::MalformedDereference(_))
        ));
        assert!(matches!(p("esp+zz"), Err(ParamError::MalformedOffset(_))));
        assert!(matches!(
            ParamSource::parse("esp+4", ParamType::Byte),
            Err(ParamError::AddressAsNarrowType { .. })
        ));
        assert_eq!(
            ParamSource::parse("[esp+4]", ParamType::Byte),
            Ok(StackValue(4))
        );
        assert!(matches!(
            ParamSource::parse("eax", ParamType::Double),
            Err(ParamError::SixtyFourBitType(_))
        ));
        assert!(matches!(
            ParamSource::parse("const:256", ParamType::Byte),
            Err(ParamError::ConstantTooWide { .. })
        ));
        assert_eq!(
            ParamSource::parse("const:0xFF", ParamType::Sbyte),
            Ok(Constant(0xFFFF_FFFF))
        );
        assert!(matches!(
            ParamSource::parse("const:1", ParamType::Float),
            Err(ParamError::FloatConstant)
        ));
    }

    #[test]
    fn saved_block_is_where_esp_minus_564_points() {
        assert_eq!(SAVED_STATE_FROM_GAME_ESP, 564);
        assert_eq!(
            ParamSource::parse(SAVED_REGISTERS_SOURCE, ParamType::Pointer),
            Ok(ParamSource::StackAddress(-SAVED_STATE_FROM_GAME_ESP))
        );
        assert_eq!(
            core::mem::offset_of!(SavedRegisters, eax),
            Reg::Eax.saved_offset() as usize
        );
        assert_eq!(
            core::mem::offset_of!(SavedRegisters, edi),
            Reg::Edi.saved_offset() as usize
        );
        assert_eq!(
            core::mem::offset_of!(SavedRegisters, ebx),
            Reg::Ebx.saved_offset() as usize
        );
    }

    /// The grammar files KPM keeps so its two parsers cannot drift; read here
    /// too when the submodule is checked out.
    #[test]
    fn kpm_grammar_tables() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../third_party/Kotor-Patch-Manager/src/KotorPatcher/tests");
        let Ok(constants) = std::fs::read_to_string(dir.join("constant-sources.tsv")) else {
            eprintln!("KPM submodule not checked out; skipping");
            return;
        };
        let offsets = std::fs::read_to_string(dir.join("signed-offsets.tsv")).unwrap();
        let rows = |text: &str| -> Vec<(String, String, String)> {
            text.lines()
                .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                .map(|l| {
                    let mut parts = l.split('\t');
                    (
                        parts.next().unwrap().to_string(),
                        parts.next().unwrap().to_string(),
                        parts.next().unwrap_or("-").to_string(),
                    )
                })
                .collect()
        };
        let mut checked = 0;
        for (source, outcome, value) in rows(&constants) {
            let got = parse_constant_source(&source);
            let want = match outcome.as_str() {
                "parsed" => ConstantSource::Parsed(value.parse().unwrap()),
                "malformed" => ConstantSource::Malformed,
                _ => ConstantSource::None,
            };
            assert_eq!(got, want, "constant {source:?}");
            checked += 1;
        }
        for (text, outcome, value) in rows(&offsets) {
            let got = parse_signed_offset(&text);
            let want = (outcome == "parsed").then(|| value.parse::<i32>().unwrap());
            assert_eq!(got, want, "offset {text:?}");
            checked += 1;
        }
        assert!(checked > 40);
    }
}
