//! 32-bit x86 decoding (iced-x86): instruction boundaries, relative
//! branches, and register use.

use std::collections::BTreeSet;

use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, InstructionInfoFactory, IntelFormatter,
    OpAccess, OpKind,
};

#[derive(Debug, Clone)]
pub struct Insn {
    pub va: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    /// A branch whose target is encoded relative to the instruction
    /// (`call rel32`, `jmp rel8/rel32`, `jcc`, `loop`, `jecxz`).
    pub relative_target: Option<u64>,
    pub invalid: bool,
}

impl Insn {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn hex(&self) -> String {
        hex(&self.bytes)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn formatter() -> IntelFormatter {
    let mut f = IntelFormatter::new();
    let o = f.options_mut();
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(true);
    o.set_space_after_operand_separator(true);
    o.set_show_branch_size(false);
    o.set_small_hex_numbers_in_decimal(false);
    f
}

fn relative_target(instr: &Instruction) -> Option<u64> {
    (0..instr.op_count()).find_map(|i| match instr.op_kind(i) {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instr.near_branch_target())
        }
        _ => None,
    })
}

/// Decode up to `max` instructions from `bytes`, which start at `va`. Stops
/// early at the end of the bytes; an undecodable or truncated instruction is
/// returned with `invalid = true` and decoding stops after it.
pub fn decode(bytes: &[u8], va: u64, max: usize) -> Vec<Insn> {
    let mut decoder = Decoder::with_ip(32, bytes, va, DecoderOptions::NONE);
    let mut f = formatter();
    let mut out = Vec::new();
    let mut instr = Instruction::default();
    while decoder.can_decode() && out.len() < max {
        let start = (decoder.ip() - va) as usize;
        decoder.decode_out(&mut instr);
        let len = instr.len().max(1);
        let end = (start + len).min(bytes.len());
        let invalid = instr.is_invalid();
        let mut text = String::new();
        if invalid {
            text.push_str("(bad or truncated)");
        } else {
            f.format(&instr, &mut text);
        }
        out.push(Insn {
            va: va + start as u64,
            bytes: bytes[start..end].to_vec(),
            text,
            relative_target: if invalid {
                None
            } else {
                relative_target(&instr)
            },
            invalid,
        });
        if invalid {
            break;
        }
    }
    out
}

/// Whether `[va, va+len)` covers whole instructions, decoding from `va`.
#[derive(Debug, Clone)]
pub enum Boundary {
    /// The range is exactly these instructions.
    Exact(Vec<Insn>),
    /// The last instruction starts inside the range and ends past it.
    Split {
        covered: Vec<Insn>,
        straddling: Insn,
    },
    /// Something in the range does not decode.
    Invalid { covered: Vec<Insn>, at: u64 },
}

/// `bytes` start at `va` and should extend past `len` (up to 15 bytes) so the
/// instruction straddling the end can be decoded whole.
pub fn boundary(bytes: &[u8], va: u64, len: usize) -> Boundary {
    let mut covered = Vec::new();
    let mut at = 0usize;
    for insn in decode(bytes, va, usize::MAX) {
        if insn.invalid {
            return Boundary::Invalid {
                covered,
                at: insn.va,
            };
        }
        let next = at + insn.len();
        if next > len {
            return Boundary::Split {
                covered,
                straddling: insn,
            };
        }
        covered.push(insn);
        at = next;
        if at == len {
            return Boundary::Exact(covered);
        }
    }
    Boundary::Invalid {
        covered,
        at: va + at as u64,
    }
}

/// Registers (by 32-bit family name: `eax`, `esp`, ...) the instructions
/// read and write, implicit operands and memory-address registers included.
pub fn register_use(bytes: &[u8], va: u64) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut decoder = Decoder::with_ip(32, bytes, va, DecoderOptions::NONE);
    let mut factory = InstructionInfoFactory::new();
    let (mut reads, mut writes) = (BTreeSet::new(), BTreeSet::new());
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        for used in factory.info(&instr).used_registers() {
            let reg = used.register();
            let full = reg.full_register32();
            if !full.is_gpr32() {
                continue;
            }
            let name = format!("{full:?}").to_ascii_lowercase();
            match used.access() {
                OpAccess::Read | OpAccess::CondRead => {
                    reads.insert(name);
                }
                OpAccess::Write | OpAccess::CondWrite => {
                    writes.insert(name);
                }
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    reads.insert(name.clone());
                    writes.insert(name);
                }
                _ => {}
            }
        }
    }
    (reads, writes)
}

/// Join instruction texts as `mov eax, [esp+8] ; test eax, eax`.
pub fn join(insns: &[Insn]) -> String {
    insns
        .iter()
        .map(|i| i.text.as_str())
        .collect::<Vec<_>>()
        .join(" ; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries() {
        // mov eax,[esp+8] ; test eax,eax ; push ebp
        let code = [0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0, 0x55];
        assert!(matches!(boundary(&code, 0x401000, 6), Boundary::Exact(v) if v.len() == 2));
        match boundary(&code, 0x401000, 5) {
            Boundary::Split {
                covered,
                straddling,
            } => {
                assert_eq!(covered.len(), 1);
                assert_eq!(straddling.va, 0x401004);
                assert_eq!(straddling.len(), 2);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn relative_branches_and_registers() {
        // call rel32 (to 0x401000+5+0x10) ; push 0
        let code = [0xE8, 0x10, 0x00, 0x00, 0x00, 0x6A, 0x00];
        let insns = decode(&code, 0x401000, 10);
        assert_eq!(insns[0].relative_target, Some(0x401015));
        assert_eq!(insns[1].relative_target, None);
        let (reads, writes) = register_use(&[0x6A, 0x00], 0);
        assert!(reads.contains("esp") && writes.contains("esp"));
        let (reads, _) = register_use(&[0x8A, 0x45, 0x08], 0); // mov al,[ebp+8]
        assert!(reads.contains("ebp"));
        let (_, writes) = register_use(&[0x8A, 0x45, 0x08], 0);
        assert!(writes.contains("eax"));
    }
}
