//! Host-side tools for KOTOR Patch Manager patches: verify hooks against an
//! executable, disassemble and search it, and package a `.kpatch`.
//! The `kpm-tool` binary is a thin CLI over these modules.

pub mod find;
pub mod known;
pub mod pack;
pub mod pe;
pub mod sources;
pub mod testpe;
pub mod verify;
pub mod x86;

/// Parse a VA: hexadecimal, with or without `0x`, `_` separators allowed.
pub fn parse_va(text: &str) -> Result<u64, String> {
    let t = text.trim().replace('_', "");
    let digits = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(&t);
    u64::from_str_radix(digits, 16).map_err(|_| format!("{text:?} is not a hexadecimal address"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn va() {
        assert_eq!(super::parse_va("0x00401234"), Ok(0x401234));
        assert_eq!(super::parse_va("0040_1234"), Ok(0x401234));
        assert!(super::parse_va("zz").is_err());
    }
}
