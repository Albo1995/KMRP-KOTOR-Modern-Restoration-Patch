//! Facts about the game process a patch module runs in.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The environment variable KPM's runtime sets to `target_version_sha` from
/// `patch_config.toml` before it loads any patch module (`patcher.cpp`).
pub const KOTOR_VERSION_SHA_ENV: &str = "KOTOR_VERSION_SHA";

/// The SHA-256 KPM's installer recorded for this game's executable, if the
/// runtime set [`KOTOR_VERSION_SHA_ENV`]. Cheap: no hashing.
pub fn kotor_version_sha() -> Option<String> {
    std::env::var(KOTOR_VERSION_SHA_ENV)
        .ok()
        .filter(|s| !s.is_empty())
}

/// Path of the process's main module (`GetModuleFileNameW(NULL)` on Windows;
/// under Proton, a Windows path such as `Z:\...\swkotor2.exe`).
pub fn main_module_path() -> io::Result<PathBuf> {
    std::env::current_exe()
}

/// The folder holding the main module: the game folder.
pub fn game_dir() -> io::Result<PathBuf> {
    let exe = main_module_path()?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "main module has no parent"))
}

/// SHA-256 of a file, streamed.
pub fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// SHA-256 of a byte slice.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Uppercase hex, the form KPM's version tables use.
pub fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02X}");
            s
        })
}

/// SHA-256 (uppercase hex) of the main module's file on disk. This is the
/// hash KPM matches against `supported_versions`/`target_versions`. Reads the
/// whole executable (~6 MB for swkotor2.exe), so call it off the loader lock.
pub fn main_module_sha256() -> io::Result<String> {
    Ok(hex_upper(&sha256_file(&main_module_path()?)?))
}

/// Base address of the main module (`GetModuleHandleW(NULL)`).
#[cfg(windows)]
pub fn main_module_base() -> usize {
    unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(core::ptr::null()) as usize
    }
}

/// Milliseconds since this process was created (`GetProcessTimes`).
#[cfg(windows)]
pub fn process_uptime_ms() -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let ticks = |f: FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
    unsafe {
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        if GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        ) == 0
        {
            return None;
        }
        let mut now = zero;
        GetSystemTimeAsFileTime(&mut now);
        ticks(now).checked_sub(ticks(created)).map(|t| t / 10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing() {
        // SHA-256("abc")
        assert_eq!(
            hex_upper(&sha256(b"abc")),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        let exe = main_module_path().unwrap();
        assert_eq!(
            hex_upper(&sha256_file(&exe).unwrap()),
            hex_upper(&sha256(&std::fs::read(&exe).unwrap()))
        );
        assert!(game_dir().unwrap().is_dir());
    }
}
