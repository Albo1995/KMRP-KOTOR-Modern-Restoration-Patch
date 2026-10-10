//! `kmrp2-hello`: the smallest useful KOTOR Patch Manager patch module for
//! `swkotor2.exe`, built with `kpm-sdk`.
//!
//! On `DLL_PROCESS_ATTACH` it records the load time and starts a thread that
//! appends to `kmrp2.log` in the game folder: the time, the process uptime,
//! the main module's path, base and SHA-256, and KPM's `KOTOR_VERSION_SHA`.
//! It also exports one example detour, [`Kmrp2ExampleDetour`], which no
//! hook uses yet: `patch/kmrp2-hello.hooks.toml` carries it commented out,
//! with its address left as a TODO, so the packaged patch installs as a
//! DLL-only patch (KPM loads the module and applies no hooks).

use std::sync::atomic::{AtomicU32, Ordering};

use kpm_sdk::{c_void, kpm_log};

/// The log file, in the game folder.
pub const LOG_FILE: &str = "kmrp2.log";

static EXAMPLE_CALLS: AtomicU32 = AtomicU32::new(0);

kpm_sdk::detour! {
    /// Example detour for a `__thiscall` member function's entry.
    ///
    /// Declared in hooks.toml (commented out there until a site is found) as
    /// `function = "Kmrp2ExampleDetour"` with two parameters:
    /// `source = "ecx", type = "pointer"` (the object) and
    /// `source = "esp+4", type = "pointer"` (the *address* of the first
    /// stack argument; at a function's first instruction `[esp]` is the
    /// return address). It logs its first five calls and returns 0; since
    /// "eax" is not excluded from restore, the return value is discarded
    /// and the game's own code runs on unchanged.
    fn Kmrp2ExampleDetour(this: *mut c_void, first_arg_slot: *const u32) -> i32 {
        let n = EXAMPLE_CALLS.fetch_add(1, Ordering::Relaxed);
        if n < 5 {
            #[cfg(windows)]
            let first = kpm_sdk::mem::try_read::<u32>(first_arg_slot as usize);
            #[cfg(not(windows))]
            let first: Option<u32> = None;
            kpm_log!(
                "Kmrp2ExampleDetour call {}: this={:p} first stack argument={}",
                n + 1,
                this,
                first.map_or("unreadable".to_string(), |v| format!("{v:#010X}"))
            );
        }
        0
    }
}

/// What gets logged once the module is loaded. Separate from `DllMain` so
/// it can run on the host in tests.
pub fn startup_report(load_time: std::time::SystemTime, uptime_ms: Option<u64>) -> Vec<String> {
    use kpm_sdk::process;
    let mut lines = vec![format!(
        "kmrp2-hello {} loaded at {}{}",
        env!("CARGO_PKG_VERSION"),
        kpm_sdk::log::timestamp(load_time),
        uptime_ms.map_or(String::new(), |ms| format!(
            " ({ms} ms after the process started)"
        ))
    )];
    match process::main_module_path() {
        Ok(p) => lines.push(format!("main module: {}", p.display())),
        Err(e) => lines.push(format!("main module path unavailable: {e}")),
    }
    #[cfg(windows)]
    lines.push(format!(
        "main module base: {:#010X}",
        process::main_module_base()
    ));
    let measured = process::main_module_sha256();
    match &measured {
        Ok(sha) => lines.push(format!("main module SHA-256: {sha}")),
        Err(e) => lines.push(format!("main module SHA-256 unavailable: {e}")),
    }
    match (process::kotor_version_sha(), &measured) {
        (None, _) => lines.push(format!(
            "{} not set (not loaded by KPM's runtime?)",
            process::KOTOR_VERSION_SHA_ENV
        )),
        (Some(kpm), Ok(sha)) if kpm.eq_ignore_ascii_case(sha) => {
            lines.push(format!("{} matches", process::KOTOR_VERSION_SHA_ENV))
        }
        (Some(kpm), _) => lines.push(format!(
            "{} = {kpm} DIFFERS from the file on disk",
            process::KOTOR_VERSION_SHA_ENV
        )),
    }
    lines
}

#[cfg(windows)]
mod entry {
    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{HINSTANCE, TRUE};
    use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
    use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

    fn on_attach() {
        let load_time = std::time::SystemTime::now();
        let uptime = kpm_sdk::process::process_uptime_ms();
        kpm_sdk::log::init(super::LOG_FILE);
        kpm_sdk::log::install_panic_logger();
        // Hashing reads the whole executable: do it off the loader lock.
        let spawned = std::thread::Builder::new()
            .name("kmrp2-hello".into())
            .spawn(move || {
                kpm_sdk::ffi_guard("kmrp2-hello startup", || {
                    for line in super::startup_report(load_time, uptime) {
                        kpm_sdk::log::line(&line);
                    }
                })
            });
        if let Err(e) = spawned {
            kpm_sdk::kpm_log!("kmrp2-hello: could not start its thread: {e}");
        }
    }

    /// The DLL entry point (stdcall `DllMain@12`, called by MinGW's
    /// `DllMainCRTStartup`).
    #[no_mangle]
    #[allow(non_snake_case)]
    pub extern "system" fn DllMain(
        module: HINSTANCE,
        reason: u32,
        _reserved: *mut core::ffi::c_void,
    ) -> BOOL {
        if reason == DLL_PROCESS_ATTACH {
            kpm_sdk::ffi_guard("DllMain", || {
                unsafe { DisableThreadLibraryCalls(module) };
                on_attach();
            });
        }
        TRUE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_has_a_hash() {
        let lines = startup_report(std::time::SystemTime::now(), Some(12));
        assert!(lines[0].contains("12 ms after"));
        assert!(lines.iter().any(|l| l.starts_with("main module SHA-256: ")));
    }

    #[test]
    fn example_detour_returns_zero() {
        let arg = 0xDEADu32;
        let r = unsafe { Kmrp2ExampleDetour(core::ptr::null_mut(), &arg) };
        assert_eq!(r, 0);
    }
}
