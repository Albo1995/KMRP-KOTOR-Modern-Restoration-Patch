//! Frame capture for testing: saves the game's back buffer at its true
//! resolution, independent of gamescope or the desktop.
//!
//! The module replaces `swkotor2.exe`'s import of `GDI32!SwapBuffers`. Every
//! [`POLL_FRAMES`] frames the hook looks for [`REQUEST_FILE`] in the game
//! folder. When it is there, the hook deletes it, reads the back buffer with
//! `glReadPixels` before the swap, and writes `kmrp2-shot-<name>.tga` (32-bit
//! BGRA, bottom-left origin, which is OpenGL's row order). The request file's
//! first line, if any, names the shot; otherwise shots are numbered. Each
//! capture and each change of viewport size is logged.

#[cfg(windows)]
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// Created by the tester to ask for a capture.
pub const REQUEST_FILE: &str = "kmrp2-capture.request";

/// How often, in frames, the request file is looked for.
pub const POLL_FRAMES: u32 = 15;

/// A TGA header for an uncompressed 32-bit image, bottom-left origin.
pub fn tga_header(width: u16, height: u16) -> [u8; 18] {
    let mut h = [0u8; 18];
    h[2] = 2; // uncompressed true-colour
    h[12..14].copy_from_slice(&width.to_le_bytes());
    h[14..16].copy_from_slice(&height.to_le_bytes());
    h[16] = 32;
    h[17] = 8; // 8 alpha bits, origin bottom-left
    h
}

/// The file name for a capture: the request's first line reduced to safe
/// characters, or a sequence number.
pub fn shot_name(request: &str, seq: u32) -> String {
    let stem: String = request
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if stem.is_empty() {
        format!("kmrp2-shot-{seq:03}.tga")
    } else {
        format!("kmrp2-shot-{stem}.tga")
    }
}

#[cfg(windows)]
static ORIGINAL_SWAP: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static FRAMES: AtomicU32 = AtomicU32::new(0);
#[cfg(windows)]
static SHOTS: AtomicU32 = AtomicU32::new(0);
#[cfg(windows)]
static LAST_SIZE: AtomicU32 = AtomicU32::new(0);

#[cfg(windows)]
mod imp {
    use super::*;
    use kpm_sdk::kpm_log;
    use windows_sys::Win32::Graphics::Gdi::HDC;
    use windows_sys::Win32::Graphics::OpenGL::{
        glGetIntegerv, glPixelStorei, glReadBuffer, glReadPixels, GL_BACK, GL_PACK_ALIGNMENT,
        GL_UNSIGNED_BYTE, GL_VIEWPORT,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_READWRITE};

    const GL_BGRA: u32 = 0x80E1;

    type SwapFn = unsafe extern "system" fn(HDC) -> i32;

    unsafe fn rd32(addr: usize) -> u32 {
        core::ptr::read_unaligned(addr as *const u32)
    }

    unsafe fn cstr_eq_ignore_case(addr: usize, want: &str) -> bool {
        let p = addr as *const u8;
        for (i, w) in want.bytes().enumerate() {
            if !(*p.add(i)).eq_ignore_ascii_case(&w) {
                return false;
            }
        }
        *p.add(want.len()) == 0
    }

    /// Finds the IAT slot of `dll!func` (imported by name) in the main module.
    unsafe fn find_iat_slot(dll: &str, func: &str) -> Option<usize> {
        let base = GetModuleHandleW(core::ptr::null()) as usize;
        if base == 0 {
            return None;
        }
        let nt = base + rd32(base + 0x3C) as usize;
        // Optional header at nt+0x18; PE32 data directory 1 (imports) at +0x68.
        let import_rva = rd32(nt + 0x18 + 0x68) as usize;
        if import_rva == 0 {
            return None;
        }
        let mut desc = base + import_rva;
        loop {
            let name_rva = rd32(desc + 12) as usize;
            if name_rva == 0 {
                return None;
            }
            if cstr_eq_ignore_case(base + name_rva, dll) {
                let names = rd32(desc) as usize; // OriginalFirstThunk
                let iat = rd32(desc + 16) as usize; // FirstThunk
                let lookup = if names != 0 { names } else { iat };
                let mut i = 0usize;
                loop {
                    let entry = rd32(base + lookup + i * 4);
                    if entry == 0 {
                        return None;
                    }
                    if entry & 0x8000_0000 == 0
                        && cstr_eq_ignore_case(base + entry as usize + 2, func)
                    {
                        return Some(base + iat + i * 4);
                    }
                    i += 1;
                }
            }
            desc += 20;
        }
    }

    unsafe fn capture(request: &str) {
        let mut vp = [0i32; 4];
        glGetIntegerv(GL_VIEWPORT, vp.as_mut_ptr());
        let (w, h) = (vp[2].max(0) as usize, vp[3].max(0) as usize);
        if w == 0 || h == 0 || w > 16384 || h > 16384 {
            kpm_log!("capture: bad viewport {:?}", vp);
            return;
        }
        let mut pixels = vec![0u8; w * h * 4];
        glReadBuffer(GL_BACK);
        glPixelStorei(GL_PACK_ALIGNMENT, 1);
        glReadPixels(
            0,
            0,
            w as i32,
            h as i32,
            GL_BGRA,
            GL_UNSIGNED_BYTE,
            pixels.as_mut_ptr().cast(),
        );
        // Opaque alpha, so viewers do not show the frame as transparent.
        for px in pixels.chunks_exact_mut(4) {
            px[3] = 0xFF;
        }
        let seq = SHOTS.fetch_add(1, Ordering::Relaxed) + 1;
        let name = shot_name(request, seq);
        let mut data = Vec::with_capacity(18 + pixels.len());
        data.extend_from_slice(&tga_header(w as u16, h as u16));
        data.extend_from_slice(&pixels);
        match std::fs::write(&name, &data) {
            Ok(()) => kpm_log!(
                "capture: wrote {name} ({w}x{h}, frame {})",
                FRAMES.load(Ordering::Relaxed)
            ),
            Err(e) => kpm_log!("capture: could not write {name}: {e}"),
        }
    }

    unsafe extern "system" fn swap_hook(hdc: HDC) -> i32 {
        let frame = FRAMES.fetch_add(1, Ordering::Relaxed);
        if frame % POLL_FRAMES == 0 {
            kpm_sdk::ffi_guard("capture poll", || {
                let mut vp = [0i32; 4];
                glGetIntegerv(GL_VIEWPORT, vp.as_mut_ptr());
                let size = ((vp[2] as u32) << 16) | (vp[3] as u32 & 0xFFFF);
                if LAST_SIZE.swap(size, Ordering::Relaxed) != size {
                    kpm_log!("capture: viewport now {}x{} at frame {frame}", vp[2], vp[3]);
                }
                if let Ok(request) = std::fs::read_to_string(REQUEST_FILE) {
                    let _ = std::fs::remove_file(REQUEST_FILE);
                    capture(&request);
                }
            });
        }
        let original: SwapFn = core::mem::transmute(ORIGINAL_SWAP.load(Ordering::Relaxed));
        original(hdc)
    }

    /// Replaces the exe's `GDI32!SwapBuffers` import with the capture hook.
    pub fn install() {
        unsafe {
            let Some(slot) = find_iat_slot("GDI32.dll", "SwapBuffers") else {
                kpm_log!("capture: GDI32!SwapBuffers import not found; capture disabled");
                return;
            };
            let mut old = 0u32;
            if VirtualProtect(slot as *const _, 4, PAGE_READWRITE, &mut old) == 0 {
                kpm_log!("capture: VirtualProtect failed on the import slot; capture disabled");
                return;
            }
            ORIGINAL_SWAP.store(rd32(slot) as usize, Ordering::Relaxed);
            core::ptr::write_unaligned(slot as *mut u32, swap_hook as SwapFn as usize as u32);
            VirtualProtect(slot as *const _, 4, old, &mut old);
            kpm_log!(
                "capture: SwapBuffers hooked at import slot {slot:#010X}; create {REQUEST_FILE} in the game folder to save a frame"
            );
        }
    }
}

#[cfg(windows)]
pub use imp::install;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_32bit_bottom_left() {
        let h = tga_header(3840, 2160);
        assert_eq!(h[2], 2);
        assert_eq!(u16::from_le_bytes([h[12], h[13]]), 3840);
        assert_eq!(u16::from_le_bytes([h[14], h[15]]), 2160);
        assert_eq!((h[16], h[17]), (32, 8));
    }

    #[test]
    fn names_are_sanitised() {
        assert_eq!(shot_name("main menu/../x\n", 4), "kmrp2-shot-mainmenux.tga");
        assert_eq!(shot_name("", 7), "kmrp2-shot-007.tga");
        assert_eq!(shot_name("options-4k", 1), "kmrp2-shot-options-4k.tga");
    }
}
