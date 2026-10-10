//! Reading and writing game memory by virtual address.
//!
//! `swkotor2.exe` has no relocation table worth relying on and loads at its
//! preferred base (0x00400000), so a VA from the disassembly is the address at
//! run time. The raw functions ([`read`], [`write`], [`read_bytes`]) are
//! `unsafe` and do no checking; the `try_*` functions (Windows only) first ask
//! `VirtualQuery` whether the whole range is committed and accessible, so a
//! stale pointer yields `None` instead of an access violation. That check is
//! not atomic with the access -- another thread could unmap the page in
//! between -- but for the game's heap and image it is the practical guard.

/// Read a `T` at `va` (unaligned is fine).
///
/// # Safety
/// `va..va+size_of::<T>()` must be readable and hold a valid `T`.
#[inline]
pub unsafe fn read<T: Copy>(va: usize) -> T {
    unsafe { core::ptr::read_unaligned(va as *const T) }
}

/// Write a `T` at `va` (unaligned is fine). Does not change page protection:
/// use [`write_code`] for code or read-only data.
///
/// # Safety
/// `va..va+size_of::<T>()` must be writable.
#[inline]
pub unsafe fn write<T: Copy>(va: usize, value: T) {
    unsafe { core::ptr::write_unaligned(va as *mut T, value) }
}

/// Copy `len` bytes from `va`.
///
/// # Safety
/// The range must be readable.
pub unsafe fn read_bytes(va: usize, len: usize) -> Vec<u8> {
    unsafe { core::slice::from_raw_parts(va as *const u8, len).to_vec() }
}

/// Follow a pointer chain: `base`, then for each offset `p = *(p) + offset`.
/// `deref_chain(G, &[0x10, 0x4])` is `*(*(G) + 0x10) + 0x4`, the address of
/// the field. Returns `None` on a null link.
///
/// # Safety
/// Every link must be readable (see [`try_deref_chain`] for a checked one).
pub unsafe fn deref_chain(base: usize, offsets: &[usize]) -> Option<usize> {
    let mut p = base;
    for off in offsets {
        let next: u32 = unsafe { read(p) };
        if next == 0 {
            return None;
        }
        p = (next as usize).wrapping_add(*off);
    }
    Some(p)
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    use windows_sys::Win32::System::Memory::{
        VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
        PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    fn range_ok(va: usize, len: usize, ok: impl Fn(u32) -> bool) -> bool {
        if va == 0 {
            return false;
        }
        let Some(end) = va.checked_add(len.max(1)) else {
            return false;
        };
        let mut at = va;
        while at < end {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
            let got = unsafe {
                VirtualQuery(
                    at as *const _,
                    &mut info,
                    core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if got == 0 || info.State != MEM_COMMIT {
                return false;
            }
            let protect = info.Protect;
            if protect & (PAGE_GUARD | PAGE_NOACCESS) != 0 || !ok(protect & 0xFF) {
                return false;
            }
            let region_end = (info.BaseAddress as usize).saturating_add(info.RegionSize);
            if region_end <= at {
                return false;
            }
            at = region_end;
        }
        true
    }

    pub fn is_readable(va: usize, len: usize) -> bool {
        range_ok(va, len, |p| {
            matches!(
                p,
                PAGE_READONLY
                    | PAGE_READWRITE
                    | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY
            )
        })
    }

    pub fn is_writable(va: usize, len: usize) -> bool {
        range_ok(va, len, |p| {
            matches!(
                p,
                PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            )
        })
    }

    pub fn is_executable(va: usize, len: usize) -> bool {
        range_ok(va, len, |p| {
            matches!(
                p,
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            )
        })
    }

    pub unsafe fn write_code(va: usize, bytes: &[u8]) -> Result<(), u32> {
        let mut old = 0u32;
        if unsafe {
            VirtualProtect(
                va as *const _,
                bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )
        } == 0
        {
            return Err(unsafe { windows_sys::Win32::Foundation::GetLastError() });
        }
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), va as *mut u8, bytes.len()) };
        let mut ignored = 0u32;
        unsafe {
            VirtualProtect(va as *const _, bytes.len(), old, &mut ignored);
            FlushInstructionCache(GetCurrentProcess(), va as *const _, bytes.len());
        }
        Ok(())
    }
}

/// Whether `[va, va+len)` is committed, readable memory.
#[cfg(windows)]
pub fn is_readable(va: usize, len: usize) -> bool {
    win::is_readable(va, len)
}

/// Whether `[va, va+len)` is committed, writable memory.
#[cfg(windows)]
pub fn is_writable(va: usize, len: usize) -> bool {
    win::is_writable(va, len)
}

/// Whether `[va, va+len)` is committed, executable memory.
#[cfg(windows)]
pub fn is_executable(va: usize, len: usize) -> bool {
    win::is_executable(va, len)
}

/// Read a `T` at `va` if the range is readable. Any bit pattern must be a
/// valid `T` (integers, floats, raw pointers, `#[repr(C)]` structs of them).
#[cfg(windows)]
pub fn try_read<T: Copy>(va: usize) -> Option<T> {
    if is_readable(va, core::mem::size_of::<T>()) {
        Some(unsafe { read(va) })
    } else {
        None
    }
}

/// Write a `T` at `va` if the range is writable (no protection change).
///
/// # Safety
/// Writing arbitrary values into the game's data can break its invariants.
#[cfg(windows)]
pub unsafe fn try_write<T: Copy>(va: usize, value: T) -> bool {
    if is_writable(va, core::mem::size_of::<T>()) {
        unsafe { write(va, value) };
        true
    } else {
        false
    }
}

/// [`deref_chain`] with every link checked by [`is_readable`].
#[cfg(windows)]
pub fn try_deref_chain(base: usize, offsets: &[usize]) -> Option<usize> {
    let mut p = base;
    for off in offsets {
        let next: u32 = try_read(p)?;
        if next == 0 {
            return None;
        }
        p = (next as usize).wrapping_add(*off);
    }
    Some(p)
}

/// Whether the bytes at `va` are `expected` (and readable) -- the same test
/// KPM's runtime makes before patching a site.
#[cfg(windows)]
pub fn bytes_match(va: usize, expected: &[u8]) -> bool {
    is_readable(va, expected.len())
        && unsafe { core::slice::from_raw_parts(va as *const u8, expected.len()) } == expected
}

/// Overwrite code or read-only data: `VirtualProtect` to RWX, copy, restore
/// the old protection, flush the instruction cache. Returns the Win32 error.
///
/// # Safety
/// Another thread executing the bytes mid-write sees a torn instruction.
/// Patch sites before the game reaches them, or patch whole instructions that
/// no thread is in.
#[cfg(windows)]
pub unsafe fn write_code(va: usize, bytes: &[u8]) -> Result<(), u32> {
    unsafe { win::write_code(va, bytes) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_access_and_chain() {
        let mut target = 0x1122_3344u32;
        let field = &mut target as *mut u32 as usize;
        // A two-level chain: holder -> object; object+4 is the field.
        let object = [0u32, 0];
        let object_addr = object.as_ptr() as usize;
        let holder = object_addr as u32;
        let holder_addr = &holder as *const u32 as usize;
        if usize::BITS == 32 {
            assert_eq!(
                unsafe { deref_chain(holder_addr, &[4]) },
                Some(object_addr + 4)
            );
        }
        unsafe { write(field, 7u32) };
        assert_eq!(unsafe { read::<u32>(field) }, 7);
        assert_eq!(unsafe { read_bytes(field, 4) }, 7u32.to_le_bytes());
        let null = 0u32;
        assert_eq!(
            unsafe { deref_chain(&null as *const u32 as usize, &[0]) },
            None
        );
    }
}
