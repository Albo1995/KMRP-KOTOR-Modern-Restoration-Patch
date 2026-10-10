//! Calling engine functions at fixed virtual addresses.
//!
//! `swkotor2.exe` is a 32-bit MSVC build; its member functions are
//! `__thiscall` (`this` in ECX, arguments on the stack, callee pops), its
//! Win32-style and many free functions `__stdcall` (stack, callee pops), the
//! rest `__cdecl` (stack, caller pops). Calling with the wrong convention
//! corrupts ESP, so declare each function with the one the disassembly shows:
//! a `ret N` epilogue means callee-pops (thiscall/stdcall), a `ret` with the
//! caller's `add esp, N` means cdecl, and a read of ECX before any write means
//! thiscall.
//!
//! `thiscall`, `stdcall` and `fastcall` exist only on 32-bit x86, so the
//! functions [`engine_fn!`](crate::engine_fn) declares with them are compiled
//! only for `target_arch = "x86"`; `cdecl` ones compile everywhere.

/// Reinterpret a virtual address as a function pointer of type `F`.
///
/// # Safety
/// `F` must be a function-pointer type whose signature and ABI match the code
/// at `va`, and that code must be mapped and executable when called.
#[inline]
pub unsafe fn fn_at<F: Copy>(va: usize) -> F {
    const { assert!(core::mem::size_of::<F>() == core::mem::size_of::<usize>()) };
    // SAFETY: same size, asserted above; validity is the caller's contract.
    unsafe { core::mem::transmute_copy::<usize, F>(&va) }
}

/// Declare typed wrappers for engine functions by address.
///
/// ```ignore
/// kpm_sdk::engine_fn! {
///     /// CSWGuiManager::SomeMethod (VA from the owner's own disassembly)
///     pub thiscall fn gui_some_method(this: *mut c_void, x: i32) -> i32 = 0x0040_0000;
///     pub stdcall  fn some_free_fn(a: u32) = 0x0040_0010;
///     pub cdecl    fn some_cdecl(fmt: *const u8) -> i32 = 0x0040_0020;
/// }
/// ```
///
/// Each becomes `pub unsafe fn name(args) -> R` that transmutes the address
/// to `unsafe extern "<abi>" fn(..) -> R` and calls it. Conventions:
/// `thiscall` (first argument is `this`, passed in ECX), `stdcall`,
/// `fastcall` (first two 32-bit arguments in ECX, EDX), `cdecl`.
#[macro_export]
macro_rules! engine_fn {
    () => {};
    ($(#[$m:meta])* $vis:vis thiscall fn $($rest:tt)*) => {
        $crate::__engine_fn_one!{ [cfg(target_arch = "x86")] "thiscall" $(#[$m])* $vis fn $($rest)* }
    };
    ($(#[$m:meta])* $vis:vis stdcall fn $($rest:tt)*) => {
        $crate::__engine_fn_one!{ [cfg(target_arch = "x86")] "stdcall" $(#[$m])* $vis fn $($rest)* }
    };
    ($(#[$m:meta])* $vis:vis fastcall fn $($rest:tt)*) => {
        $crate::__engine_fn_one!{ [cfg(target_arch = "x86")] "fastcall" $(#[$m])* $vis fn $($rest)* }
    };
    ($(#[$m:meta])* $vis:vis cdecl fn $($rest:tt)*) => {
        $crate::__engine_fn_one!{ [cfg(all())] "C" $(#[$m])* $vis fn $($rest)* }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __engine_fn_one {
    (
        [$cfg:meta] $abi:literal $(#[$m:meta])* $vis:vis fn $name:ident
        ( $($arg:ident : $ty:ty),* $(,)? ) $(-> $ret:ty)? = $va:expr ; $($rest:tt)*
    ) => {
        $(#[$m])*
        #[$cfg]
        #[allow(clippy::missing_safety_doc)]
        #[inline]
        $vis unsafe fn $name($($arg: $ty),*) $(-> $ret)? {
            let f: unsafe extern $abi fn($($ty),*) $(-> $ret)? =
                unsafe { $crate::call::fn_at(($va) as usize) };
            unsafe { f($($arg),*) }
        }
        $crate::engine_fn!{ $($rest)* }
    };
}

#[cfg(test)]
mod tests {
    extern "C" fn add(a: i32, b: i32) -> i32 {
        a + b
    }

    crate::engine_fn! {
        cdecl fn call_add(a: i32, b: i32) -> i32 = add as *const () as usize;
        /// Declared for x86 only; just has to compile on the host.
        thiscall fn _never_called(this: *mut u8, x: i32) -> i32 = 0x0040_1000;
        stdcall fn _never_called_either(x: i32) = 0x0040_2000;
    }

    #[test]
    fn calls_by_address() {
        assert_eq!(unsafe { call_add(2, 3) }, 5);
        let f: extern "C" fn(i32, i32) -> i32 = unsafe { super::fn_at(add as *const () as usize) };
        assert_eq!(f(1, 1), 2);
    }
}
