//! Keeping Rust panics out of the game: every exported entry point runs its
//! body under [`ffi_guard`], which catches the unwind, logs it, and returns a
//! fallback value instead.
//!
//! Since Rust 1.81 a panic that reaches an `extern "C"` boundary aborts the
//! process rather than unwinding into foreign frames, so without a guard a
//! panicking hook would kill the game outright. With one, the hook simply
//! returns its fallback (zero / null / `()`), which for a detour whose return
//! is not consumed means "do nothing".
//!
//! The guard only works with `panic = "unwind"` (the default). With
//! `panic = "abort"` it still compiles, but the panic aborts immediately.

use std::panic::{self, AssertUnwindSafe};

/// The value an entry point returns when its body panicked.
pub trait HookReturn {
    fn on_panic() -> Self;
}

macro_rules! zero_return {
    ($($t:ty),*) => { $(impl HookReturn for $t { fn on_panic() -> Self { 0 as $t } })* };
}
zero_return!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize, f32, f64);

impl HookReturn for () {
    fn on_panic() -> Self {}
}

impl HookReturn for bool {
    fn on_panic() -> Self {
        false
    }
}

impl<T> HookReturn for *mut T {
    fn on_panic() -> Self {
        core::ptr::null_mut()
    }
}

impl<T> HookReturn for *const T {
    fn on_panic() -> Self {
        core::ptr::null()
    }
}

/// Run `body`; if it panics, log `name` and the panic message through the
/// global logger (if [`crate::log::init`] was called) and return
/// [`HookReturn::on_panic`].
#[inline]
pub fn ffi_guard<R: HookReturn>(name: &str, body: impl FnOnce() -> R) -> R {
    match panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            crate::log::line(&format!(
                "PANIC in {name}: {message}; returned the fallback value"
            ));
            R::on_panic()
        }
    }
}

/// Define KPM detour hook functions.
///
/// ```ignore
/// kpm_sdk::detour! {
///     /// hooks.toml: parameters = [ecx (pointer), esp+4 (pointer)],
///     /// exclude_from_restore = ["eax"], consumed_exit_address = ...
///     fn MyHook(this: *mut c_void, arg_slot: *mut u32) -> i32 {
///         0
///     }
/// }
/// ```
///
/// expands to
///
/// ```ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn MyHook(this: *mut c_void, arg_slot: *mut u32) -> i32 {
///     kpm_sdk::guard::ffi_guard("MyHook", move || -> i32 { 0 })
/// }
/// ```
///
/// i.e. an undecorated cdecl export that KPM's `GetProcAddress` finds by the
/// name written in `function = "MyHook"`, with panics caught. Each argument
/// is one `[[hooks.parameters]]` entry, in order; declare it with the Rust
/// type [`crate::abi::ParamType::rust_type`] gives. The body is not an
/// `unsafe` context: dereference pointers inside `unsafe {}` blocks.
#[macro_export]
macro_rules! detour {
    ($(
        $(#[$meta:meta])*
        fn $name:ident ( $($arg:ident : $ty:ty),* $(,)? ) $(-> $ret:ty)? $body:block
    )*) => {$(
        $(#[$meta])*
        #[no_mangle]
        #[allow(non_snake_case, clippy::missing_safety_doc)]
        pub unsafe extern "C" fn $name($($arg: $ty),*) $(-> $ret)? {
            $crate::guard::ffi_guard(stringify!($name), move || $(-> $ret)? { $body })
        }
    )*};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_and_falls_back() {
        let r: i32 = ffi_guard("t", || panic!("boom"));
        assert_eq!(r, 0);
        let p: *mut u8 = ffi_guard("t", || panic!("boom"));
        assert!(p.is_null());
        assert_eq!(ffi_guard("t", || 7u32), 7);
    }

    crate::detour! {
        /// A test export.
        fn KpmSdkTestHook(a: u32, b: *mut u32) -> u32 {
            if a == 99 { panic!("bad") }
            unsafe { *b = a; }
            a + 1
        }
        fn KpmSdkTestUnit(_a: i32) {}
    }

    #[test]
    fn detour_macro() {
        let mut slot = 0u32;
        assert_eq!(unsafe { KpmSdkTestHook(4, &mut slot) }, 5);
        assert_eq!(slot, 4);
        assert_eq!(unsafe { KpmSdkTestHook(99, &mut slot) }, 0);
        unsafe { KpmSdkTestUnit(1) };
        let _: unsafe extern "C" fn(u32, *mut u32) -> u32 = KpmSdkTestHook;
    }
}
