//! Rust SDK for KOTOR Patch Manager (KPM) patch modules.
//!
//! A KPM patch module is a 32-bit Windows DLL (`binaries/windows_x86.dll` in
//! a `.kpatch`, installed as `patches\<id>.dll`) that KPM's runtime
//! (`KotorPatcher.dll`, loaded by its `binkw32.dll` proxy) loads with
//! `LoadLibrary`, and whose exports it calls from generated detour wrappers at
//! the sites its `hooks.toml` names. Build modules for `i686-pc-windows-gnu`.
//!
//! * [`abi`] -- the wrapper's calling contract, the parameter-source grammar.
//! * [`detour!`] -- define exported, panic-guarded hook functions.
//! * [`engine_fn!`] / [`call`] -- call game functions by address
//!   (thiscall / stdcall / fastcall / cdecl).
//! * [`mem`] -- read/write game memory at VAs, checked variants, code writes.
//! * [`log`] / [`kpm_log!`] -- a timestamped log file in the game folder.
//! * [`process`] -- game folder, main-module SHA-256, `KOTOR_VERSION_SHA`.
//! * [`model`] (feature `model`, default) -- serde model of `hooks.toml`,
//!   `manifest.toml` and `patch_config.toml`, with KPM's validation rules.
//!
//! See the crate README for the ABI written out in full.

pub mod abi;
pub mod call;
pub mod guard;
pub mod log;
pub mod mem;
#[cfg(feature = "model")]
pub mod model;
pub mod process;

pub use abi::{ParamSource, ParamType, Reg, SavedRegisters};
pub use guard::{ffi_guard, HookReturn};

/// `void*` for hook signatures.
pub use core::ffi::c_void;
