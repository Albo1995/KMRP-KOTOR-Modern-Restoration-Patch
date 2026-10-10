# kpm-sdk

A Rust SDK for writing KOTOR Patch Manager (KPM) patch modules: 32-bit
Windows DLLs that KPM's runtime loads into `swkotor2.exe` (or `swkotor.exe`)
and calls from the detour sites a patch's `hooks.toml` names.

Everything below about KPM was read from the source in
`third_party/Kotor-Patch-Manager` at submodule commit `2a784bf`
(`RayesDiyab/Kotor-Patch-Manager`, branch `kmrp`): the runtime in
`src/KotorPatcher/src/core/{config_reader,patcher,trampoline,wrapper_x86}.cpp`
and `include/wrappers/wrapper_base.h`, the manager in
`src/KPatchCore/{Parsers/HooksParser.cs,Models/Hook.cs,Models/Parameter.cs,Validators/HookValidator.cs,Applicators/ConfigGenerator.cs,Applicators/PatchApplicator.cs,Managers/PatchRepository.cs}`.
Not yet measured in a running game: nothing here has been run inside
`swkotor2.exe`; the wrapper behaviour is as read, and the `kmrp2-hello`
module built with this SDK has been compiled and inspected, not loaded.

## How a module gets loaded

1. The game loads `binkw32.dll`, KPM's proxy (`src/KProxy`), which forwards
   Bink calls to the renamed original `binkw32Hooked.dll` and loads
   `KotorPatcher.dll`.
2. `KotorPatcher.dll` reads `patch_config.toml` beside it, sets the
   environment variable `KOTOR_VERSION_SHA` to its `target_version_sha`, and
   applies each `[[patches]]` entry in order. If any hook site does not yet
   read as its `original_bytes` (SteamStub-encrypted `.text`), it polls every
   15 ms for up to 30 s on a worker thread before applying.
3. A patch with a `dll` and no hooks is DLL-only: the module is loaded and
   nothing else happens; its `DllMain` does the work. For a `detour` hook the
   module is loaded (`LoadLibrary`, path relative to the game folder,
   `patches\<patch id>.dll`), the export named by `function` is resolved with
   `GetProcAddress`, `original_bytes` are verified, a wrapper is generated,
   and the site is overwritten with `E9 rel32` to the wrapper plus `0x90` over
   the rest of `original_bytes`.
4. The first failing hook stops every hook after it (`ApplyPatches` returns
   on the first `false`).

A `.kpatch` is a zip (`Patches/create-patch.py`): `manifest.toml`, one or more
`*hooks.toml` at the root, and `binaries/windows_x86.dll`. KPM picks every
hooks file whose `[metadata] target_versions` is empty or contains the game
executable's SHA-256 (case-insensitive).

## The detour ABI

The wrapper (`wrapper_x86.cpp`, `GenerateDetourWrapper`) is reached by a JMP,
so there is no return address between the game's stack and the wrapper. In
order, it:

| Step | Code | Effect |
| --- | --- | --- |
| 1 | `LEA ESP,[ESP-528]` | FXSAVE area (512 + 16 slack) |
| 2 | `PUSHAD; PUSHFD; MOV EBX,ESP` | saved block at EBX; game ESP = EBX + 564 |
| 3 | `FXSAVE` (16-aligned) | x87, MMX, SSE, MXCSR saved |
| 4 | `AND ESP,-16; SUB ESP,pad` | ESP 16-aligned at the CALL |
| 5 | one `PUSH` per parameter, last first | parameter 0 is the first C argument |
| 6 | `CALL function; MOV ESP,EBX` | caller-side cleanup is implicit, so cdecl or stdcall both work |
| 7 | `FXRSTOR` if `preserve_registers` | FPU state back; an `ST(0)` return is lost |
| 8 | `POPFD` if `preserve_flags` | flags back |
| 9 | `POPAD`, or per-register `POP`s | see below |
| 10 | `LEA ESP,[ESP+528]` | back to the game's ESP |
| 11 | `original_bytes`, unless `skip_original_bytes` | the stolen instructions, run in the wrapper |
| 12 | if `consumed_exit_address`: `PUSHFD; TEST EAX,EAX; JZ; POPFD; JMP exit; POPFD` | non-zero EAX takes the exit |
| 13 | `JMP address + len(original_bytes)` | resume |

Write the hook as a **cdecl export with an undecorated name**:

```rust
use kpm_sdk::c_void;

kpm_sdk::detour! {
    /// hooks.toml: parameters [ecx: pointer, esp+4: pointer]
    fn MyHook(this: *mut c_void, first_arg: *mut u32) -> i32 {
        0
    }
}
```

which is `#[no_mangle] pub unsafe extern "C" fn MyHook(...) -> i32` with the
body inside a panic guard. Do not use `extern "stdcall"` (`"system"`): on
i686 its export would be decorated `MyHook@8`, and `GetProcAddress("MyHook")`
would not find it. The function must preserve EBX, ESI, EDI and EBP, which
every Rust ABI does; it may clobber EAX, ECX, EDX, flags and FPU/SSE state.

### Parameters

Each `[[hooks.parameters]]` entry is one 4-byte stack argument. `source`
(trimmed and lowercased; parsed by `abi::ParamSource::parse`, which mirrors
`ExtractAndPushParameter` and is checked against KPM's own grammar tables):

| `source` | The argument is | Example use |
| --- | --- | --- |
| `eax` `ecx` `edx` `ebx` `esi` `edi` `ebp` | the register's value at the site | `ecx` = `this` at a thiscall entry |
| `esp+N`, `esp-N` | the **address** of a game stack slot (LEA, not a load) | `esp+4` at a function entry = pointer to the first stack argument; write through it to change the argument |
| `reg+N`, `reg-N` | register value + N (an address) | `esi+0x10` = address of a field |
| `[esp+N]` | the value in that stack slot | the first argument by value |
| `[reg+N]`, `[reg]` | the value at register + N | a field's value |
| `const:V` | an immediate (decimal or `0x` hex) | one export serving several builds |

`esp` alone is refused. Offsets need a sign; magnitude at most `0x7FFF0000`.
`type` and the Rust type to declare:

| `type` | Slot | Rust |
| --- | --- | --- |
| `int` / `uint` | 32-bit | `i32` / `u32` |
| `pointer` | 32-bit | `*mut T`, `*const T`, `usize` |
| `float` | 4 raw bytes | `f32` |
| `byte` / `short` | zero-extended | `u8` / `u16` |
| `sbyte` / `sshort` | sign-extended | `i8` / `i16` |
| `int64` `uint64` `double` | refused on x86 | -- |

Address forms (`esp+N`, `reg+N`) cannot be `byte`/`short`/`sbyte`/`sshort`/
`float`; constants cannot be `float` and must fit the type. **A parameter the
wrapper cannot read drops the whole hook.**

### Return values and registers

* The return value is in EAX. It reaches the game only if `"eax"` is in
  `exclude_from_restore`. With `consumed_exit_address` set, non-zero EAX
  jumps there *after* the stolen bytes ran; KPM's manager refuses a
  consumed-exit hook without `"eax"` excluded, and the stolen bytes must
  neither touch EAX nor move ESP (`kpm-tool verify` checks both).
* Excluding `ecx`/`edx` hands the game whatever the hook left in them, which
  is undefined. Excluding `ebx` or `esp` has no effect (EBX is always
  restored; ESP is never popped). `preserve_registers = false` restores only
  EBX and skips FXRSTOR.
* To set any register explicitly, take the saved block as a parameter:
  `source = "esp-564", type = "pointer"` is `LEA ECX,[EBX]`, a
  `*mut kpm_sdk::SavedRegisters` (`eflags, edi, esi, ebp, esp_wrapper, ebx,
  edx, ecx, eax`). Writes to it are what POPFD/POPAD restore. This relies on
  KPM's private 528-byte FXSAVE area (`abi::SAVED_STATE_FROM_GAME_ESP`);
  re-check it whenever the runtime is updated.

### Stolen bytes

`original_bytes` (at least 5 for `detour` and `replace`) must end on an
instruction boundary, and for a detour that re-executes them they must be
position independent: a `call rel32` or `jcc rel8` copied into the wrapper
jumps somewhere else. `kpm-tool verify` checks this against the executable.

### Other hook types (no module needed)

| `type` | Applied | Rules |
| --- | --- | --- |
| `simple` | `replacement_bytes` written over the site in memory | same length as `original_bytes` |
| `replace` | site becomes `JMP block` + NOPs; block = `replacement_bytes` + `JMP address+len(original)` | `original_bytes` >= 5; replacement any length, must not branch relatively outside itself |
| `static` | written into the executable file at install by the manager; never in `patch_config.toml` | same length |
| anything else | treated as `detour` | |

## Panics

Rust aborts the process when a panic reaches an `extern "C"` boundary. Every
`detour!` function, and anything run through `kpm_sdk::ffi_guard`, catches
the unwind, writes `PANIC in <name>: <message>` to the module log, and
returns a fallback (0, null, `false`, `()`). Keep `panic = "unwind"` (the
default) for that to work; `kotor2/.cargo/config.toml` does.

## Calling the engine

```rust
kpm_sdk::engine_fn! {
    pub thiscall fn some_method(this: *mut c_void, x: i32) -> i32 = 0x0040_0000;
    pub stdcall  fn some_free(a: u32) = 0x0040_0010;
    pub cdecl    fn some_cdecl(a: u32) -> u32 = 0x0040_0020;
}
```

(placeholder addresses). `thiscall`/`stdcall`/`fastcall` items compile only
for `target_arch = "x86"`. `kpm_sdk::call::fn_at::<F>(va)` is the untyped form.

## Memory, logging, process

* `mem::read`/`write`/`read_bytes`/`deref_chain` (unchecked);
  `mem::try_read`/`try_write`/`try_deref_chain`/`is_readable`/`bytes_match`
  (Windows, `VirtualQuery`-checked); `mem::write_code` (VirtualProtect + copy
  + FlushInstructionCache).
* `log::init("kmrp2.log")` once, then `kpm_log!("...")`: UTC-timestamped
  lines appended (and flushed) to that file in the game folder.
  `log::install_panic_logger()` adds panic locations.
* `process::game_dir()`, `main_module_sha256()` (what KPM matches),
  `kotor_version_sha()` (KPM's `KOTOR_VERSION_SHA`), `main_module_base()`,
  `process_uptime_ms()`.

## The TOML model (feature `model`, on by default)

`model::HooksFile`, `Hook`, `Parameter`, `Manifest`, `PatchConfig`. Both
readers' syntaxes are accepted (integer or `"0x..."` addresses and bytes; the
manager accepts only integers, so strings produce a warning). KMRP's
`install`, `kpm_patch`, `kpm_provided_by` and `when` keys are fields; other
unknown keys land in `extra` and are reported. `Hook::issues()` applies the
manager's and runtime's rules for a 32-bit target. The tests parse every
hooks and manifest file in KMRP's `src/controller-native/` and in KPM's
`Patches/` without error.

## Building a module

```sh
rustup target add i686-pc-windows-gnu
# plus MinGW-w64's i686 gcc on PATH: Fedora `dnf install mingw32-gcc`,
# Debian/Ubuntu `apt install gcc-mingw-w64-i686`
cd kotor2
cargo build --release --target i686-pc-windows-gnu -p kmrp2-hello
```

A crate that defines `DllMain` (`extern "system"`) should pass
`-Wl,--enable-stdcall-fixup` for that target, as `kmrp2-hello/build.rs`
does, or GNU ld warns while matching `_DllMain@12` to the export `DllMain`.
