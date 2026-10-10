# kpm-tool

Host-side (Linux x86_64) tools for KOTOR Patch Manager patches against a
32-bit Windows executable. Only ever reads the executable.

```sh
cd kotor2
cargo build --release -p kpm-tool
T=target/release/kpm-tool
EXE=".../Knights of the Old Republic II/swkotor2.exe"
```

## verify

```sh
$T verify --exe "$EXE" --hooks my.hooks.toml [--hooks other.kpatch ...] [-v]
```

`--hooks` takes a `*hooks.toml`, an installed `patch_config.toml`, or a
`.kpatch` (whose hooks files KPM would not pick for this exe are skipped).
Exit 0 = pass, 1 = a check failed, 2 = could not run. Checks:

* SHA-256 of the exe against `target_versions` (or `target_version_sha`, or
  the `.kpatch` manifest's `supported_versions`); the build name if KPM knows it.
* every rule KPM's manager and runtime apply to a hook (detour >= 5 bytes,
  `function` present, consumed exit needs `"eax"` excluded, simple/static
  lengths, parameter sources the x86 wrapper can read, unknown keys);
* VA -> file offset through the section table (headers, zero-filled tails and
  addresses outside every section are reported); detour/replace sites must be
  in an executable section; consumed exits must be in code;
* `original_bytes` equal the file (a static hook already applied passes);
* the stolen range ends on an instruction boundary (iced-x86), with the
  instruction it would cut and the two lengths that would not;
* KMRP's stolen-byte rules (`tools/check_hook_stolen_bytes.py`): no relative
  branch re-executed by a detour; a consumed-exit hook's stolen bytes neither
  touch EAX nor move ESP; no stolen read of an excluded register; a replace
  block does not branch relatively outside itself;
* overlapping ranges across all inputs: fail across files; inside one file a
  warning when `install`/`kpm_patch`/`when` differ (KMRP's alternatives) or
  with `--allow-overlap-in-file`, otherwise fail.

A SteamStub-packed exe (`.bind` section) has its code-byte checks skipped.

## disasm, find, hash

```sh
$T disasm --exe "$EXE" --va 0x00506599 --count 12   # also prints a ready original_bytes
$T find   --exe "$EXE" --pattern "8B 44 24 ?? 85 C0" [--section .text] [--max 200]
$T hash   --exe "$EXE"
```

## pack

```sh
$T pack --manifest manifest.toml --hooks x.hooks.toml [--hooks ...] \
        [--dll module.dll] [--binary extra.file ...] --out X.kpatch
```

The layout of KPM's `Patches/create-patch.py`: a deflated zip of
`manifest.toml`, each hooks file at the root by name (sorted), then
`binaries/windows_x86.dll` and any `--binary` files. Refuses a manifest
without `id/name/version/author/description`, a hooks file not named
`*hooks.toml`, a hook KPM would reject, a detour patch without a module, a
module that is not an i386 DLL or does not export every detour `function`.
Timestamps are fixed, so the same inputs give the same bytes; the archive is
read back and compared after writing.

## Tests

`tests/verify.rs` builds PE32 images in code (`src/testpe.rs`; no game
bytes): pass, hash mismatch, byte mismatch, split instruction, short detour,
overlaps across and within files, relative branch, consumed-exit rules,
replace/static/data/header/zero-tail/outside mapping, SteamStub skip,
`patch_config.toml` layout, find/disasm, pack-then-verify, CLI exit codes.
