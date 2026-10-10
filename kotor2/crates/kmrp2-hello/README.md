# kmrp2-hello

The smallest KOTOR Patch Manager patch module for `swkotor2.exe`, built with
[`kpm-sdk`](../kpm-sdk/README.md). It changes nothing in the game. When KPM
loads it, its `DllMain` notes the time and starts a thread that appends to
`kmrp2.log` in the game folder: the load time (UTC) and milliseconds since the
process started, the main module's path, base and SHA-256, and whether KPM's
`KOTOR_VERSION_SHA` matches the file on disk. It exports one example detour,
`Kmrp2ExampleDetour`, which nothing hooks yet.

`patch/kmrp2-hello.hooks.toml` holds that detour **commented out, address
TODO**: no KotOR 2 site has been located. With no hooks, KPM installs the
patch as DLL-only (it loads `patches\kmrp2-hello.dll` and applies nothing).

## Build and pack

```sh
cd kotor2
cargo build --release --target i686-pc-windows-gnu -p kmrp2-hello
cargo run --release -p kpm-tool -- pack \
    --manifest crates/kmrp2-hello/patch/manifest.toml \
    --hooks crates/kmrp2-hello/patch/kmrp2-hello.hooks.toml \
    --dll target/i686-pc-windows-gnu/release/kmrp2_hello.dll \
    --out target/kpatch/kmrp2-hello.kpatch
```

Measured on 2026-10-10 (Rust 1.97.0, MinGW-w64 GCC 16.2.1, Fedora 44):
`kmrp2_hello.dll` 982,528 bytes, exports `DllMain` and `Kmrp2ExampleDetour`,
imports `KERNEL32.dll`, `kernel32.dll`, `msvcrt.dll`, `ntdll.dll`,
`USERENV.dll`, `WS2_32.dll`, `bcryptprimitives.dll` and
`api-ms-win-core-synch-l1-2-0.dll` (the last two come from Rust's standard
library: `ProcessPrng` and `WaitOnAddress`; Windows 10+, and present in
current Wine/Proton). `kpm-tool verify` of the packed `.kpatch` against the
owner's Steam `swkotor2.exe` passed (hash match, no hooks). **Not yet run in
the game**: whether it loads under Proton and writes the log is untested.

## Known swkotor2.exe builds (from the KPM submodule, `2a784bf`)

| SHA-256 | KPM key | Build | KPM patches with a hooks file for it |
| --- | --- | --- | --- |
| `6A522E71631DCEE93467BD2010F3B23D9145326E1E2E89305F13AB104DBBFFEF` | `kotor2_steam_aspyr` | Steam, Aspyr update, Windows | 19 |
| `777BEE235A9E8BDD9863F6741BC3AC54BB6A113B62B1D2E4D12BBE6DB963A914` | `kotor2_gog_aspyr` | GOG, Aspyr update, Windows | 26 |
| `ED043D21A4578FD1C6F1557F0F72BDE5589BA3572A5B6F1A687ED9FEEAB49AC3` | `kotor2_steam_aspyr_linux` | Steam, Aspyr native Linux (ELF) | -- |
| `1C536C3EF2E8BED348B38934B381E3DC427F3EBEE21FADDFBD7524FBB2388D77` | `kotor2_steam_aspyr_macos` | Steam 1.0.2, Aspyr macOS (x86_64) | -- |

The owner's executable is the Steam one: 6,588,416 bytes, `6A522E71...`. On
2026-10-10 `kpm-tool verify` read it as PE32 i386, base `0x00400000`,
sections `.text .rdata .data .rsrc`, no `.bind`. KPM's static (on-disk)
hooks for it suggest the same: the Steam KotOR 2 executable is not
SteamStub-encrypted, unlike KotOR 1's. Against it, the hooks files of
K2AspyrMusicFix, BorderlessFullscreen, K2GrassFogFix and Max Lights all
matched (23 hooks, including Max Lights' three detours).

Patches with Steam hooks: 4GBPatch, BorderlessFullscreen, DeSteamify,
FullPartySelect, GoodAlignmentHeads, K2AspyrColorCorrection,
K2AspyrFogReflectionFix, K2AspyrMusicFix, K2AspyrNormalMapsFix,
K2AspyrSaberTextureFix, K2AspyrShaderFixes, K2AspyrVisibleConsole,
K2FinesseMeleeFix, K2GrassFogFix, K2MP3PlaybackFix, Max Lights,
SemiTransparentLetterbox, StoreConfirmThreshold2500, StoreNoConfirmThreshold.
The ones with detours (and so a module): K2AspyrVisibleConsole,
K2MP3PlaybackFix, Max Lights. Their hooks files are the best reference for
known-good swkotor2.exe sites; the Steam addresses were generated from GOG's
mappings (`kotor2_steam_aspyr.db`'s own description).
