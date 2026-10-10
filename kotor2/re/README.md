# KotOR 2 reverse-engineering notes

Where KMRP's KotOR 1 patch sites are in KotOR 2, worked out on 2026-10-10 by
reading the code in Ghidra. Nothing here has been patched or tested in the game
yet, except the one measurement under *Measured in the game*.

## The build

| | |
| --- | --- |
| Game | *Star Wars: Knights of the Old Republic II*, Steam, Aspyr update, Windows |
| Executable | `swkotor2.exe`, 6,588,416 bytes |
| SHA-256 | `6A522E71631DCEE93467BD2010F3B23D9145326E1E2E89305F13AB104DBBFFEF` (KPM's `kotor2-steam-aspyr`) |
| Format | PE32 i386, image base `0x00400000`, sections `.text .rdata .data .rsrc`, no SteamStub |
| Addresses | virtual addresses, as Ghidra shows them |

The exe keeps its RTTI, so `classes.txt` lists 392 classes with their vtable
addresses, all the `CSWGui*` classes among them.

## Files

| File | What |
| --- | --- |
| `k1_sites.tsv` | the 131 KMRP KotOR 1 sites (from `src/engine/windows-sites.json` and `src/controller-native/*.hooks.toml`), each named by the KotOR 1 1.03 function it is in (KPM's `kotor1_0_3.db`) |
| `map-lists.tsv`, `map-lists.md` | lists, text, panels, message boxes, character generation: 52 sites, 44 confirmed, 5 likely, 3 not needed |
| `map-screen.tsv`, `map-screen.md` | resolution, video mode, area map, minimap, movies, dialogue, input: 74 sites, 33 confirmed, 13 likely, 22 not needed, 6 not found. Section 6 covers what Aspyr does at 3840x2160 |
| `k2_names-*.tsv` | KotOR 2 functions named along the way (address, name, evidence); guesses are marked |
| `classes.txt` | RTTI vtable address and class name |
| `scripts/` | the Ghidra headless scripts used. `ghidra.sh` holds the paths of the machine they ran on |

Each TSV row gives the KotOR 1 site, its purpose, the KotOR 2 function and site,
the original bytes at the KotOR 2 site (checked against instruction boundaries),
a status and the evidence. "Confirmed" means two independent pieces of evidence;
"likely" means one. Every KotOR 2 address must still pass `kpm-tool verify`
before it is used.

## Things that matter most

- The Steam build is unoptimised: every function starts `55 8BEC` and keeps
  its locals at `[ebp-N]`. A KotOR 1 hook that read `esp+N` or `esi`/`edi`
  has to pass `ebp` and read the frame instead.
- Objects are 4 bytes bigger per embedded control than in KotOR 1. List-box
  fields are KotOR 1's plus `0x10`.
- Aspyr already scales the GUI: every panel and control from an 800x600
  design size (`0x9F4390`/`0x9F4394`, never written), separately in width and
  height, and text by `1 + 0.5 * floor((width - 1022) / 1024)` (`0x479AB0`).
- The six panel-recentring operands are `SUB EAX,+640/+480` in KotOR 2, the
  opposite of KotOR 1's `ADD EAX,-640/-480`. Copying KotOR 1's replacement
  bytes would invert the fix.
- Aspyr accepts only resolutions up to the desktop size and at least 1024x720;
  anything else falls back to 1024x768.

## Measured in the game

On 2026-10-10, under gamescope at 1366x768 (16:9), the main menu was a 4:3
panel centred on the screen (frame lines from x=168 to x=1190, 1,022 px), with
nothing stretched. The code reading had predicted that every menu would be
stretched 1.333x across 16:9, so that prediction does not hold for the main
menu. Each other screen still has to be checked before it is fixed.

The same session showed the 1024x768 fallback: with `Width=3840`,
`Height=2160` in `swkotor2.ini` and gamescope's window at 1366x768, the game
opened at 1024x768.
