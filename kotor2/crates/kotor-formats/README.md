# kotor-formats

> **Reference.** What this crate reads and writes, and how far its round trips
> are proven. Held to the [documentation standard](../../../docs/documentation-standard.md).

Readers and writers for the resource formats of BioWare's Odyssey engine, the
foundation of KMRP's Rust port to *KotOR II: The Sith Lords*
(`swkotor2.exe`, Windows, run under Proton). Pure Rust, `#![forbid(unsafe_code)]`,
one dependency (`thiserror`), no platform-specific code: it builds for the
32-bit Windows target the game needs as well as for the host.

## What is implemented

| module | format | read | write | round trip of unmodified data |
| --- | --- | --- | --- | --- |
| `gff` | GFF V3.2, every field type (Byte..Int64, Float, Double, CExoString, ResRef, CExoLocString, Void, Struct, List, Orientation, Vector; unknown types kept raw) | yes | yes | byte-exact when the source is densely packed (see below) |
| `gui` | `.gui` controls on top of GFF: `EXTENT`, `BORDER`/`HILIGHT`/`SELECTED`/`HILIGHTSELECTED`, `TEXT` (font, strref), `MOVETO`, `SCROLLBAR`, `PROTOITEM`, nested `CONTROLS` | yes | yes (edits keep each field's stored GFF type) | as GFF |
| `key` | KEY V1 (`chitin.key`) and BIF V1, with case-insensitive BIF path resolution | yes | no | n/a |
| `erf` | ERF / MOD / SAV / HAK V1.0 | yes | yes | byte-exact for the conventional section order; data order and inter-resource padding kept |
| `rim` | RIM V1.0 | yes | yes | byte-exact; header bytes, data order and padding kept |
| `twoda` | 2DA V2.b (binary) and V2.0 (text) | both | both | binary byte-exact when the string pool holds each string once |
| `tlk` | TLK V3.0 | yes | yes (packs text in entry order) | not claimed for `dialog.tlk` |
| `tpc` | TPC header, DXT1 / DXT5 / grey / RGB / RGBA mip chains, cube maps, cycle animations, trailing TXI; DXT decode to RGBA | yes | yes | byte-exact by construction (data and TXI kept raw) |
| `tga` | TGA types 2, 3, 10, 11 at 8/16/24/32 bpp, any origin | yes | yes | uncompressed byte-exact; RLE exact for files this crate wrote |
| `txi` | TXI key/value text, including the multi-line `upperleftcoords` / `lowerrightcoords` font keys | yes | yes (normalized spacing) | not byte-exact |
| `restype` | Odyssey resource type ids <-> extensions | | | |
| `text` | bijective Windows-1252 mapping used for every string | | | every byte sequence |

Strings are `String` throughout. Every byte decodes through a Windows-1252
table in which the five undefined bytes map to the C1 controls of the same
value, so `encode(decode(bytes)) == bytes` for any input, including installs in
other code pages (they display wrong characters but still round-trip).

## How the round trips work

**GFF.** The reader records, on every struct and field, its index in the
source, its label index, its data offset and its raw inline dword. The writer
orders the struct array, field array, field data, field-index lists and
list-index lists by those positions, reuses the source label table, and only
places new nodes canonically (depth-first, the order PyKotor's writer uses).
Offsets are always recomputed, so the output is valid after any edit. When
nothing was edited and the source had no unreferenced or shared bytes, the
output is byte-identical. The recorded positions are invisible to `==`.

Bytes in the field-data, field-indices and list-indices sections that nothing
references are kept too, attached to the block they follow, and a block two
fields or lists shared in the source stays shared. This was added after the
first run against a KotOR 2 install (2026-10-10): 2080 of 2085 GFFs in the
BIFs came back identical, while `temp_char.bic` (field indices) and four
`*palstd.itp` palettes (list indices) came back shorter. The first differing
offsets, 0x2c and 0x34, are those sections' size fields in the header, and
unreferenced bytes are the likely cause. That cause is **not yet confirmed**:
`kfmt gff diff <file>` prints each section's unreferenced, shared and
overlapping bytes, and the next run will show whether these five now match.
A block that only partly overlaps another cannot be reproduced; such files
still rewrite to an equal tree and are reported as layout-only differences.

**ERF / RIM.** The data is emitted in source offset order with the bytes the
source had between resources (alignment padding) and before the first one.
ERF tables are written in the conventional order header, localized strings,
keys, resource list; an ERF laid out differently reads fine but is rewritten
in that order.

**2DA.** The pool is rewritten in the source's order, then new strings in
row-major first-use order.

**TPC.** The image data and the TXI are kept as raw bytes. The split between
them is computed from the header (mip count clamped to what the file holds),
and when the bytes after that point are not text, from a trailing
`proceduretype cycle` TXI whose frame layout accounts for the data exactly.

## Provenance and what is not yet verified

The byte layouts come from public documentation (BioWare's Aurora format
PDFs, xoreos, PyKotor), from KMRP's own Python tools under `tools/`, which
edit KotOR 1 GUI files and write TPCs the game loads, and from the synthetic
tests in this crate. **None of it has yet been measured against KotOR 2
files.** The ignored tests in [`tests/game_install.rs`](tests/game_install.rs)
do that against a real install; until they have been run, treat these as
open:

* First run against a KotOR 2 install (reported by the owner, 2026-10-10):
  164/164 GUI, 424 2DA, 5282 TPC, 27 archives and `dialog.tlk` byte-identical;
  2080/2085 GFFs byte-identical. The five others are described above.
* TPC cube maps (height = 6 x width) and animated textures (`proceduretype
  cycle`, `numx`, `numy`) are laid out as xoreos describes; neither has been
  checked against a real file here.
* The KotOR 2 GUI fields `HILIGHTSELECTED` and `BORDER/INNEROFFSETY` are read
  when present; that KotOR 2 uses them is from documentation.
* Swizzled BGRA TPCs (encoding 12, Xbox) are recognized but not decoded.
  Compressed `BZF` BIFs (Xbox, mobile) are not supported.
* `dialog.tlk` is read; rewriting it is not claimed to be byte-exact.

## Running the tests

```sh
cd kotor2
cargo test -p kotor-formats                      # synthetic tests
KOTOR2_DIR="/path/to/Star Wars Knights of the Old Republic II" \
  cargo test -p kotor-formats --test game_install -- --ignored --nocapture
```

`KOTOR2_DIR` is the folder holding `chitin.key`. The game tests read only;
they never write into the install. They extract every `.gui` and every `.2da`
named by `chitin.key`, every `.gui`, `.2da` and `.tpc` in `Override`, and a
sample of the TPCs in `TexturePacks/*.erf`, round-trip each through this
crate, and fail listing every file that did not come back byte-identical with
the first differing offset. They also round-trip a sample of the archives in
`modules/` and `TexturePacks/`. Counts are printed with `--nocapture`.

No game file is, or may be, committed to this repository: every fixture in the
unit tests is built in code.
