# kfmt

> **Reference.** The command-line front end of
> [`kotor-formats`](../kotor-formats/README.md). Held to the
> [documentation standard](../../../docs/documentation-standard.md).

Inspect and round-trip KotOR resource files: dump a GFF, list and extract
from `chitin.key` and from ERF/MOD/RIM archives, print 2DAs, describe TPCs,
and check that rewriting a file through `kotor-formats` gives back the same
bytes.

```sh
cd kotor2
cargo build --release -p kfmt
K2="/path/to/Star Wars Knights of the Old Republic II"   # the folder with chitin.key

./target/release/kfmt key list "$K2/chitin.key" --type gui
./target/release/kfmt key list "$K2/chitin.key" --bifs          # BIF table, resolved on disk
./target/release/kfmt key extract "$K2/chitin.key" GUINAME.gui -o /tmp/menu.gui
./target/release/kfmt gff dump /tmp/menu.gui
./target/release/kfmt gui list /tmp/menu.gui
./target/release/kfmt gff roundtrip /tmp/menu.gui            # byte-identical, or the first difference
./target/release/kfmt erf list "$K2/TexturePacks/swpc_tex_gui.erf"
./target/release/kfmt erf extract "$K2/TexturePacks/swpc_tex_gui.erf" TEXNAME.tpc -o /tmp/tex
./target/release/kfmt tpc info /tmp/tex/TEXNAME.tpc --tga /tmp/tex.tga
./target/release/kfmt 2da dump /tmp/appearance.2da
./target/release/kfmt roundtrip "$K2/modules/MODULE.rim"
```

`GUINAME`, `TEXNAME` and `MODULE` are placeholders: `key list` and `erf list`
show what an install actually holds.

| command | does |
| --- | --- |
| `gff dump <file>` | JSON: each struct `{"struct_id", "fields": [{"label", "type", "value"}]}`, so field order, duplicate labels and stored types are all visible |
| `gff roundtrip <file> [-o out]` | reads and rewrites; reports `byte-identical` or the sizes, first differing offset, differing-byte count and a hex window around it. `-o -` writes the output to stdout |
| `gui list <file>` | every control (depth first) with its GFF path, tag, type, extent and font |
| `key list <chitin.key> [--type ext] [--bifs]` | resources as `name.ext  bif  entry`, or the BIF table with the path each BIF resolved to (`MISSING` if not found) |
| `key extract <chitin.key> <name.ext> [-o out]` | one resource from the BIFs; default output `./name.ext` |
| `erf list` / `erf extract <archive> [names...] [-o dir]` | ERF, MOD, SAV, HAK and RIM, chosen by signature |
| `2da dump <file> [--text]` | an aligned table, or `--text` for 2DA V2.0 |
| `tpc info <file> [--tga out]` | header, format, kind (single / cube map / animated), every mip level, the TXI; `--tga` exports layer 0 level 0 as a 32-bit TGA |
| `roundtrip <file> [-o out]` | `gff roundtrip` for any format with a writer: GFF, binary 2DA, ERF family, RIM, TPC, TGA, TLK |

Exit status: 0 on success or a byte-identical round trip, 1 when a round trip
differs, 2 on any error. Every error names the file it came from. `kfmt` never
overwrites an existing output file unless given `--force`, and it only ever
reads from the paths it is given as input, so pointing it at a live install is
safe.

BIF paths in `chitin.key` are Windows paths (`data\gui.bif`); they are
resolved case-insensitively, so a Proton install on a case-sensitive
filesystem works as is.
