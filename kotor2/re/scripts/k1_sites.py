"""List every KMRP KotOR 1 patch site with the K1 1.03 function that contains it.

Usage: python3 -I k1_sites.py <kmrp repo> <out.tsv>
"""
import bisect
import json
import sqlite3
import sys
import tomllib
from pathlib import Path

repo = Path(sys.argv[1])
out = Path(sys.argv[2])

db = sqlite3.connect(f"file:{repo}/third_party/Kotor-Patch-Manager/AddressDatabases/kotor1_0_3.db?mode=ro", uri=True)
funcs = sorted((a, f"{c}::{n}") for c, n, a in db.execute("select class_name, function_name, address from functions"))
addrs = [a for a, _ in funcs]


def owner(va):
    i = bisect.bisect_right(addrs, va) - 1
    if i < 0:
        return "?", 0
    return funcs[i][1], va - funcs[i][0]


rows = []
sites = json.loads((repo / "src/engine/windows-sites.json").read_text())["sites"]
for s in sites:
    rows.append((int(s["va"], 16), "windows-sites.json", "bytes", s.get("original", "")))

for toml_path in sorted((repo / "src/controller-native").glob("*.hooks.toml")):
    data = tomllib.loads(toml_path.read_text())
    for h in data.get("hooks", []):
        rows.append((h["address"], toml_path.name, h.get("type", "") + ":" + h.get("function", ""), h.get("install", "")))

seen = set()
with out.open("w") as w:
    w.write("va\tsource\tkind\textra\tk1_function\toffset\n")
    for va, src, kind, extra in sorted(rows):
        key = (va, src)
        if key in seen:
            continue
        seen.add(key)
        name, off = owner(va)
        w.write(f"{va:08X}\t{src}\t{kind}\t{extra}\t{name}\t+0x{off:X}\n")
print(len(seen), "sites")
