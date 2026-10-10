#!/bin/bash
# Run a Ghidra script read-only against a private copy of the analysed project.
# Usage: ghidra.sh <copy-name> <Script.java> <script args...>
set -e
base="/home/aayre/kotor2 fixes/ghidra"
name="$1"; shift
proj="$base/copies/$name"
if [ ! -d "$proj/swkotor2.rep" ]; then
  mkdir -p "$proj"
  cp -r "$base/swkotor2.rep" "$base/swkotor2.gpr" "$proj/"
fi
/home/aayre/Decomp/tools/ghidra_12.1.3_PUBLIC/support/analyzeHeadless "$proj" swkotor2 -process swkotor2.exe -noanalysis -readOnly \
  -scriptPath "$base/scripts" -postScript "$@" 2>&1 | grep -E '\.java>|ERROR|Exception' || true
