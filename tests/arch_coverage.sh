#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")"

env PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/pycache}" python3 - <<'PY'
from __future__ import annotations

from collections import defaultdict

from harness.manifest import all_cases


preferred_arches = [
    "aarch64",
    "amd64",
    "armel",
    "armhf",
    "i386",
    "la64",
    "m68k",
    "mips",
    "mipsel",
    "mips64",
    "mips64el",
    "msp430",
    "msp430x",
    "ppc",
    "ppc64",
    "riscv64",
    "sh2a",
    "sh4",
    "sh4el",
    "xtensa",
]
# The familiar engines in a familiar order. This is a preference, not the whole
# list: anything else the manifest emits is appended below, so a newly added
# backend cannot be silently dropped from the report.
preferred_engines = [
    "unicorn",
    "angr",
    "panda",
    "pcode",
    "pcode_symbolic",
    "styx",
    "styx-mpc860",
    "triton",
    "afl",
]

coverage = defaultdict(lambda: defaultdict(set))
seen_arches = set()
seen_engines = set()

for case in all_cases():
    if "scenario" not in case.tags:
        continue
    scenario, _, variant = case.id.partition(":")
    if not variant:
        continue

    if variant.startswith("afl:"):
        engine = "afl"
        arch = variant.split(":", 1)[1]
    else:
        arch, dot, emulator = variant.partition(".")
        engine = "unicorn" if not dot else emulator

    if arch and arch[0].isalpha():
        coverage[scenario][engine].add(arch)
        seen_arches.add(arch)
        seen_engines.add(engine)

arch_order = [arch for arch in preferred_arches if arch in seen_arches]
arch_order.extend(sorted(seen_arches - set(arch_order)))

# Same idea as arch_order: preferred first, then whatever else turned up.
engine_order = [engine for engine in preferred_engines if engine in seen_engines]
engine_order.extend(sorted(seen_engines - set(engine_order)))

for scenario in sorted(coverage):
    print(f"{scenario}:")
    for engine in engine_order:
        row = []
        for arch in arch_order:
            row.append(arch if arch in coverage[scenario][engine] else " " * len(arch))
        if any(item.strip() for item in row):
            print(f"  {engine:14} {' '.join(row)}")
PY
