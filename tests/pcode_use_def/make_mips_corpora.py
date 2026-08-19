#!/usr/bin/env python3
"""Generate the MIPS corpus variants from the mips32 corpus.

The four MIPS targets share almost all of their ground truth:

  * ``corpus_mipsel.json``    -- MIPS32 little-endian. Identical instruction
    set to mips32; only the byte encoding differs (each 4-byte word is stored
    in the opposite order), so every ``bytes`` field is the mips32 encoding
    byte-reversed and the use/def ground truth is copied verbatim.

  * ``corpus_mips64.json``    -- MIPS64 big-endian. The MIPS32 encodings are a
    subset of MIPS64 and decode identically (a 32-bit op sign-extends into the
    64-bit register; the harness collapses Ghidra's ``<reg>_lo`` view back to
    the architectural register), so the mips32 entries are reused unchanged and
    the doubleword instructions in ``DWORD_ENTRIES`` below are appended.

  * ``corpus_mips64el.json``  -- MIPS64 little-endian: ``corpus_mips64.json``
    with every word byte-reversed.

Keeping these as generated artifacts (committed alongside the generator, like
CORPUS.md) means they stay in lock-step with the hand-maintained mips32 corpus
while still being picked up by the auto-loading harness.

The DWORD_ENTRIES encodings were produced with ``llvm-mc -arch=mips64
-mcpu=mips64r2 --show-encoding`` using ABI-stable registers (a0-a3/s0/sp, which
name the same physical register under both the o32 names Ghidra prints and the
n64 names llvm-mc assembles) and verified against ``analyze`` under
MIPS:BE:64:default.

Usage:
  python tests/pcode_use_def/make_mips_corpora.py         # regenerate the 3 files
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "corpus_mips32.json")


def _reg(name):
    return {"reg": name}


def _mem(base, offset, size):
    return {
        "mem": {"base": base, "index": None, "scale": 1, "offset": offset, "size": size}
    }


def _entry(
    asm, hexbytes, categories, uses, defs, uses_opt=None, defs_opt=None, notes=""
):
    return {
        "asm": asm,
        "bytes": hexbytes,
        "categories": categories,
        "uses": uses,
        "defs": defs,
        "uses_optional": uses_opt or [],
        "defs_optional": defs_opt or [],
        "notes": notes,
    }


# MIPS64-only (doubleword) instructions. Encodings from llvm-mc; ground truth
# hand-written from the ISA and verified against analyze.
DWORD_ENTRIES = [
    _entry(
        "daddu $a0, $a1, $a2",
        "00a6202d",
        ["arith", "64bit"],
        [_reg("a1"), _reg("a2")],
        [_reg("a0")],
    ),
    _entry(
        "daddiu $a0, $a1, 16",
        "64a40010",
        ["arith", "imm", "64bit"],
        [_reg("a1")],
        [_reg("a0")],
    ),
    _entry(
        "dsubu $a0, $a1, $a2",
        "00a6202f",
        ["arith", "64bit"],
        [_reg("a1"), _reg("a2")],
        [_reg("a0")],
    ),
    _entry(
        "dsll $a0, $a1, 4", "00052138", ["shift", "64bit"], [_reg("a1")], [_reg("a0")]
    ),
    _entry(
        "dsrl $a0, $a1, 4", "0005213a", ["shift", "64bit"], [_reg("a1")], [_reg("a0")]
    ),
    _entry(
        "dsra $a0, $a1, 4", "0005213b", ["shift", "64bit"], [_reg("a1")], [_reg("a0")]
    ),
    _entry(
        "dsll32 $a0, $a1, 4",
        "0005213c",
        ["shift", "64bit"],
        [_reg("a1")],
        [_reg("a0")],
        notes="shift amount is +32",
    ),
    _entry(
        "dsllv $a0, $a1, $a2",
        "00c52014",
        ["shift", "64bit", "variable"],
        [_reg("a1"), _reg("a2")],
        [_reg("a0")],
    ),
    _entry(
        "dsrlv $a0, $a1, $a2",
        "00c52016",
        ["shift", "64bit", "variable"],
        [_reg("a1"), _reg("a2")],
        [_reg("a0")],
    ),
    _entry(
        "ld $a0, 8($sp)",
        "dfa40008",
        ["load", "64bit", "base+disp"],
        [_reg("sp"), _mem("sp", 8, 8)],
        [_reg("a0")],
    ),
    _entry(
        "sd $a0, 8($sp)",
        "ffa40008",
        ["store", "64bit", "base+disp"],
        [_reg("a0"), _reg("sp")],
        [_mem("sp", 8, 8)],
    ),
    _entry(
        "ldl $a0, 7($s0)",
        "6a040007",
        ["load", "unaligned", "partial", "64bit"],
        [_reg("s0"), _reg("a0"), _mem("s0", 7, 8)],
        [_reg("a0")],
        notes="unaligned load-left merges into dest, so $a0 is read and written",
    ),
    _entry(
        "ldr $a0, 0($s0)",
        "6e040000",
        ["load", "unaligned", "partial", "64bit"],
        [_reg("s0"), _reg("a0"), _mem("s0", 0, 8)],
        [_reg("a0")],
        notes="unaligned load-right merges into dest",
    ),
    _entry(
        "lwu $a0, 4($s0)",
        "9e040004",
        ["load", "zeroext", "64bit"],
        [_reg("s0"), _mem("s0", 4, 4)],
        [_reg("a0")],
        notes="load word unsigned: zero-extends a 32-bit word into the 64-bit reg",
    ),
    _entry(
        "dmult $a0, $a1",
        "0085001c",
        ["muldiv", "64bit"],
        [_reg("a0"), _reg("a1")],
        [_reg("hi"), _reg("lo")],
    ),
    _entry(
        "dmultu $a0, $a1",
        "0085001d",
        ["muldiv", "64bit"],
        [_reg("a0"), _reg("a1")],
        [_reg("hi"), _reg("lo")],
    ),
    _entry(
        "ddiv $zero, $a0, $a1",
        "0085001e",
        ["muldiv", "64bit"],
        [_reg("a0"), _reg("a1")],
        [_reg("hi"), _reg("lo")],
        uses_opt=[_reg("zero")],
        notes="raw ddiv form ($zero dest marker) to avoid llvm-mc trap-check expansion",
    ),
    _entry(
        "ddivu $zero, $a0, $a1",
        "0085001f",
        ["muldiv", "64bit"],
        [_reg("a0"), _reg("a1")],
        [_reg("hi"), _reg("lo")],
        uses_opt=[_reg("zero")],
        notes="raw ddivu form",
    ),
    _entry("dclz $a0, $a1", "70a42024", ["bit", "64bit"], [_reg("a1")], [_reg("a0")]),
    _entry(
        "drotr $a0, $a1, 8", "0025223a", ["rotate", "64bit"], [_reg("a1")], [_reg("a0")]
    ),
    _entry(
        "dext $a0, $a1, 4, 8",
        "7ca43903",
        ["bitfield", "64bit"],
        [_reg("a1")],
        [_reg("a0")],
    ),
    _entry(
        "dins $a0, $a1, 4, 8",
        "7ca45907",
        ["bitfield", "64bit"],
        [_reg("a1"), _reg("a0")],
        [_reg("a0")],
        notes="insert merges into dest, so $a0 is read and written",
    ),
]


def _byteswap_word(hexbytes):
    """Reverse a 4-byte (8 hex char) instruction word for the opposite endian."""
    b = bytes.fromhex(hexbytes)
    if len(b) != 4:
        raise ValueError(f"expected a 4-byte MIPS word, got {len(b)}: {hexbytes}")
    return b[::-1].hex()


def _swap_entries(entries):
    out = []
    for e in entries:
        e = dict(e)
        e["bytes"] = _byteswap_word(e["bytes"])
        out.append(e)
    return out


def _write(path, corpus):
    with open(path, "w") as f:
        json.dump(corpus, f, indent=1)
        f.write("\n")


def main() -> None:
    with open(SRC) as f:
        mips32 = json.load(f)
    base = mips32["base_address"]
    mips32_entries = mips32["entries"]

    mipsel = {
        "isa": "mipsel",
        "ghidra_lang": "MIPS:LE:32:default",
        "llvm_triple": "mipsel-unknown-linux-gnu",
        "base_address": base,
        "entries": _swap_entries(mips32_entries),
    }

    mips64 = {
        "isa": "mips64",
        "ghidra_lang": "MIPS:BE:64:default",
        "llvm_triple": "mips64-unknown-linux-gnu",
        "base_address": base,
        "entries": mips32_entries + DWORD_ENTRIES,
    }

    mips64el = {
        "isa": "mips64el",
        "ghidra_lang": "MIPS:LE:64:default",
        "llvm_triple": "mips64el-unknown-linux-gnu",
        "base_address": base,
        "entries": _swap_entries(mips64["entries"]),
    }

    _write(os.path.join(HERE, "corpus_mipsel.json"), mipsel)
    _write(os.path.join(HERE, "corpus_mips64.json"), mips64)
    _write(os.path.join(HERE, "corpus_mips64el.json"), mips64el)
    print(
        f"wrote corpus_mipsel.json ({len(mipsel['entries'])}), "
        f"corpus_mips64.json ({len(mips64['entries'])}), "
        f"corpus_mips64el.json ({len(mips64el['entries'])})"
    )


if __name__ == "__main__":
    main()
