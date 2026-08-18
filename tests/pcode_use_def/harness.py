#!/usr/bin/env python3
"""Validation harness for the pcode-based instruction use/def analysis.

Runs every corpus entry (see README.md in this directory for the corpus
schema and ground-truth conventions) through
`smallworld.instructions.pcode_use_def.analyze` and compares the
reported use/def sets against ground truth.

Each entry is judged twice:

  * strict     — exact match (case-insensitive names) against ground truth,
                 with `uses_optional`/`defs_optional` items allowed but not
                 required.
  * normalized — same, after dropping flag registers and canonicalizing
                 sub-registers (eax->rax, w3->x3) on BOTH sides, and
                 reducing offsets mod 2^address-size. An entry that fails
                 strict but passes normalized indicates a naming/modeling
                 difference rather than a wrong dataflow fact.

Outcome categories per entry:
  pass            strict match
  pass-normalized normalized match only (flag/subregister/sign differences)
  mismatch        wrong or missing operands even after normalization
  error           analyze raised an exception
  decode          bytes did not decode to exactly one instruction

Usage:
  python tests/pcode_use_def/harness.py                 # all corpora
  python tests/pcode_use_def/harness.py --isa ppc32     # one ISA
  python tests/pcode_use_def/harness.py --json out.json # full per-entry report
  python tests/pcode_use_def/harness.py -v              # per-entry detail on stdout
"""

import argparse
import glob
import json
import logging
import os
import re
import sys
import traceback

# Neutralize the analysis code's debug scaffolding *before* importing it:
# pcode_use_def currently contains live breakpoint() calls, and logs every
# pcode op at INFO when its pdebug flag is set.
os.environ.setdefault("PYTHONBREAKPOINT", "0")
logging.disable(logging.INFO)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# ----------------------------------------------------------------------- #
# Per-ISA normalization tables
# ----------------------------------------------------------------------- #

X86_FLAGS = {
    "cf",
    "pf",
    "af",
    "zf",
    "sf",
    "of",
    "df",
    "tf",
    "if",
    "ac",
    "id",
    "rflags",
    "eflags",
    "flags",
}

FLAG_REGS = {
    "x86_64": X86_FLAGS,
    "i386": X86_FLAGS,
    "aarch64": {
        "ng",
        "zr",
        "cy",
        "ov",
        # the flags as a unit (mrs/msr nzcv)
        "nzcv",
        # Ghidra AARCH64 scratch/status registers that can leak into pcode
        "shift_carry",
        "tmpcy",
        "tmpov",
        "tmpng",
        "tmpzr",
    },
    "ppc32": {
        "cr0",
        "cr1",
        "cr2",
        "cr3",
        "cr4",
        "cr5",
        "cr6",
        "cr7",
        "xer_so",
        "xer_ov",
        "xer_ca",
        "xer_count",
        "xer_string",
        "xer",
        "crall",
    },
    "mips32": set(),
    # MIPS has no integer condition-code registers; hi/lo are real defs.
    "mipsel": set(),
    "mips64": set(),
    "mips64el": set(),
    "arm32": {
        # ARM condition flags (Ghidra names them like AArch64)
        "ng",
        "zr",
        "cy",
        "ov",
        "cpsr",
        # Ghidra ARM scratch/status registers that leak into pcode:
        # shift_carry is the barrel-shifter carry (even a plain add
        # copies cy into it), tmp* are the flag-computation temporaries,
        # tb/isamodeswitch are Thumb-interworking state.
        "shift_carry",
        "tmpcy",
        "tmpov",
        "tmpng",
        "tmpzr",
        "tb",
        "isamodeswitch",
    },
}

ADDRESS_BITS = {
    "x86_64": 64,
    "i386": 32,
    "ppc32": 32,
    "aarch64": 64,
    "mips32": 32,
    "mipsel": 32,
    "mips64": 64,
    "mips64el": 64,
    "arm32": 32,
}


def _x86_64_subregs():
    m = {}
    for full, e, x, lo, hi in (
        ("rax", "eax", "ax", "al", "ah"),
        ("rbx", "ebx", "bx", "bl", "bh"),
        ("rcx", "ecx", "cx", "cl", "ch"),
        ("rdx", "edx", "dx", "dl", "dh"),
    ):
        for sub in (e, x, lo, hi):
            m[sub] = full
    for full, e, x, lo in (
        ("rsi", "esi", "si", "sil"),
        ("rdi", "edi", "di", "dil"),
        ("rbp", "ebp", "bp", "bpl"),
        ("rsp", "esp", "sp", "spl"),
    ):
        for sub in (e, x, lo):
            m[sub] = full
    for n in range(8, 16):
        for suffix in ("d", "w", "b"):
            m[f"r{n}{suffix}"] = f"r{n}"
    return m


def _i386_subregs():
    m = {}
    for full, x, lo, hi in (
        ("eax", "ax", "al", "ah"),
        ("ebx", "bx", "bl", "bh"),
        ("ecx", "cx", "cl", "ch"),
        ("edx", "dx", "dl", "dh"),
    ):
        for sub in (x, lo, hi):
            m[sub] = full
    for full, x, lo in (
        ("esi", "si", "sil"),
        ("edi", "di", "dil"),
        ("ebp", "bp", "bpl"),
        ("esp", "sp", "spl"),
    ):
        for sub in (x, lo):
            m[sub] = full
    return m


def _aarch64_subregs():
    m = {f"w{n}": f"x{n}" for n in range(31)}
    m["wzr"] = "xzr"
    m["wsp"] = "sp"
    return m


SUBREG_MAP = {
    "x86_64": _x86_64_subregs(),
    "i386": _i386_subregs(),
    "ppc32": {},
    "aarch64": _aarch64_subregs(),
    "mips32": {},
    # MIPS GPRs have no narrower aliases (a 32-bit op on MIPS64 still names
    # the full register); endianness does not change the register model.
    "mipsel": {},
    "mips64": {},
    "mips64el": {},
    # ARM GPRs (r0-r15) have no narrower aliases; sp/lr/pc are r13/r14/r15.
    "arm32": {"r13": "sp", "r14": "lr", "r15": "pc"},
}


# ----------------------------------------------------------------------- #
# Operand canonicalization
# ----------------------------------------------------------------------- #
#
# Both ground-truth items and analysis outputs are reduced to hashable
# tuples:
#   ("reg", name)
#   ("mem", base, index, scale, offset, size)


def _clean_reg(name):
    if name is None or name == "None":
        return None
    return str(name).lower()


def canon_expected(item):
    """Ground-truth JSON item -> canonical tuple."""
    if "reg" in item:
        return ("reg", _clean_reg(item["reg"]))
    if "mem" in item:
        m = item["mem"]
        index = _clean_reg(m.get("index"))
        scale = int(m.get("scale") or 1) if index is not None else 1
        return (
            "mem",
            _clean_reg(m.get("base")),
            index,
            scale,
            int(m.get("offset") or 0),
            int(m.get("size") or 0),
        )
    raise ValueError(f"malformed ground-truth item: {item!r}")


def canon_actual(op):
    """Operand object from analyze -> canonical tuple."""
    # Imported lazily so canonicalization is testable without smallworld.
    from smallworld.instructions import RegisterOperand
    from smallworld.instructions.instructions import MemoryReferenceOperand

    if isinstance(op, RegisterOperand):
        return ("reg", _clean_reg(op.name))
    if isinstance(op, MemoryReferenceOperand):
        base = _clean_reg(getattr(op, "base", None))
        index = _clean_reg(getattr(op, "index", None))
        scale = int(getattr(op, "scale", 1) or 1) if index is not None else 1
        offset = int(getattr(op, "offset", 0) or 0)
        size = int(getattr(op, "size", 0) or 0)
        return ("mem", base, index, scale, offset, size)
    return ("other", repr(op))


# FP status/exception bit registers, dropped like integer flags in the
# normalized comparison (Ghidra models PPC's FPSCR as ~30 fp_* bits).
FLAG_PATTERNS = {
    "ppc32": re.compile(r"fp_\w+|fpscr"),
}

# The program counter is excluded from ground truth by convention
# (README rule 3); some Ghidra models emit it explicitly (AArch64
# br/ret write pc), so the normalized comparison drops it.
PC_REGS = {
    "x86_64": {"rip"},
    "i386": {"eip"},
    "ppc32": {"pc"},
    "aarch64": {"pc"},
    "mips32": {"pc"},
    "mipsel": {"pc"},
    "mips64": {"pc"},
    "mips64el": {"pc"},
    "arm32": {"pc"},
}


def _alias(isa, name):
    """Map tool-specific register names onto a per-ISA canonical form
    shared by ground truth and analysis output."""
    if isa in ("x86_64", "i386"):
        # Ghidra models SSE lanes as pseudo-registers: xmm0_qa, xmm0_da...
        m = re.fullmatch(r"([xyz]mm\d+)_[a-z]+", name)
        if m:
            return m.group(1)
    if isa == "aarch64":
        # b0/h0/s0/d0/q0/z0 are all views of vector register 0
        m = re.fullmatch(r"[bhsdqz](\d+)", name)
        if m:
            return f"v{m.group(1)}"
    if isa in ("mips32", "mipsel", "mips64", "mips64el") and name == "s8":
        # Capstone calls register 30 "fp"; Ghidra calls it "s8"
        return "fp"
    if isa in ("mips64", "mips64el"):
        # Ghidra's MIPS64 model names the low/high 32-bit views of a 64-bit
        # GPR as <reg>_lo / <reg>_hi. A 32-bit MIPS64 op (addu, sll, lw, ...)
        # operates on the _lo view and sign-extends into the full register;
        # collapse both views to the architectural register for use/def, the
        # same way x86 eax->rax and AArch64 w3->x3 are handled.
        m = re.fullmatch(r"(.+)_(lo|hi)", name)
        if m:
            return m.group(1)
    return name


def normalize(item, isa):
    """Canonical tuple -> normalized tuple, or None if it should be dropped
    from the normalized comparison (flag and pc registers)."""
    subregs = SUBREG_MAP[isa]
    mod = 1 << ADDRESS_BITS[isa]

    def fixreg(r):
        if r is None:
            return None
        r = _alias(isa, r)
        return subregs.get(r, r)

    if item[0] == "reg":
        name = _alias(isa, item[1])
        if name in FLAG_REGS[isa] or name in PC_REGS[isa]:
            return None
        pattern = FLAG_PATTERNS.get(isa)
        if pattern is not None and pattern.fullmatch(name):
            return None
        return ("reg", subregs.get(name, name))
    if item[0] == "mem":
        _, base, index, scale, offset, size = item
        return ("mem", fixreg(base), fixreg(index), scale, offset % mod, size)
    return item


def fmt_item(item):
    if item is None:
        return "<dropped>"
    if item[0] == "reg":
        return item[1]
    if item[0] == "mem":
        _, base, index, scale, offset, size = item
        s = ""
        if base:
            s += base
        if index:
            s += f"+{scale}*{index}" if s else f"{scale}*{index}"
        if offset or not s:
            s += f"{offset:+#x}" if s else f"{offset:#x}"
        return f"mem[{s}]:{size}"
    return item[1]


# ----------------------------------------------------------------------- #
# Comparison
# ----------------------------------------------------------------------- #


def compare(expected, optional, actual):
    """Set comparison where `optional` items are allowed but not required.

    Returns (ok, missing, extra).
    """
    expected = set(expected)
    optional = set(optional)
    actual = set(actual)
    missing = expected - actual
    extra = actual - expected - optional
    return (not missing and not extra), missing, extra


def check_entry(entry, corpus, analyze):
    isa = corpus["isa"]
    lang = corpus["ghidra_lang"]
    base = int(corpus["base_address"])
    raw = bytes.fromhex(entry["bytes"])

    result = {
        "isa": isa,
        "asm": entry["asm"],
        "bytes": entry["bytes"],
        "categories": entry.get("categories", []),
        "status": None,
    }

    try:
        analyzed = analyze(raw, lang, base)
    except Exception as exc:  # noqa: BLE001 - we want everything
        result["status"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["traceback"] = traceback.format_exc(limit=6)
        return result

    if len(analyzed) != 1:
        result["status"] = "decode"
        result["error"] = (
            f"decoded to {len(analyzed)} instructions: "
            f"{[r['instr'] for r in analyzed]}"
        )
        return result

    result["ghidra_disasm"] = analyzed[0]["instr"]

    exp = {
        "use": [canon_expected(i) for i in entry.get("uses", [])],
        "def": [canon_expected(i) for i in entry.get("defs", [])],
    }
    opt = {
        "use": [canon_expected(i) for i in entry.get("uses_optional", [])],
        "def": [canon_expected(i) for i in entry.get("defs_optional", [])],
    }
    act = {
        "use": [canon_actual(o) for o in analyzed[0]["use"]],
        "def": [canon_actual(o) for o in analyzed[0]["def"]],
    }

    strict_ok = True
    norm_ok = True
    for kind in ("use", "def"):
        ok, missing, extra = compare(exp[kind], opt[kind], act[kind])
        strict_ok &= ok
        result[f"missing_{kind}"] = sorted(fmt_item(i) for i in missing)
        result[f"extra_{kind}"] = sorted(fmt_item(i) for i in extra)

        def norm_all(items):
            out = set()
            for i in items:
                n = normalize(i, isa)
                if n is not None:
                    out.add(n)
            return out

        n_ok, n_missing, n_extra = compare(
            norm_all(exp[kind]),
            norm_all(opt[kind]),
            norm_all(act[kind]),
        )
        norm_ok &= n_ok
        result[f"missing_{kind}_norm"] = sorted(fmt_item(i) for i in n_missing)
        result[f"extra_{kind}_norm"] = sorted(fmt_item(i) for i in n_extra)

    result["actual_use"] = sorted(fmt_item(i) for i in act["use"])
    result["actual_def"] = sorted(fmt_item(i) for i in act["def"])

    if strict_ok:
        result["status"] = "pass"
    elif norm_ok:
        result["status"] = "pass-normalized"
    else:
        result["status"] = "mismatch"
    return result


# ----------------------------------------------------------------------- #
# Driver / reporting
# ----------------------------------------------------------------------- #

STATUS_ORDER = ["pass", "pass-normalized", "mismatch", "error", "decode"]


def load_corpora(corpus_dir, isas):
    corpora = []
    for path in sorted(glob.glob(os.path.join(corpus_dir, "corpus_*.json"))):
        with open(path) as f:
            corpus = json.load(f)
        if isas and corpus["isa"] not in isas:
            continue
        corpus["_path"] = path
        corpora.append(corpus)
    return corpora


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--isa", action="append", default=None, help="restrict to this ISA (repeatable)"
    )
    ap.add_argument("--corpus-dir", default=HERE)
    ap.add_argument(
        "--json", default=None, help="write full per-entry results to this file"
    )
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print per-entry detail for non-passing entries",
    )
    ap.add_argument(
        "--max-details",
        type=int,
        default=15,
        help="max non-passing entries detailed per ISA (with -v)",
    )
    args = ap.parse_args(argv)

    corpora = load_corpora(args.corpus_dir, args.isa)
    if not corpora:
        print("no corpus files found", file=sys.stderr)
        return 2

    from smallworld.instructions.pcode_use_def import analyze

    all_results = []
    for corpus in corpora:
        isa = corpus["isa"]
        results = []
        for entry in corpus["entries"]:
            results.append(check_entry(entry, corpus, analyze))
        all_results.extend(results)

        counts = {s: 0 for s in STATUS_ORDER}
        for r in results:
            counts[r["status"]] += 1
        total = len(results)
        agree = counts["pass"] + counts["pass-normalized"]
        print(
            f"\n=== {isa} ({total} instructions) "
            f"[{os.path.basename(corpus['_path'])}] ==="
        )
        for s in STATUS_ORDER:
            if counts[s]:
                print(f"  {s:16s} {counts[s]:4d}")
        print(
            f"  agreement (normalized): {agree}/{total} "
            f"({100.0 * agree / total:.0f}%)"
        )

        if args.verbose:
            shown = 0
            for r in results:
                if r["status"] in ("pass",):
                    continue
                if shown >= args.max_details:
                    remaining = sum(1 for x in results if x["status"] != "pass") - shown
                    print(
                        f"  ... {remaining} more non-passing entries "
                        f"(see --json report)"
                    )
                    break
                shown += 1
                print(f"  [{r['status']}] {r['asm']}  ({r['bytes']})")
                if r["status"] in ("error", "decode"):
                    print(f"      {r['error']}")
                    continue
                for kind in ("use", "def"):
                    for label, key in (
                        ("missing", f"missing_{kind}_norm"),
                        ("extra", f"extra_{kind}_norm"),
                    ):
                        if r.get(key):
                            print(f"      {kind} {label}: " f"{', '.join(r[key])}")
                print(
                    f"      analysis said: use={r['actual_use']} "
                    f"def={r['actual_def']}"
                )

    # Global summary
    counts = {s: 0 for s in STATUS_ORDER}
    for r in all_results:
        counts[r["status"]] += 1
    total = len(all_results)
    agree = counts["pass"] + counts["pass-normalized"]
    print(f"\n=== TOTAL: {total} instructions ===")
    for s in STATUS_ORDER:
        print(f"  {s:16s} {counts[s]:4d}")
    print(
        f"  agreement (normalized): {agree}/{total} " f"({100.0 * agree / total:.0f}%)"
    )

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"summary": counts, "results": all_results}, f, indent=2)
        print(f"\nfull report written to {args.json}")

    return 0 if agree == total else 1


if __name__ == "__main__":
    sys.exit(main())
