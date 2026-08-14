"""Berkeley TestFloat against SmallWorld's emulated FPUs.

TestFloat is the reference conformance suite for IEEE-754 arithmetic: it
generates the operand patterns that break naive implementations - denormals,
exponent boundaries, ties, signed zeroes, infinities, NaNs - and checks answers
against Berkeley SoftFloat.  The rest of the floating-point coverage in this
suite uses hand-picked operands whose results are exactly representable, which
is good for pinning down semantics but says nothing about rounding.  This
scenario is the opposite: thousands of adversarial cases per operation, checked
bit-exactly.

``nix/testfloat.nix`` builds TestFloat-3e and SoftFloat-3e from upstream (nothing
is vendored here) and puts ``testfloat_gen``/``testfloat_ver`` on PATH inside
``nix develop``.  The harness sits between them::

    testfloat_gen f32_add  ->  operands + SoftFloat's reference + flags
                               (we keep only the operands)
    guest kernel           ->  our result for each operand set
    testfloat_ver f32_add  ->  recomputes the reference, reports mismatches

**Results are compared; exception flags are not.**  Reading and clearing the FP
status register per operation is real per-architecture work - SuperH
``fpscr[6:2]``, x86 ``mxcsr``, ARM ``fpscr``, MIPS ``fcsr`` - so for now the
reference flag column is echoed back unchanged, which means ``testfloat_ver``
only ever reports *value* mismatches.  Every spec carries ``compares_flags``,
currently ``False`` everywhere, so the gap is visible in the code rather than
implied; the runner also prints it on every run.

``-checkNaNs`` is deliberately left off (its default).  SoftFloat's NaN-payload
propagation is fixed at build time by ``SPECIALIZE_TYPE`` - we build
``8086-SSE`` - so payloads are not comparable across the targets we emulate.
Everything else, including infinities and signed zeroes, is compared in full.

Guest kernel contract
---------------------

Per-case emulator round-trips are not an option: on PANDA, rewriting ``pc`` and
stepping again silently does nothing every other iteration (the step is consumed
re-synchronising, so ``pc`` stays put and no instruction executes).  So each run
loads one blob that loops in the guest:

===============  ==========================================================
``r_in``         input base; packed operands, target byte order, no padding
``r_out``        output base; one result per case
``r_count``      case count, greater than zero
entry            fixed offset per (precision, arity) - see ``Kernel``
exit             a single shared ``done`` label every loop branches to
===============  ==========================================================

Each architecture therefore needs exactly one assembly file holding four loops
(f32/f64 x binary/unary) at fixed offsets.  The arithmetic instruction inside a
loop is patched by the harness, which is why four loops cover every operation
rather than needing one blob per operation.  The patch table is verified by
disassembly in ``check_patches`` so the byte surgery cannot rot silently.

This module is only the plumbing.  The kernels, encoding tables and skip
reasons live one per architecture in ``testfloat_arch``, which discovers its own
modules - see that package's docstring for how to add an architecture.  Nothing
here should need to change to support a new one.

Running more cases
------------------

The default is a few thousand cases per operation, which keeps CI honest without
being slow.  TestFloat's level-1 sets are tens of thousands per function; for an
exhaustive local sweep pass a larger count::

    python3 tests/run_case.py testfloat sh2a.pcode --cases 46464

Cases are taken deterministically from the front of the generated list, so a
failure at a given count always reproduces.
"""

from __future__ import annotations

import logging
import shutil
import struct
import subprocess
import sys
from typing import Sequence, Tuple

from .common import TestsPath, make_emulator, make_platform, split_variant
from .spec import ScenarioInfo, from_arch_table, just_run
from .testfloat_arch import (
    EXIT_OFFSET,
    SPECS,
    VARIANT_SKIPS,
    TestFloatSpec,
    kernel_key,
    normalise_disasm,
    op_shape,
    skip_reason,
)

NATIVE_PARITY = True

_SCENARIO = "testfloat"

CODE_BASE = 0x1000
IN_BASE = 0x00100000
OUT_BASE = 0x00200000
REGION_SIZE = 0x00100000

DEFAULT_CASES = 3000

SCENARIO_PREFIXES = ((_SCENARIO, _SCENARIO),)


# --------------------------------------------------------------------------
# TestFloat plumbing
# --------------------------------------------------------------------------
def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(
            f"{name} not on PATH; it comes from nix/testfloat.nix, so run this "
            f"inside `nix develop .`"
        )
    return path


def generate_cases(func: str, count: int) -> list[Sequence[str]]:
    """Operand columns for the first ``count`` cases of ``func``.

    Read to completion rather than piped through `head`: closing the pipe early
    kills testfloat_gen with SIGPIPE, which surfaces as a spurious failure.
    """
    out = subprocess.run(
        [_tool("testfloat_gen"), func],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    _, arity = op_shape(func)
    cases = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < arity + 2:
            continue
        cases.append(fields)
        if len(cases) >= count:
            break
    return cases


def verify(func: str, lines: Sequence[str]) -> Tuple[bool, str, str]:
    """Hand results to testfloat_ver; return (ok, full report, verdict line).

    testfloat_ver splits its output across stdout and stderr - the per-case
    mismatch dump goes to one and the summary to the other - so the streams are
    kept apart and the verdict is picked by content rather than by position.
    """
    proc = subprocess.run(
        [_tool("testfloat_ver"), func],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
    )
    report = "\n".join(
        part for part in (proc.stdout.strip(), proc.stderr.strip()) if part
    )
    ok = "no errors found" in report
    verdict = next(
        (
            line.strip()
            for line in report.splitlines()
            if "no errors found" in line or "errors found" in line
        ),
        report.splitlines()[-1] if report else "(no output)",
    )
    return ok, report, verdict


# --------------------------------------------------------------------------
# Running one (arch, engine, function)
# --------------------------------------------------------------------------
def _pack(values: Sequence[int], width: int, big: bool) -> bytes:
    fmt = (">" if big else "<") + ("I" if width == 4 else "Q")
    return b"".join(struct.pack(fmt, v) for v in values)


def _unpack(data: bytes, width: int, big: bool) -> list[int]:
    fmt = (">" if big else "<") + ("I" if width == 4 else "Q")
    return [
        struct.unpack(fmt, data[i : i + width])[0] for i in range(0, len(data), width)
    ]


def _is_nan(value: int, width: int) -> bool:
    exp_mask, frac_mask = (
        (0x7F800000, 0x007FFFFF)
        if width == 4
        else (0x7FF0000000000000, 0x000FFFFFFFFFFFFF)
    )
    return value & exp_mask == exp_mask and bool(value & frac_mask)


def _drop_nan_results(
    cases: Sequence[Sequence[str]], arity: int, width: int
) -> Tuple[list[Sequence[str]], int]:
    """Remove cases whose reference result is a NaN.

    IEEE 754 does not specify NaN payloads, and SuperH deliberately does not
    propagate them: every NaN-producing operation returns the fixed qNaN
    0x7FBFFFFF. TestFloat's reference is built with SPECIALIZE_TYPE=8086-SSE,
    which propagates an input payload instead, so comparing these would fail
    PANDA -- the backend that models the hardware most faithfully -- while
    passing backends that happen to match x86. testfloat_ver re-derives the
    reference from the operands rather than reading it from the file, so the
    payload cannot be normalised in place; the rows have to come out.
    """
    kept = [c for c in cases if not _is_nan(int(c[arity], 16), width)]
    return kept, len(cases) - len(kept)


def run_function(spec: TestFloatSpec, variant: str, func: str, count: int) -> int:
    import smallworld

    arch, engine = split_variant(variant)
    width, arity = op_shape(func)
    precision = func.split("_")[0]
    op = func.split("_", 1)[1]

    kernel = spec.kernels[kernel_key(func)]
    if op not in kernel.patches:
        print(f"SKIP {func}: no encoding for operation {op!r} on {arch}")
        return 0

    cases = generate_cases(func, count)
    if not cases:
        print(f"FAIL {func}: testfloat_gen produced no cases")
        return 1
    cases, dropped = _drop_nan_results(cases, arity, width)
    if not cases:
        print(f"FAIL {func}: every generated case had a NaN result")
        return 1

    big = spec.platform.byteorder == "BIG"
    operands = [[int(f, 16) for f in c[:arity]] for c in cases]
    ref_flags = [c[-1] for c in cases]

    flat: list[int] = []
    for row in operands:
        flat.extend(row)

    smallworld.logging.setup_logging(level=logging.WARNING)
    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    blob = bytearray((TestsPath / _SCENARIO / f"{_SCENARIO}.{arch}.bin").read_bytes())
    patch = kernel.patches[op]
    blob[kernel.patch_offset : kernel.patch_offset + len(patch)] = patch
    code = smallworld.state.memory.code.Executable.from_bytes(
        bytes(blob), address=CODE_BASE
    )
    machine.add(code)

    inputs = smallworld.state.memory.RawMemory.from_bytes(
        _pack(flat, width, big), address=IN_BASE
    )
    machine.add(inputs)
    outputs = smallworld.state.memory.RawMemory.from_bytes(
        b"\0" * (len(cases) * width), address=OUT_BASE
    )
    machine.add(outputs)

    stack = smallworld.state.memory.stack.Stack.for_platform(
        platform, spec.stack_base, spec.stack_size
    )
    machine.add(stack)

    getattr(cpu, "sp").set(stack.get_pointer())
    getattr(cpu, "pc").set(CODE_BASE + kernel.entry)
    getattr(cpu, spec.in_register).set(IN_BASE)
    getattr(cpu, spec.out_register).set(OUT_BASE)
    getattr(cpu, spec.count_register).set(len(cases))
    for name, value in spec.setup.get(precision, {}).items():
        getattr(cpu, name).set(value)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(CODE_BASE + EXIT_OFFSET)
    machine.emulate(emulator)

    raw = emulator.read_memory_content(OUT_BASE, len(cases) * width)
    results = _unpack(raw, width, big)

    lines = [
        " ".join(c[:arity] + [f"{r:0{width * 2}X}", flags])
        for c, r, flags in zip(cases, results, ref_flags)
    ]
    ok, report, verdict = verify(func, lines)
    status = "PASS" if ok else "FAIL"
    note = f" [{dropped} NaN-result cases not compared]" if dropped else ""
    print(f"{status} {func:10} {variant:16} {verdict}{note}")
    if not ok:
        for line in report.splitlines()[:14]:
            print(f"    {line}")
    return 0 if ok else 1


def check_patches(arch: str, spec: TestFloatSpec, verbose: bool = True) -> int:
    """Disassemble every patched instruction so the byte surgery cannot rot.

    The patch tables encode raw opcodes at a fixed offset. If a kernel's layout
    shifts, that offset lands on the wrong instruction and the run reports
    results for an operation nobody asked for -- confidently, and with no
    outward sign. Each architecture therefore records the disassembly it expects
    and this compares against it, mnemonic *and* operands, before any result is
    believed.

    The expectation has to come from the architecture rather than be derived
    here: every target spells these operations differently (``fadd fr1, fr0``,
    ``addss xmm0, xmm1``, ``vadd.f32 s0, s0, s1``, ``add.s $f0, $f0, $f1``), and
    the operands are the half that catches the mistake this guard exists for --
    a register field belonging to the wrong precision.

    A kernel with no expectation for an operation counts as a failure rather
    than a pass. An unverified patch table is precisely the state being ruled
    out, so silence about it would defeat the purpose.
    """
    import capstone

    import smallworld

    platform = make_platform(smallworld, spec.platform)
    platdef = smallworld.platforms.PlatformDef.for_platform(platform)
    md = capstone.Cs(platdef.capstone_arch, platdef.capstone_mode)
    blob = bytearray((TestsPath / _SCENARIO / f"{_SCENARIO}.{arch}.bin").read_bytes())

    failures = 0
    for key, kernel in sorted(spec.kernels.items()):
        for op, patch in sorted(kernel.patches.items()):
            probe = bytearray(blob)
            probe[kernel.patch_offset : kernel.patch_offset + len(patch)] = patch
            decoded = list(
                md.disasm(bytes(probe[kernel.patch_offset :]), kernel.patch_offset)
            )
            if decoded:
                actual = f"{decoded[0].mnemonic} {decoded[0].op_str}".strip()
            else:
                actual = "<undecodable>"

            expected = kernel.expect.get(op)
            if expected is None:
                note = "  NO EXPECTATION RECORDED - add one to the arch module"
                ok = False
            else:
                ok = normalise_disasm(actual) == normalise_disasm(expected)
                note = "" if ok else f"  EXPECTED {expected}"

            if verbose or not ok:
                print(
                    f"  {key:11} {op:5} @{kernel.patch_offset:#05x} -> "
                    f"{actual:24}{note}"
                )
            failures += 0 if ok else 1
    return failures


def can_run(scenario: str, variant: str) -> bool:
    if scenario != _SCENARIO:
        return False
    arch, engine = split_variant(variant)
    return arch in SPECS and engine in SPECS[arch].engines


# Which functions each precision covers. Breadth of architectures matters more
# than depth of operations here, so this is a representative set rather than
# TestFloat's full catalogue: the four basic arithmetic ops exercise every
# rounding path, and sqrt is the one unary op with interesting rounding.
FUNCTIONS_F32 = ("f32_add", "f32_sub", "f32_mul", "f32_div", "f32_sqrt")
FUNCTIONS_F64 = ("f64_add", "f64_sub", "f64_mul", "f64_div", "f64_sqrt")


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog=f"run_case.py {scenario} {variant}")
    parser.add_argument("--cases", type=int, default=DEFAULT_CASES)
    parser.add_argument("--functions", default=None, help="comma-separated override")
    parser.add_argument(
        "--check-patches",
        action="store_true",
        help="only verify the opcode patch table disassembles as intended",
    )
    opts = parser.parse_args(list(args))

    arch, engine = split_variant(variant)
    spec = SPECS[arch]

    if opts.check_patches:
        return 1 if check_patches(arch, spec) else 0

    if opts.functions:
        functions = tuple(opts.functions.split(","))
    else:
        functions = FUNCTIONS_F32 + FUNCTIONS_F64

    # Verify the byte surgery on every run, not just when asked. It is pure
    # disassembly and costs nothing next to the emulation, and a guard that only
    # a human ever invokes is a guard that silently stops holding. Quiet unless
    # something is wrong; a bad patch table makes every result meaningless, so
    # this fails the run rather than warning.
    if check_patches(arch, spec, verbose=False):
        print(f"FAIL {variant}: patch table does not disassemble as intended")
        return 1

    print(
        f"testfloat {variant}: {opts.cases} cases/function, "
        f"comparing results only (exception flags not compared: "
        f"compares_flags={spec.compares_flags})"
    )

    # PANDA aborts in qemu_add_drive_opts ("ran out of space in
    # drive_config_groups") the moment a second PandaEmulator is constructed in
    # one process, and every function needs its own emulator. Fan out to one
    # child process per function so the usual `run_case.py testfloat sh4.panda`
    # invocation still runs the whole set.
    if engine == "panda" and len(functions) > 1:
        return _run_each_in_subprocess(variant, functions, opts.cases)

    failures = 0
    for func in functions:
        reason = skip_reason(arch, engine, func)
        if reason is not None:
            print(f"SKIP {func:10} {variant:16} {reason}")
            continue
        failures += run_function(spec, variant, func, opts.cases)
    return 1 if failures else 0


def _run_each_in_subprocess(variant: str, functions: Sequence[str], cases: int) -> int:
    failed = False
    for func in functions:
        proc = subprocess.run(
            [
                sys.executable,
                str(TestsPath / "run_case.py"),
                _SCENARIO,
                variant,
                "--functions",
                func,
                "--cases",
                str(cases),
            ],
            cwd=str(TestsPath),
            check=False,
            capture_output=True,
            text=True,
        )
        for line in proc.stdout.splitlines():
            if line.startswith(("PASS ", "FAIL ", "SKIP ")) or line.startswith("    "):
                print(line)
        if proc.returncode != 0:
            failed = True
            if not any(line.startswith("FAIL ") for line in proc.stdout.splitlines()):
                tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
                print(f"FAIL {func:10} {variant:16} child exited {proc.returncode}")
                for line in tail:
                    print(f"    {line}")
    return 1 if failed else 0


SCENARIO_INFO = ScenarioInfo(
    prefix=_SCENARIO,
    scenario=_SCENARIO,
    tags=("scenario", _SCENARIO, "fpu", "float"),
    variants_source=from_arch_table(SPECS, skip_reasons=VARIANT_SKIPS),
    run_factory=just_run(),
)
