from __future__ import annotations

import io
import pathlib
import sys
import typing

from .coverage import wrap_python_command
from .framework import CaseRunner, CaseSpec, RepoRoot, TestsPath
from .legacy_library import LEGACY_LIBRARY_MODELS
from .legacy_matrix import LEGACY_MATRIX
from .parity import check_manifest_parity, check_registered_scenario_parity

PYTHON = sys.executable

VariantInfo = tuple[str, typing.Optional[str], dict[str, typing.Any]]


def _variant_from_entry(
    suite_name: str,
    entry: dict[str, typing.Any],
    *,
    prefix: str | None = None,
) -> VariantInfo:
    if "run_test" in entry:
        run_test = entry["run_test"]
        args = run_test.get("args", [])
        kwargs = run_test.get("kwargs", {})
        if args:
            return _normalise_variant(str(args[0])), entry["skip_reason"], kwargs
        if "arch" in kwargs:
            return _normalise_variant(str(kwargs["arch"])), entry["skip_reason"], kwargs
        if "kind" in kwargs:
            return _normalise_variant(str(kwargs["kind"])), entry["skip_reason"], kwargs

    stem = entry["name"]
    if stem.startswith("test_"):
        stem = stem[5:]
    if prefix and stem.startswith(f"{prefix}_"):
        stem = stem[len(prefix) + 1 :]

    default_suffix: str | None = None
    if suite_name.endswith("Angr"):
        default_suffix = "angr"
    elif suite_name.endswith("Ghidra"):
        default_suffix = "pcode"
    elif suite_name.endswith("Panda"):
        default_suffix = "panda"

    parts = stem.split("_")
    explicit_suffix = None
    if parts[-1] in {"angr", "panda", "pcode", "ghidra", "unicorn"}:
        explicit_suffix = parts[-1]
        stem = "_".join(parts[:-1])

    suffix = explicit_suffix or default_suffix
    if suffix in {None, "unicorn"}:
        variant = stem
    elif suffix == "ghidra":
        variant = f"{stem}.pcode"
    else:
        variant = f"{stem}.{suffix}"
    return _normalise_variant(variant), entry["skip_reason"], {}


def _normalise_variant(variant: str) -> str:
    return variant.replace(".ghidra", ".pcode")


def _legacy_variants(
    suite_names: tuple[str, ...],
    *,
    prefix: str | None = None,
) -> list[VariantInfo]:
    variants: list[VariantInfo] = []
    for suite_name in suite_names:
        for entry in LEGACY_MATRIX.get(suite_name, []):
            variants.append(_variant_from_entry(suite_name, entry, prefix=prefix))
    seen: set[str] = set()
    ordered: list[VariantInfo] = []
    for variant, skip_reason, kwargs in variants:
        if variant in seen:
            continue
        seen.add(variant)
        ordered.append((variant, skip_reason, kwargs))
    return ordered


def _case(
    case_id: str,
    *tags: str,
    run: typing.Callable[[CaseRunner], None],
    skip_reason: str | None = None,
    weight: int = 1,
    description: str | None = None,
) -> CaseSpec:
    return CaseSpec(
        id=case_id,
        tags=tuple(tags),
        run=run,
        skip_reason=skip_reason,
        weight=weight,
        description=description,
    )


def _run_case_command(
    runner: CaseRunner,
    scenario: str,
    variant: str,
    *args: str,
    stdin: str | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> tuple[str, str]:
    result = runner.command(
        [PYTHON, "run_case.py", scenario, variant, *args],
        cwd=TestsPath,
        stdin=stdin,
        env=env,
        check=check,
    )
    return result.stdout, result.stderr


def _run_script(
    runner: CaseRunner,
    script: str,
    *args: str,
    stdin: str | None = None,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> tuple[str, str]:
    result = runner.command(
        [PYTHON, script, *args],
        cwd=cwd or TestsPath,
        stdin=stdin,
        env=env,
        check=check,
    )
    return result.stdout, result.stderr


def _run_afl_showmap(
    runner: CaseRunner,
    *,
    inputs_dir: pathlib.Path,
    target: list[str],
    cwd: pathlib.Path | None = None,
    stdin: str | None = None,
    check: bool = True,
) -> tuple[str, str]:
    result = runner.command(
        [
            "afl-showmap",
            "-C",
            "-t",
            "10000",
            "-U",
            "-m",
            "none",
            "-i",
            str(inputs_dir),
            "-o",
            "/dev/stdout",
            "--",
            *target,
        ],
        cwd=cwd or TestsPath,
        stdin=stdin,
        check=check,
    )
    return result.stdout, result.stderr


def _build_square_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, kwargs in _legacy_variants(
        ("SquareTests",), prefix="square"
    ):
        signext = bool(kwargs.get("signext", False))
        sixteenbit = bool(kwargs.get("sixteenbit", False))

        def run(
            runner: CaseRunner,
            *,
            variant: str = variant,
            signext: bool = signext,
            sixteenbit: bool = sixteenbit,
        ) -> None:
            numbers = [5, 1337]
            if not sixteenbit:
                numbers.append(65535)
            for number in numbers:
                stdout, _ = _run_case_command(runner, "square", variant, str(number))
                result = number**2
                if signext and result & 0xFFFFFFFF80000000 != 0:
                    result = 0xFFFFFFFF80000000 | result
                if sixteenbit:
                    result &= 0xFFFF
                runner.assert_contains(stdout, rf"{result:#x}")

        cases.append(
            _case(
                f"square:{variant}",
                "scenario",
                "square",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_branch_cases() -> list[CaseSpec]:
    cases = []
    variants = _legacy_variants(
        (
            "BranchTestsAngr",
            "BranchTestsGhidra",
            "BranchTestsPanda",
            "BranchTestsUnicorn",
        ),
        prefix="branch",
    )
    for variant, skip_reason, _ in variants:

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            for number, expected in ((99, "0x0"), (100, "0x1"), (101, "0x0")):
                stdout, _ = _run_case_command(runner, "branch", variant, str(number))
                runner.assert_contains(stdout, expected)

        cases.append(
            _case(
                f"branch:{variant}",
                "scenario",
                "branch",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_call_cases() -> list[CaseSpec]:
    cases = []
    variants = _legacy_variants(
        ("CallTestsAngr", "CallTestsGhidra", "CallTestsPanda", "CallTestsUnicorn"),
        prefix="call",
    )
    for variant, skip_reason, kwargs in variants:
        signext = bool(kwargs.get("signext", False))

        def run(
            runner: CaseRunner, *, variant: str = variant, signext: bool = signext
        ) -> None:
            outputs = (
                (0, 0xFFFFFFFFFFFFFFF9 if signext else 0xFFFFFFF9),
                (101, 0x321),
                (65536, 0x21),
            )
            for number, expected in outputs:
                stdout, _ = _run_case_command(runner, "call", variant, str(number))
                runner.assert_contains(stdout, f"{expected:#x}")

        cases.append(
            _case(
                f"call:{variant}", "scenario", "call", run=run, skip_reason=skip_reason
            )
        )
    return cases


def _build_dma_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("DMATests",), prefix="dma"):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_case_command(runner, "dma", variant, "10", "2")
            runner.assert_contains(stdout, "0x5")

        cases.append(
            _case(f"dma:{variant}", "scenario", "dma", run=run, skip_reason=skip_reason)
        )
    return cases


def _build_recursion_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(
        ("RecursionTests",), prefix="recursion"
    ):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            for number, expected in (
                (-1, 91),
                (0, 91),
                (100, 91),
                (101, 91),
                (102, 92),
            ):
                stdout, _ = _run_case_command(runner, "recursion", variant, str(number))
                runner.assert_contains(stdout, f"{expected:#x}")

        cases.append(
            _case(
                f"recursion:{variant}",
                "scenario",
                "recursion",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_stack_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, kwargs in _legacy_variants(
        ("StackTests",), prefix="stack"
    ):
        expected = str(kwargs.get("res", "0xaaaaaaaa"))

        def run(
            runner: CaseRunner, *, variant: str = variant, expected: str = expected
        ) -> None:
            stdout, _ = _run_case_command(runner, "stack", variant)
            runner.assert_contains(stdout.lower(), expected.lower())

        cases.append(
            _case(
                f"stack:{variant}",
                "scenario",
                "stack",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_block_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("BlockTests",), prefix="block"):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_case_command(runner, "block", variant, "2740", "1760")
            for parts in (
                ("1", "1760"),
                ("2", "1760"),
                ("3", "0"),
                ("4", "1"),
                ("5", "980"),
                ("6", "20"),
            ):
                runner.assert_line_contains(stdout, *parts)

        cases.append(
            _case(
                f"block:{variant}",
                "scenario",
                "block",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_strlen_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("StrlenTests",), prefix="strlen"):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_case_command(runner, "strlen", variant, "")
            runner.assert_contains(stdout, "0x0")
            stdout, _ = _run_case_command(runner, "strlen", variant, "foobar")
            runner.assert_contains(stdout, "0x6")

        cases.append(
            _case(
                f"strlen:{variant}",
                "scenario",
                "strlen",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_hooking_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, kwargs in _legacy_variants(
        ("HookingTests",), prefix="hooking"
    ):
        expected = "oo bar baz" if kwargs.get("heckingMIPS64", False) else "foo bar baz"

        def run(
            runner: CaseRunner, *, variant: str = variant, expected: str = expected
        ) -> None:
            stdout, _ = _run_case_command(
                runner, "hooking", variant, stdin="foo bar baz"
            )
            runner.assert_contains(stdout, expected)

        cases.append(
            _case(
                f"hooking:{variant}",
                "scenario",
                "hooking",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_elf_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("ElfTests",), prefix="elf"):
        cases.append(
            _case(
                f"elf:{variant}",
                "scenario",
                "elf",
                run=lambda runner, variant=variant: _run_case_command(
                    runner, "elf", variant, "foobar"
                ),
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_rela_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("RelaTests",), prefix="rela"):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_case_command(runner, "rela", variant)
            runner.assert_contains(stdout, "Hello, world!")

        cases.append(
            _case(
                f"rela:{variant}", "scenario", "rela", run=run, skip_reason=skip_reason
            )
        )
    return cases


def _build_static_rela_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("StaticRelaTests",)):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_script(
                runner, f"static_rela/static_rela.{variant}.py", "foobar"
            )
            runner.assert_contains(stdout, "foobar")

        cases.append(
            _case(
                f"static_rela:{variant}",
                "scenario",
                "static_rela",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_link_elf_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(
        ("LinkElfTests",), prefix="link_elf"
    ):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_case_command(runner, "link_elf", variant, "42")
            runner.assert_contains(stdout.lower(), "0x2a")

        cases.append(
            _case(
                f"link_elf:{variant}",
                "scenario",
                "link_elf",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_elf_core_load_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(
        ("ElfCoreLoadTests",), prefix="elf_core"
    ):
        cases.append(
            _case(
                f"elf_core.load:{variant}",
                "scenario",
                "elf_core",
                "load",
                run=lambda runner, variant=variant: _run_script(
                    runner, f"elf_core/load/elf_core.{variant}.py"
                ),
                skip_reason=skip_reason,
                weight=2,
            )
        )
    return cases


def _build_elf_core_actuate_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("ElfCoreActuateTests",)):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_script(runner, f"elf_core/actuate/elf_core.{variant}.py")
            runner.assert_contains(stdout, "foobar")

        cases.append(
            _case(
                f"elf_core.actuate:{variant}",
                "scenario",
                "elf_core",
                run=run,
                skip_reason=skip_reason,
                weight=2,
            )
        )
    return cases


def _build_pe_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("PETests",), prefix="pe"):
        cases.append(
            _case(
                f"pe:{variant}",
                "scenario",
                "pe",
                run=lambda runner, variant=variant: _run_case_command(
                    runner, "pe", variant
                ),
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_link_pe_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("LinkPETests",), prefix="pe"):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_case_command(runner, "link_pe", variant, "42")
            runner.assert_contains(stdout.lower(), "0x2a")

        cases.append(
            _case(
                f"link_pe:{variant}",
                "scenario",
                "link_pe",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_floats_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("FloatsTests",), prefix="floats"):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_script(runner, f"floats/floats.{variant}.py", "2.2", "1.1")
            runner.assert_contains(stdout, "3.3")

        cases.append(
            _case(
                f"floats:{variant}",
                "scenario",
                "floats",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_syscall_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(
        ("SyscallTests",), prefix="syscall"
    ):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_script(runner, f"syscall/syscall.{variant}.py")
            runner.assert_contains(stdout, "Executing syscall")
            runner.assert_contains(stdout, "Executing a write syscall")

        cases.append(
            _case(
                f"syscall:{variant}",
                "scenario",
                "syscall",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_static_buffer_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("StaticBufferTests",)):

        def run(runner: CaseRunner, *, variant: str = variant) -> None:
            stdout, _ = _run_case_command(runner, "static_buf", variant)
            runner.assert_contains(stdout.lower(), "0x4a1")

        cases.append(
            _case(
                f"static_buf:{variant}",
                "scenario",
                "static_buf",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_delay_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("DelayTests",)):
        cases.append(
            _case(
                f"delay:{variant}",
                "scenario",
                "delay",
                run=lambda runner, variant=variant: _run_script(
                    runner, f"delay/delay.{variant}.py"
                ),
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_exitpoint_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("ExitpointTests",)):
        cases.append(
            _case(
                f"exitpoint:{variant}",
                "scenario",
                "exitpoint",
                run=lambda runner, variant=variant: _run_case_command(
                    runner, "exitpoint", variant
                ),
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_unmapped_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("UnmappedTests",)):
        cases.append(
            _case(
                f"unmapped:{variant}",
                "scenario",
                "unmapped",
                run=lambda runner, variant=variant: _run_case_command(
                    runner, "unmapped", variant
                ),
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_symbolic_cases() -> list[CaseSpec]:
    symbolic_scripts = [
        ("symbolic:branch", "symbolic/branch.amd64.angr.symbolic.py", (), None),
        ("symbolic:dma", "symbolic/dma.amd64.angr.symbolic.py", ("10", "2"), None),
        (
            "symbolic:hooking",
            "symbolic/hooking.amd64.angr.symbolic.py",
            (),
            "foo bar baz",
        ),
        ("symbolic:square", "symbolic/square.amd64.angr.symbolic.py", (), None),
    ]
    cases = []
    for case_id, script, args, stdin in symbolic_scripts:
        cases.append(
            _case(
                case_id,
                "analysis",
                "symbolic",
                run=lambda runner, script=script, args=args, stdin=stdin: _run_script(
                    runner, script, *args, stdin=stdin
                ),
                weight=2,
            )
        )
    return cases


def _build_sysv_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("SysVModelTests",)):
        cases.append(
            _case(
                f"sysv:{variant}",
                "scenario",
                "sysv",
                run=lambda runner, variant=variant: _run_script(
                    runner, f"sysv/sysv.{variant}.py"
                ),
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_structure_cases() -> list[CaseSpec]:
    return [
        _case(
            "struct:amd64",
            "scenario",
            "struct",
            run=lambda runner: runner.assert_contains(
                _run_script(runner, "struct/struct.amd64.py")[0], "node_b->data = 42"
            ),
        ),
        _case(
            "struct:amd64.panda",
            "scenario",
            "struct",
            run=lambda runner: runner.assert_contains(
                _run_script(runner, "struct/struct.amd64.panda.py")[0],
                "node_b->data = 42",
            ),
        ),
    ]


def _build_memhook_cases() -> list[CaseSpec]:
    cases = []
    variants = _legacy_variants(("MemhookTests",))
    wide_variants = {
        "aarch64",
        "amd64",
        "i386",
        "la64",
        "mips64",
        "mips64el",
        "riscv64",
    }
    for variant, skip_reason, _ in variants:
        width = "8" if variant.split(".")[0] in wide_variants else "4"
        qux_addr = "0x1030" if width == "8" else "0x1034"
        script_variant = variant
        if variant.endswith(".pcode") and variant != "m68k.pcode":
            script_variant = variant[: -len(".pcode")] + ".ghidra"

        def run(
            runner: CaseRunner,
            *,
            script_variant: str = script_variant,
            width: str = width,
            qux_addr: str = qux_addr,
        ) -> None:
            stdout, _ = _run_script(
                runner,
                f"memhook/memhook.{script_variant}.py",
            )
            runner.assert_line_contains(stdout, "foo: read 1 bytes at 0x1004")
            runner.assert_line_contains(stdout, f"bar: read {width} bytes at 0x1010")
            runner.assert_line_contains(stdout, f"baz: read {width} bytes at 0x1020")
            runner.assert_line_contains(
                stdout, f"qux: read {width} bytes at {qux_addr}"
            )

        cases.append(
            _case(
                f"memhook:{variant}",
                "scenario",
                "memhook",
                run=run,
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_crash_triage_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("CrashTriageTests",)):
        cases.append(
            _case(
                f"crash_triage:{variant}",
                "analysis",
                "crash_triage",
                run=lambda runner, variant=variant: _run_script(
                    runner, f"crash_triage/crash_triage.{variant}.py"
                ),
                skip_reason=skip_reason,
                weight=2,
            )
        )
    return cases


def _build_trace_execution_cases() -> list[CaseSpec]:
    expectations = {
        "trace_executor/test_trace_is_correct_1.py": [
            "EXPECTED  trace digest matchest truth",
            "trace is 18 instructions which is correct",
            "execption args are what we expect",
            "exception type is correct -- EmulationReadUnmappedFailure",
            "exception operands are correct -- [(x86BSIDMemoryReferenceOperand([rax]), 0)]",
            "EXPECTED  No unexpected results",
        ],
        "trace_executor/test_trace_is_correct_2.py": [
            "EXPECTED  trace digest matchest truth",
            "trace is 100 instructions which is correct",
            "no exception in trace as expected",
            "EXPECTED  No unexpected results",
        ],
        "trace_executor/test_trace_reproduces.py": [
            "EXPECTED  trace digests are same",
            "EXPECTED  traces are same number of instructions",
            "EXPECTED  No unexpected results",
        ],
        "trace_executor/test_traces_different.py": [
            "EXPECTED  trace digests are not same which is as desired",
            "EXPECTED  No unexpected results",
        ],
        "trace_executor/test_branch_and_cmp_info.py": [
            "EXPECTED  One hint returned, as expected",
            "EXPECTED  num branches is 9, as expected",
            "EXPECTED  comparisons in trace are correct",
            "EXPECTED  immediates in trace are correct",
            "EXPECTED  No unexpected results",
        ],
    }
    cases = []
    for script, lines in expectations.items():

        def run(
            runner: CaseRunner, *, script: str = script, lines: list[str] = lines
        ) -> None:
            stdout, _ = _run_script(runner, script)
            for line in lines:
                runner.assert_line_contains(stdout, line)

        cases.append(
            _case(
                f"trace_execution:{pathlib.Path(script).stem}",
                "analysis",
                "trace_execution",
                run=run,
                weight=2,
            )
        )
    return cases


def _build_loop_detection_cases() -> list[CaseSpec]:
    expected = [
        "EXPECTED  found loop hint in hints1",
        "EXPECTED  found loop hint in hints2",
        "EXPECTED  loop hint in hints1 is correct",
        "EXPECTED  loop hint in hints2 is correct",
        "EXPECTED  No unexpected results",
    ]

    def run(runner: CaseRunner) -> None:
        stdout, _ = _run_script(runner, "loop_detector/test_loop_detector_1.py")
        for line in expected:
            runner.assert_contains(stdout, line)

    return [
        _case(
            "loop_detection:test_loop_detector_1", "analysis", "loop_detector", run=run
        )
    ]


def _build_coverage_frontier_cases() -> list[CaseSpec]:
    expectations = {
        "coverage_frontier/test_coverage_frontier_1.py": [
            "EXPECTED  One hint returned, as expected",
            "EXPECTED  One item in coverage frontier, as expected",
            "EXPECTED  Coverage frontier is as expected: 0x1158",
            "EXPECTED  No unexpected results",
        ],
        "coverage_frontier/test_coverage_frontier_2.py": [
            "EXPECTED  One hint returned, as expected",
            "EXPECTED  Zero items in coverage frontier, as expected",
            "EXPECTED  No unexpected results",
        ],
    }
    cases = []
    for script, lines in expectations.items():

        def run(
            runner: CaseRunner, *, script: str = script, lines: list[str] = lines
        ) -> None:
            stdout, _ = _run_script(runner, script)
            for line in lines:
                runner.assert_contains(stdout, line)

        cases.append(
            _case(
                f"coverage_frontier:{pathlib.Path(script).stem}",
                "analysis",
                "coverage_frontier",
                run=run,
            )
        )
    return cases


def _build_colorizer_cases() -> list[CaseSpec]:
    cases = []
    for name in ("test_colorizer_1.py", "test_colorizer_2.py"):

        def run(runner: CaseRunner, *, name: str = name) -> None:
            stdout, _ = _run_script(runner, f"colorizer/{name}")
            runner.assert_contains(stdout, "EXPECTED  No unexpected results")

        cases.append(
            _case(
                f"colorizer:{pathlib.Path(name).stem}", "analysis", "colorizer", run=run
            )
        )
    return cases


def _build_fsgsbase_cases() -> list[CaseSpec]:
    expected_lines = [
        "Here's where in fs segment lsb of rax is: 40. ... which is correct.  Looks like fs:[0x28] address is working properly.",
        "Here's where in gs segment lsb of rbx is: 19. ... which is correct.  Looks like gs:[0x13] address is working properly.",
    ]

    def run(runner: CaseRunner) -> None:
        stdout, _ = _run_script(runner, "fsgsbase/fsgsbase.amd64.py")
        for line in expected_lines:
            runner.assert_line_contains(stdout, line)

    return [_case("fsgsbase:amd64", "scenario", "fsgsbase", run=run)]


def _build_rtos_cases() -> list[CaseSpec]:
    demo_dir = RepoRoot / "use_cases" / "rtos_demo"
    inputs_dir = TestsPath / "rtos_demo" / "fuzz_inputs"
    cases = []

    def run_script_case(name: str, *expected: str) -> CaseSpec:
        def run(
            runner: CaseRunner,
            *,
            name: str = name,
            expected: tuple[str, ...] = expected,
        ) -> None:
            stdout, _ = _run_script(runner, name, cwd=demo_dir)
            for line in expected:
                runner.assert_line_contains(stdout, line)

        return _case(
            f"rtos_demo:{pathlib.Path(name).stem}",
            "analysis",
            "rtos_demo",
            run=run,
            weight=3,
        )

    cases.append(run_script_case("rtos_0_run.py", "Buffer: b'ABCDEFGHIJKLMNOP'"))

    def run_fuzz(runner: CaseRunner) -> None:
        stdout, _ = _run_afl_showmap(
            runner,
            inputs_dir=inputs_dir,
            target=[PYTHON, "rtos_1_fuzz.py", "@@"],
            cwd=demo_dir,
            stdin="testcase",
        )
        for line in (
            "003935:1",
            "007261:32",
            "007556:1",
            "025298:16",
            "029542:1",
            "033370:1",
            "042439:1",
            "046612:1",
            "048294:1",
            "051639:16",
            "053254:16",
            "053880:32",
            "055006:16",
            "056569:1",
            "064019:1",
        ):
            runner.assert_contains(stdout, line)

    cases.append(
        _case("rtos_demo:rtos_1_fuzz", "analysis", "rtos_demo", run=run_fuzz, weight=3)
    )
    cases.append(
        run_script_case(
            "rtos_2_analyze.py", "r4: 0xf", "r8: <BV32 0#24 .. input_buffer[7:0]>"
        )
    )
    cases.append(run_script_case("rtos_3_find_lr.py", ".. Reverse(lr)>"))
    cases.append(
        run_script_case("rtos_4_exploit.py", "PC: 0x104294", "Reached stop_udp: True")
    )
    return cases


def _build_thumb_cases() -> list[CaseSpec]:
    def check_output(
        runner: CaseRunner,
        stdout: str,
        stderr: str,
        arch_names: list[str],
    ) -> None:
        expected_trace_patterns = (
            r"single step at 0x1000: <CsInsn 0x1000 \[[0-9a-f]+\]: mov r1, #1>",
            r"single step at 0x1010: <CsInsn 0x1010 \[[0-9a-f]+\]: mov(?:\.w)? r1, #1>",
            r"single step at 0x1020: <CsInsn 0x1020 \[[0-9a-f]+\]: mov r1, #1>",
            r"step block at 0x1000: <CsInsn 0x1000 \[[0-9a-f]+\]: mov r1, #1>",
            r"step block at 0x1010: <CsInsn 0x1010 \[[0-9a-f]+\]: mov(?:\.w)? r1, #1>",
            r"step block at 0x1020: <CsInsn 0x1020 \[[0-9a-f]+\]: mov r1, #1>",
        )
        for arch_name in arch_names:
            runner.assert_contains(stdout, f"STEP_{arch_name}=0x6")
            runner.assert_contains(stdout, f"STEP_{arch_name}=0x4")
            for pattern in expected_trace_patterns[:3]:
                runner.assert_contains(stderr, pattern)
            runner.assert_contains(stdout, f"BLOCK_{arch_name}=0x6")
            runner.assert_contains(stdout, f"BLOCK_{arch_name}=0x4")
            for pattern in expected_trace_patterns[3:]:
                runner.assert_contains(stderr, pattern)
            runner.assert_contains(stdout, f"RUN_{arch_name}=0x6")
            runner.assert_contains(stdout, f"RUN_{arch_name}=0x4")
            runner.assert_contains(stdout, f"PERSIST_THUMB_{arch_name}=0x4")
            runner.assert_contains(stdout, f"GET_THUMB_PRE1_{arch_name}=True")
            runner.assert_contains(stdout, f"GET_THUMB_POST1_{arch_name}=False")
            runner.assert_contains(stdout, f"GET_THUMB_PRE2_{arch_name}=False")
            runner.assert_contains(stdout, f"GET_THUMB_POST2_{arch_name}=True")

    def run_armhf(runner: CaseRunner) -> None:
        stdout, stderr = _run_script(runner, "thumb/thumb.armhf.py")
        check_output(
            runner,
            stdout,
            stderr,
            [
                "ARM_V7A",
                "ARM_V7M",
                "ARM_V7R",
            ],
        )

    def run_armel(runner: CaseRunner) -> None:
        stdout, stderr = _run_script(runner, "thumb/thumb.armel.py")
        check_output(
            runner,
            stdout,
            stderr,
            [
                "ARM_V5T",
                "ARM_V6M",
            ],
        )

    return [
        _case("thumb:armhf", "scenario", "thumb", run=run_armhf, weight=2),
        _case("thumb:armel", "scenario", "thumb", run=run_armel, weight=2),
    ]


def _build_checked_heap_cases() -> list[CaseSpec]:
    cases = []
    family_map = {
        "CheckedReadTests": "checked_heap.read",
        "CheckedWriteTests": "checked_heap.write",
        "CheckedUAFTests": "checked_heap.uaf",
        "CheckedDoubleFreeTests": "checked_heap.double_free",
    }
    for suite_name, scenario in family_map.items():
        for variant, skip_reason, _ in _legacy_variants((suite_name,)):
            cases.append(
                _case(
                    f"{scenario}:{variant}",
                    "scenario",
                    "checked_heap",
                    run=lambda runner, scenario=scenario, variant=variant: _run_case_command(
                        runner, scenario, variant
                    ),
                    skip_reason=skip_reason,
                    weight=2,
                )
            )
    return cases


def _build_function_pointer_cases() -> list[CaseSpec]:
    cases = []
    for variant, skip_reason, _ in _legacy_variants(("FunctionPointerTests",)):
        cases.append(
            _case(
                f"funcptr:{variant}",
                "scenario",
                "funcptr",
                run=lambda runner, variant=variant: _run_script(
                    runner, f"funcptr/funcptr.{variant}.py"
                ),
                skip_reason=skip_reason,
            )
        )
    return cases


def _build_fuzz_cases() -> list[CaseSpec]:
    afl_expected = {
        "amd64": ["001445:1", "003349:1", "022192:1", "040896:1"],
        "aarch64": ["002975:1", "022192:1", "039638:1", "050871:1"],
        "armel": ["002975:1", "022192:1", "050871:1"],
        "armhf": ["002975:1", "022192:1", "050871:1"],
        "m68k": ["021692:1", "022192:1", "059686:1"],
        "mips": ["013057:1", "022192:1", "036571:1", "052670:1"],
        "mipsel": ["013057:1", "022192:1", "036571:1", "052670:1"],
    }
    inputs_dir = TestsPath / "fuzz" / "fuzz_inputs"
    cases = []
    for entry in LEGACY_MATRIX["FuzzTests"]:
        stem = entry["name"][5:]
        kind, arch = stem.split("_", 1)
        skip_reason = entry["skip_reason"]
        if kind == "fuzz":

            def run(runner: CaseRunner, *, arch: str = arch) -> None:
                stdout, _ = _run_case_command(runner, "fuzz", arch)
                runner.assert_line_contains(stdout, "=0x0")
                _, stderr = _run_case_command(runner, "fuzz", arch, "-c", check=False)
                runner.assert_line_contains(stderr, "UC_ERR_WRITE_UNMAPPED")

            case_id = f"fuzz:{arch}"
            tags = ("scenario", "fuzz")
        else:

            def run(runner: CaseRunner, *, arch: str = arch) -> None:
                stdout, _ = _run_afl_showmap(
                    runner,
                    inputs_dir=inputs_dir,
                    target=[PYTHON, "run_case.py", "fuzz.afl_fuzz", arch, "@@"],
                    cwd=TestsPath,
                    check=False,
                )
                for line in afl_expected[arch]:
                    runner.assert_line_contains(stdout, line)

            case_id = f"fuzz:afl:{arch}"
            tags = ("scenario", "fuzz", "afl")
        cases.append(_case(case_id, *tags, run=run, skip_reason=skip_reason, weight=2))
    return cases


def _build_library_cases() -> list[CaseSpec]:
    arch_matrix = [
        ("aarch64", "AARCH64", "LITTLE"),
        ("amd64", "X86_64", "LITTLE"),
        ("armel", "ARM_V6M", "LITTLE"),
        ("armhf", "ARM_V7A", "LITTLE"),
        ("i386", "X86_32", "LITTLE"),
        ("la64", "LOONGARCH64", "LITTLE"),
        ("m68k", "M68K", "BIG"),
        ("mips", "MIPS32", "BIG"),
        ("mipsel", "MIPS32", "LITTLE"),
        ("mips64", "MIPS64", "BIG"),
        ("mips64el", "MIPS64", "LITTLE"),
        ("ppc", "POWERPC32", "BIG"),
        ("riscv64", "RISCV64", "LITTLE"),
    ]
    difftime_skips = {
        "i386": "Returning float fails on i386",
        "m68k": "Returning float fails on m68k",
        "mips64": "Returning float fails on mips64",
        "mips64el": "Returning float fails on mips64el",
    }
    cases = []
    for item in LEGACY_LIBRARY_MODELS:
        library = item["library"]
        function = item["function"]
        base = item["bases"][0]
        quiet = bool(item.get("quiet", False))
        custom_run = item.get("custom_run_test", "")
        for extension, arch, byteorder in arch_matrix:
            skip_reason = None
            if item["class_name"] == "C99DifftimeTests":
                skip_reason = difftime_skips.get(extension)

            def run(
                runner: CaseRunner,
                *,
                library: str = library,
                function: str = function,
                extension: str = extension,
                arch: str = arch,
                byteorder: str = byteorder,
                base: str = base,
                quiet: bool = quiet,
                custom_run: str = custom_run,
            ) -> None:
                elf = f"{library}/{function}/{function}.{extension}.elf"
                args = ["runner.py"]
                if base == "NoArgLibraryModelTest":
                    if quiet:
                        args.append("-q")
                    args.extend([elf, arch, byteorder])
                    _run_script(runner, *args, env={"TZ": "UTC"})
                    return
                if base == "OneArgLibraryModelTest":
                    if quiet:
                        args.append("-q")
                    args.extend([elf, arch, byteorder])
                    _run_script(runner, *args, env={"TZ": "UTC"}, stdin="foobar\n")
                    return
                if base == "PrintLibraryModelTest":
                    stdout, _ = _run_script(runner, "runner.py", elf, arch, byteorder)
                    expected_path = (
                        TestsPath / library / function / f"{function}.{extension}.txt"
                    )
                    expected = expected_path.read_text()
                    if "SUCCESS" not in stdout:
                        raise AssertionError(
                            f"`SUCCESS` missing from stdout:\n\n{stdout}"
                        )
                    if stdout != expected:
                        raise AssertionError(
                            f"stdout did not match {expected_path}:\n\nexpected:\n{expected}\n\nactual:\n{stdout}"
                        )
                    return
                if base == "ScanLibraryModelTest":
                    _run_script(runner, "runner.py", elf, arch, byteorder, stdin="")
                    return
                if "getenv(foobar);" in custom_run:
                    _, stderr = _run_script(runner, "runner.py", elf, arch, byteorder)
                    runner.assert_line_contains(stderr, "getenv(foobar);")
                    return
                if "system(foobar);" in custom_run:
                    _, stderr = _run_script(runner, "runner.py", elf, arch, byteorder)
                    runner.assert_line_contains(stderr, "system(foobar);")
                    return
                raise AssertionError(
                    f"unknown library-model type for {library}/{function}: {base}"
                )

            cases.append(
                _case(
                    f"{library}:{function}:{extension}",
                    "library",
                    library,
                    function,
                    run=run,
                    skip_reason=skip_reason,
                    weight=2,
                    description=f"{item['class_name']} on {extension}",
                )
            )
    return cases


def _build_documentation_case() -> list[CaseSpec]:
    def run(_: CaseRunner) -> None:
        from sphinx import application, errors

        source = RepoRoot / "docs"
        build = source / "build"
        doctree = build / "doctrees"
        warnings = io.StringIO()
        app = application.Sphinx(
            str(source),
            str(source),
            str(build),
            str(doctree),
            "html",
            status=None,
            warning=warnings,
        )
        app.build()
        warnings.flush()
        warnings.seek(0)
        content = warnings.read().strip()
        if content:
            raise errors.SphinxWarning(f"\n\n{content}")

    return [_case("documentation:build", "docs", run=run, weight=3)]


def _build_parity_case() -> list[CaseSpec]:
    return [
        _case(
            "parity:legacy_manifest",
            "meta",
            "parity",
            run=lambda _: check_manifest_parity(),
        ),
        _case(
            "parity:registered_scenarios",
            "meta",
            "parity",
            run=lambda _: check_registered_scenario_parity(),
        ),
    ]


def all_cases() -> list[CaseSpec]:
    cases: list[CaseSpec] = []
    builders = [
        _build_parity_case,
        _build_square_cases,
        _build_branch_cases,
        _build_call_cases,
        _build_dma_cases,
        _build_recursion_cases,
        _build_stack_cases,
        _build_block_cases,
        _build_strlen_cases,
        _build_hooking_cases,
        _build_elf_cases,
        _build_rela_cases,
        _build_static_rela_cases,
        _build_link_elf_cases,
        _build_elf_core_load_cases,
        _build_elf_core_actuate_cases,
        _build_pe_cases,
        _build_link_pe_cases,
        _build_floats_cases,
        _build_syscall_cases,
        _build_static_buffer_cases,
        _build_delay_cases,
        _build_exitpoint_cases,
        _build_unmapped_cases,
        _build_symbolic_cases,
        _build_sysv_cases,
        _build_structure_cases,
        _build_memhook_cases,
        _build_crash_triage_cases,
        _build_trace_execution_cases,
        _build_loop_detection_cases,
        _build_coverage_frontier_cases,
        _build_colorizer_cases,
        _build_fsgsbase_cases,
        _build_rtos_cases,
        _build_thumb_cases,
        _build_checked_heap_cases,
        _build_function_pointer_cases,
        _build_fuzz_cases,
        _build_library_cases,
        _build_documentation_case,
    ]
    for build in builders:
        cases.extend(build())
    cases.sort(key=lambda case: case.id)
    return cases
