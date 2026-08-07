from __future__ import annotations

from typing import Any, Mapping

from .common import RepoRoot, TestsPath
from .spec import ScenarioInfo, from_variants

NATIVE_PARITY = True

_DEMO_DIR = RepoRoot / "use_cases" / "rtos_demo"
_INPUTS_DIR = TestsPath / "rtos_demo" / "fuzz_inputs"

# Each non-fuzz variant maps to (script_name, expected_lines).
_SCRIPT_CASES = {
    "rtos_0_run": ("rtos_0_run.py", ("Buffer: b'ABCDEFGHIJKLMNOP'",)),
    "rtos_2_analyze": (
        "rtos_2_analyze.py",
        ("r4: 0xf", "r8: <BV32 0#24 .. input_buffer[7:0]>"),
    ),
    "rtos_3_find_lr": ("rtos_3_find_lr.py", (".. Reverse(lr)>",)),
    "rtos_4_exploit": (
        "rtos_4_exploit.py",
        ("PC: 0x104294", "Reached stop_udp: True"),
    ),
}

_FUZZ_EXPECTED = (
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
)

_VARIANTS = (
    ("rtos_0_run", None),
    ("rtos_1_fuzz", None),
    ("rtos_2_analyze", None),
    ("rtos_3_find_lr", None),
    ("rtos_4_exploit", None),
)


def _rtos_run_factory(info, variant: str, kwargs: Mapping[str, Any]):
    from .. import manifest

    if variant == "rtos_1_fuzz":

        def run(runner):
            stdout, _ = manifest._run_afl_showmap(
                runner,
                inputs_dir=_INPUTS_DIR,
                target=[manifest.PYTHON, "rtos_1_fuzz.py", "@@"],
                cwd=_DEMO_DIR,
                stdin="testcase",
            )
            for line in _FUZZ_EXPECTED:
                runner.assert_contains(stdout, line)

        return run

    script_name, expected_lines = _SCRIPT_CASES[variant]

    def run(runner):
        stdout, _ = manifest._run_script(runner, script_name, cwd=_DEMO_DIR)
        for line in expected_lines:
            runner.assert_line_contains(stdout, line)

    return run


SCENARIO_INFO = ScenarioInfo(
    prefix="rtos_demo",
    scenario="rtos_demo",
    tags=("analysis", "rtos_demo"),
    variants_source=from_variants(_VARIANTS),
    run_factory=_rtos_run_factory,
    weight=3,
)
