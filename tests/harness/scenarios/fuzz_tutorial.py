"""Integration cases for the fuzzing tutorial under ``docs/tutorial/fuzzing/``.

Both variants run the standalone tutorial scripts directly (no test-harness
scaffolding), so they verify the exact code a tutorial reader would copy.
``unicorn:armel`` is driven through ``afl-showmap``; ``styx:armel`` relies on
``styxafl``'s non-AFL fallback mode (single iteration when ``__AFL_SHM_ID``
is unset).
"""

from __future__ import annotations

from typing import Any, Mapping

from .common import RepoRoot
from .spec import ScenarioInfo, from_variants

NATIVE_PARITY = True

_TUTORIAL_DIR = RepoRoot / "docs" / "tutorial" / "fuzzing"
_SEED_RELATIVE = "inputs/good_input"

_UNICORN_EXPECTED = ("002975:1", "022192:1", "050871:1")


def _fuzz_tutorial_run_factory(info, variant: str, kwargs: Mapping[str, Any]):
    from .. import manifest

    if variant == "styx:armel":

        def run(runner):
            result = runner.command(
                [manifest.PYTHON, "styx_fuzz.py", _SEED_RELATIVE],
                cwd=_TUTORIAL_DIR,
                check=True,
            )
            runner.assert_lines_absent(result.stdout, "Traceback")

    elif variant == "unicorn:armel":

        def run(runner):
            stdout, _ = manifest._run_afl_showmap(
                runner,
                inputs_dir=_TUTORIAL_DIR / "inputs",
                target=[manifest.PYTHON, "unicorn_fuzz.py", "@@"],
                cwd=_TUTORIAL_DIR,
                check=False,
            )
            for line in _UNICORN_EXPECTED:
                runner.assert_line_contains(stdout, line)

    else:
        raise ValueError(f"unknown fuzz_tutorial variant: {variant}")

    return run


SCENARIO_INFO = ScenarioInfo(
    prefix="fuzz_tutorial",
    scenario="fuzz_tutorial",
    tags=("scenario", "fuzz", "docs"),
    variants_source=from_variants((("styx:armel", None), ("unicorn:armel", None))),
    run_factory=_fuzz_tutorial_run_factory,
    weight=2,
)
