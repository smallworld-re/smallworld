from __future__ import annotations

from .spec import ScenarioInfo, from_variants

NATIVE_PARITY = True

_VARIANTS = (
    ("amd64", None),
    ("amd64.panda", None),
)

_EXPECTED_LINES = (
    ("1", "1760"),
    ("2", "1760"),
    ("3", "0"),
    ("4", "1"),
    ("5", "980"),
    ("6", "20"),
)


def _block_run_factory(info, variant, kwargs):
    from .. import manifest

    def run(runner):
        stdout, _ = manifest._run_script(
            runner,
            f"block/block.{variant}.py",
            "2740",
            "1760",
        )
        for parts in _EXPECTED_LINES:
            runner.assert_line_contains(stdout, *parts)

    return run


SCENARIO_INFO = ScenarioInfo(
    prefix="block",
    scenario="block",
    tags=("scenario", "block"),
    variants_source=from_variants(_VARIANTS),
    run_factory=_block_run_factory,
)
