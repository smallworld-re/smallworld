from __future__ import annotations

from typing import Any, Mapping

from .spec import ScenarioInfo, from_variants

NATIVE_PARITY = True

# Each variant maps to script args/stdin for its specific .py file.
_VARIANT_CONFIG = {
    "branch": {"args": (), "stdin": None},
    "dma": {"args": ("10", "2"), "stdin": None},
    "hooking": {"args": (), "stdin": "foo bar baz"},
    "square": {"args": (), "stdin": None},
}

_VARIANTS = tuple((name, None) for name in _VARIANT_CONFIG)


def _symbolic_run_factory(info, variant: str, kwargs: Mapping[str, Any]):
    from .. import manifest

    config = _VARIANT_CONFIG[variant]
    script = f"symbolic/{variant}.amd64.angr.symbolic.py"

    def run(runner):
        manifest._run_script(
            runner,
            script,
            *config["args"],
            stdin=config["stdin"],
        )

    return run


SCENARIO_INFO = ScenarioInfo(
    prefix="symbolic",
    scenario="symbolic",
    tags=("analysis", "symbolic"),
    variants_source=from_variants(_VARIANTS),
    run_factory=_symbolic_run_factory,
    weight=2,
)
