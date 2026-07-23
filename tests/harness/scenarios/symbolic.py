from __future__ import annotations

from typing import Any, Mapping

from .spec import ScenarioInfo, from_variants

NATIVE_PARITY = True

# Each scenario maps to script args/stdin for its specific .py file.
_SCENARIO_CONFIG = {
    "branch": {"args": (), "stdin": None},
    "dma": {"args": ("10", "2"), "stdin": None},
    "hooking": {"args": (), "stdin": "foo bar baz"},
    "square": {"args": (), "stdin": None},
    "funchook": {"args": (), "stdin": None},
}

_ENGINES = ("angr", "pcode_symbolic", "triton_symbolic")

_HOOKING_PCODE_SYMBOLIC_SKIP = (
    "PutsModel reads 11 input bytes via separate read_memory_symbolic "
    "calls and then eval_atmost's the concatenated 88-bit expression. "
    "Each byte round-trips through SymZ3's Java Z3 Context, and Z3 "
    "memory grows unboundedly during the final solve, OOM-killing the "
    "test. Needs a bulk-read or caching path before this can run."
)

# TritonSymbolicEmulator is a linear (single-path) symbolic engine: it does not
# fork at symbolic branches, so scenarios that explore multiple paths are not
# supported yet. Only ``square`` (a straight-line computation queried with the
# solver) is enabled; the branch-exploring scenarios are skipped pending a
# forking implementation.
_TRITON_SYMBOLIC_UNSUPPORTED = (
    "TritonSymbolicEmulator only supports linear symbolic execution; this "
    "scenario requires exploring multiple symbolic paths."
)
_TRITON_SYMBOLIC_SCENARIOS = ("square",)


def _variant_skip(scenario: str, engine: str) -> str | None:
    if scenario == "hooking" and engine == "pcode_symbolic":
        return _HOOKING_PCODE_SYMBOLIC_SKIP
    if engine == "triton_symbolic" and scenario not in _TRITON_SYMBOLIC_SCENARIOS:
        return _TRITON_SYMBOLIC_UNSUPPORTED
    return None


# Variant id is "<scenario>" for the default engine (angr) and
# "<scenario>.pcode_symbolic" for the ghidra-symbolic engine.
def _build_variants() -> tuple[tuple[str, str | None], ...]:
    out: list[tuple[str, str | None]] = []
    for scenario in _SCENARIO_CONFIG:
        for engine in _ENGINES:
            variant_id = scenario if engine == "angr" else f"{scenario}.{engine}"
            out.append((variant_id, _variant_skip(scenario, engine)))
    return tuple(out)


_VARIANTS = _build_variants()


def _symbolic_run_factory(info, variant: str, kwargs: Mapping[str, Any]):
    from .. import manifest

    scenario_name, sep, engine = variant.partition(".")
    if not sep:
        engine = "angr"
    config = _SCENARIO_CONFIG[scenario_name]
    script = f"symbolic/{scenario_name}.amd64.{engine}.symbolic.py"

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
