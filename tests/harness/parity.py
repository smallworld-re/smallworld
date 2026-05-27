from __future__ import annotations

from .scenarios import fuzz
from .scenarios.registry import HANDLERS, REGISTERED_SCENARIOS


def _native_scenario_prefixes() -> set[str]:
    """Case-id prefixes for scenarios opted into the native parity tier.

    A scenario opts in by setting ``NATIVE_PARITY = True`` at module scope.
    Prefixes come from both ``SCENARIO_PREFIXES`` (modules that also dispatch
    in-process via ``run_case``) and ``SCENARIO_INFO``/``SCENARIO_INFOS``
    (modules that only declare cases — e.g. script-only scenarios).
    """
    prefixes: set[str] = set()
    for prefix, _scenario, handler in REGISTERED_SCENARIOS:
        if getattr(handler, "NATIVE_PARITY", False):
            prefixes.add(prefix)
    for handler in HANDLERS:
        if not getattr(handler, "NATIVE_PARITY", False):
            continue
        info = getattr(handler, "SCENARIO_INFO", None)
        if info is not None:
            prefixes.add(info.prefix)
        for info in getattr(handler, "SCENARIO_INFOS", ()):
            prefixes.add(info.prefix)
    return prefixes


def check_manifest_parity() -> None:
    """Sanity-check the manifest: every case ID must be unique."""
    from .manifest import all_cases

    seen: set[str] = set()
    duplicates: list[str] = []
    for case in all_cases():
        if case.id in seen:
            duplicates.append(case.id)
        seen.add(case.id)
    if duplicates:
        raise AssertionError(f"duplicate ids: {duplicates[:20]}")


def check_registered_scenario_parity() -> None:
    from .manifest import all_cases

    missing: list[str] = []
    for case in all_cases():
        if case.id.startswith("fuzz:"):
            parts = case.id.split(":")
            if len(parts) == 2:
                scenario = "fuzz"
                variant = parts[1]
            else:
                scenario = "fuzz.afl_fuzz"
                variant = parts[2]
            if not fuzz.can_run(scenario, variant):
                missing.append(case.id)
            continue
        for prefix, scenario, handler in REGISTERED_SCENARIOS:
            if case.id.startswith(f"{prefix}:"):
                variant = case.id[len(prefix) + 1 :]
                if not handler.can_run(scenario, variant):
                    missing.append(case.id)
                break

    if missing:
        raise AssertionError(
            "shared scenario handlers do not cover these manifest cases: "
            + str(missing[:20])
        )
