#!/usr/bin/env python3

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness.scenarios import maybe_run_registered_case


def _variants_to_try(variant: str) -> list[str]:
    variants = [variant]
    if variant.endswith(".pcode"):
        variants.append(variant[: -len(".pcode")] + ".ghidra")
    return variants


def script_path_for_case(scenario: str, variant: str) -> pathlib.Path:
    candidates: list[pathlib.Path] = []
    for variant_name in _variants_to_try(variant):
        if "." in scenario:
            family, name = scenario.split(".", 1)
            candidates.extend(
                [
                    TESTS_DIR / family / name / f"{name}.{variant_name}.py",
                    TESTS_DIR / family / name / f"{family}.{variant_name}.py",
                    TESTS_DIR / family / f"{name}.{variant_name}.py",
                ]
            )
        else:
            family = scenario
            candidates.append(TESTS_DIR / family / f"{family}.{variant_name}.py")

    for candidate in candidates:
        if candidate.exists():
            return candidate
    joined = "\n".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(
        f"no scenario entrypoint for `{scenario}` / `{variant}`.\nTried:\n{joined}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run a single integration scenario through a stable entrypoint instead "
            "of reaching into per-file legacy scripts."
        )
    )
    parser.add_argument("scenario", help="Scenario family, for example `square` or `checked_heap.read`")
    parser.add_argument("variant", help="Variant name, for example `amd64` or `amd64.pcode`")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments forwarded to the scenario")
    ns = parser.parse_args()

    registered = maybe_run_registered_case(ns.scenario, ns.variant, ns.args)
    if registered is not None:
        return registered

    script = script_path_for_case(ns.scenario, ns.variant)
    process = subprocess.run(
        [sys.executable, str(script), *ns.args],
        cwd=TESTS_DIR,
        check=False,
    )
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
