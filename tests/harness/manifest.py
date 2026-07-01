from __future__ import annotations

import pathlib
import sys
import typing

from .framework import CaseRunner, CaseSpec, TestsPath
from .parity import check_manifest_parity, check_registered_scenario_parity
from .scenarios.registry import HANDLERS
from .scenarios.spec import ScenarioInfo

PYTHON = sys.executable


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


def _iter_scenario_infos() -> typing.Iterator[ScenarioInfo]:
    seen: set[int] = set()
    for handler in HANDLERS:
        info = getattr(handler, "SCENARIO_INFO", None)
        if info is not None and id(info) not in seen:
            seen.add(id(info))
            yield info
        for info in getattr(handler, "SCENARIO_INFOS", ()):
            if id(info) in seen:
                continue
            seen.add(id(info))
            yield info


def _build_generic_cases(info: ScenarioInfo) -> list[CaseSpec]:
    if info.variants_source is None or info.run_factory is None:
        return []
    cases: list[CaseSpec] = []
    for variant, skip_reason, kwargs in info.variants_source():
        description = info.description
        if info.description_factory is not None:
            description = info.description_factory(variant, kwargs)
        cases.append(
            _case(
                f"{info.prefix}:{variant}",
                *info.tags,
                run=info.run_factory(info, variant, kwargs),
                skip_reason=skip_reason,
                weight=info.weight,
                description=description,
            )
        )
    return cases


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
    for info in _iter_scenario_infos():
        cases.extend(_build_generic_cases(info))
    cases.extend(_build_parity_case())
    cases.sort(key=lambda case: case.id)
    return cases
