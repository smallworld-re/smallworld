from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import re
import subprocess
import time
import typing

TestsPath = pathlib.Path(__file__).resolve().parents[1]
RepoRoot = TestsPath.parent


class DetailedCalledProcessError(Exception):
    """Wrap subprocess failures with captured stdout/stderr."""

    def __init__(self, error: subprocess.CalledProcessError):
        self.error = error

    def __str__(self) -> str:
        stdout = self.error.stdout.decode() if self.error.stdout else ""
        stderr = self.error.stderr.decode() if self.error.stderr else ""
        return f"{self.error}\n\nstdout:\n{stdout}\n\nstderr:\n{stderr}"


@dataclasses.dataclass(frozen=True)
class CaseSpec:
    id: str
    tags: tuple[str, ...]
    run: typing.Callable[["CaseRunner"], None] = dataclasses.field(
        repr=False, compare=False
    )
    skip_reason: str | None = None
    weight: int = 1
    description: str | None = None


@dataclasses.dataclass(frozen=True)
class CaseSummary:
    id: str
    tags: tuple[str, ...]
    skip_reason: str | None
    weight: int
    description: str | None


@dataclasses.dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str


class CaseRunner:
    """Common subprocess/assertion helpers for manifest cases."""

    def __init__(self, cwd: pathlib.Path | None = None):
        self.cwd = cwd or TestsPath

    def command(
        self,
        argv: list[str],
        *,
        stdin: str | None = None,
        cwd: pathlib.Path | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
    ) -> CommandResult:
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        try:
            process = subprocess.run(
                argv,
                cwd=cwd or self.cwd,
                env=run_env,
                input=stdin.encode() if stdin is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=check,
            )
        except subprocess.CalledProcessError as error:
            raise DetailedCalledProcessError(error) from error
        return CommandResult(
            stdout=process.stdout.decode(),
            stderr=process.stderr.decode(),
        )

    def command_shell(
        self,
        cmd: str,
        *,
        stdin: str | None = None,
        cwd: pathlib.Path | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
    ) -> CommandResult:
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        try:
            process = subprocess.run(
                cmd,
                cwd=cwd or self.cwd,
                env=run_env,
                shell=True,
                input=stdin.encode() if stdin is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            return CommandResult(
                stdout=process.stdout.decode(),
                stderr=process.stderr.decode(),
            )
        except subprocess.CalledProcessError as error:
            if check:
                raise DetailedCalledProcessError(error) from error
            return CommandResult(
                stdout=error.stdout.decode(),
                stderr=error.stderr.decode(),
            )

    def assert_contains(self, output: str, pattern: str) -> None:
        if re.search(pattern, output) is None:
            raise AssertionError(
                f"pattern `{pattern}` not found in output:\n\n{output.strip()}"
            )

    def assert_line_contains(self, output: str, *parts: str) -> None:
        for line in output.splitlines():
            if all(part in line for part in parts):
                return
        raise AssertionError(f"no line contains all of {parts!r}:\n\n{output.strip()}")

    def assert_lines_absent(self, output: str, *parts: str) -> None:
        for line in output.splitlines():
            for part in parts:
                if part in line:
                    raise AssertionError(f"line contains `{part}`:\n\n{output.strip()}")


def stable_shards(cases: list[CaseSpec], shard_count: int) -> list[list[CaseSpec]]:
    shards: list[list[CaseSpec]] = [[] for _ in range(shard_count)]
    weights = [0 for _ in range(shard_count)]
    for case in sorted(cases, key=lambda item: (-item.weight, item.id)):
        shard_index = min(range(shard_count), key=lambda idx: (weights[idx], idx))
        shards[shard_index].append(case)
        weights[shard_index] += case.weight
    for shard in shards:
        shard.sort(key=lambda item: item.id)
    return shards


def case_summaries(cases: list[CaseSpec]) -> list[CaseSummary]:
    return [
        CaseSummary(
            id=case.id,
            tags=case.tags,
            skip_reason=case.skip_reason,
            weight=case.weight,
            description=case.description,
        )
        for case in cases
    ]


def summaries_json(cases: list[CaseSpec]) -> str:
    return json.dumps(
        [
            {
                "id": summary.id,
                "tags": list(summary.tags),
                "skip_reason": summary.skip_reason,
                "weight": summary.weight,
                "description": summary.description,
            }
            for summary in case_summaries(cases)
        ],
        indent=2,
        sort_keys=True,
    )


def run_cases(cases: list[CaseSpec], *, verbose: bool = False) -> int:
    runner = CaseRunner()
    started = time.monotonic()
    failures: list[tuple[CaseSpec, BaseException]] = []
    skipped = 0
    for case in cases:
        if case.skip_reason:
            skipped += 1
            if verbose:
                print(f"SKIP {case.id}: {case.skip_reason}")
            continue
        if verbose:
            print(f"RUN  {case.id}")
        try:
            case.run(runner)
            if verbose:
                print(f"PASS {case.id}")
        except BaseException as error:  # noqa: BLE001
            failures.append((case, error))
            print(f"FAIL {case.id}")
            print(error)
    elapsed = time.monotonic() - started
    print(f"Ran {len(cases)} cases in {elapsed:.3f}s")
    if failures:
        print(f"FAILED (failures={len(failures)}, skipped={skipped})")
        return 1
    if skipped:
        print(f"OK (skipped={skipped})")
        return 0
    print("OK")
    return 0
