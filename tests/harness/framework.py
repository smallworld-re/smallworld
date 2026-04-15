from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time
import typing

from .coverage import wrap_python_command

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


def _decode_output(data: bytes | None) -> str:
    return data.decode() if data else ""


class _TeeTextIO:
    def __init__(self, primary: typing.TextIO, mirror: typing.TextIO):
        self._primary = primary
        self._mirror = mirror

    def __getattr__(self, name: str) -> typing.Any:
        return getattr(self._primary, name)

    def write(self, data: str) -> int:
        written = self._primary.write(data)
        self._mirror.write(data)
        self._mirror.flush()
        return written

    def writelines(self, lines: typing.Iterable[str]) -> None:
        for line in lines:
            self.write(line)

    def flush(self) -> None:
        self._primary.flush()
        self._mirror.flush()


class OutputLogger:
    def __init__(self, log_path: pathlib.Path):
        self.log_path = log_path
        self._stream: typing.TextIO | None = None
        self._stdout_redirect: typing.Any = None
        self._stderr_redirect: typing.Any = None

    def __enter__(self) -> OutputLogger:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.log_path.open("w", encoding="utf-8", buffering=1)
        self._stdout_redirect = contextlib.redirect_stdout(
            _TeeTextIO(sys.stdout, self._stream)
        )
        self._stderr_redirect = contextlib.redirect_stderr(
            _TeeTextIO(sys.stderr, self._stream)
        )
        self._stdout_redirect.__enter__()
        self._stderr_redirect.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._stderr_redirect is not None:
            self._stderr_redirect.__exit__(exc_type, exc_val, exc_tb)
            self._stderr_redirect = None
        if self._stdout_redirect is not None:
            self._stdout_redirect.__exit__(exc_type, exc_val, exc_tb)
            self._stdout_redirect = None
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def log_subprocess(
        self,
        *,
        command: list[str] | str,
        cwd: pathlib.Path,
        exit_code: int,
        stdout: str,
        stderr: str,
        case_id: str | None = None,
    ) -> None:
        if self._stream is None:
            return
        if self._stream.tell() > 0:
            self._stream.write("\n")
        command_text = command if isinstance(command, str) else shlex.join(command)
        self._stream.write("=== subprocess ===\n")
        if case_id is not None:
            self._stream.write(f"case: {case_id}\n")
        self._stream.write(f"command: {command_text}\n")
        self._stream.write(f"cwd: {cwd}\n")
        self._stream.write(f"exit_code: {exit_code}\n")
        self._stream.write("--- stdout ---\n")
        self._stream.write(stdout)
        if stdout and not stdout.endswith("\n"):
            self._stream.write("\n")
        self._stream.write("--- stderr ---\n")
        self._stream.write(stderr)
        if stderr and not stderr.endswith("\n"):
            self._stream.write("\n")
        self._stream.write("=== end subprocess ===\n")
        self._stream.flush()


@contextlib.contextmanager
def managed_output_logger(
    log_path: pathlib.Path | None,
) -> typing.Iterator[OutputLogger | None]:
    if log_path is None:
        yield None
        return
    with OutputLogger(log_path) as logger:
        yield logger


class CaseRunner:
    """Common subprocess/assertion helpers for manifest cases."""

    def __init__(
        self,
        cwd: pathlib.Path | None = None,
        *,
        output_logger: OutputLogger | None = None,
    ):
        self.cwd = cwd or TestsPath
        self.output_logger = output_logger
        self.active_case_id: str | None = None

    def _log_subprocess(
        self,
        command: list[str] | str,
        *,
        cwd: pathlib.Path,
        exit_code: int,
        stdout: str,
        stderr: str,
    ) -> None:
        if self.output_logger is None:
            return
        self.output_logger.log_subprocess(
            command=command,
            cwd=cwd,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            case_id=self.active_case_id,
        )

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
        argv = wrap_python_command(list(argv), env=run_env)
        run_cwd = cwd or self.cwd
        try:
            process = subprocess.run(
                argv,
                cwd=run_cwd,
                env=run_env,
                input=stdin.encode() if stdin is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=check,
            )
        except subprocess.CalledProcessError as error:
            self._log_subprocess(
                argv,
                cwd=run_cwd,
                exit_code=error.returncode,
                stdout=_decode_output(error.stdout),
                stderr=_decode_output(error.stderr),
            )
            raise DetailedCalledProcessError(error) from error
        result = CommandResult(
            stdout=_decode_output(process.stdout),
            stderr=_decode_output(process.stderr),
        )
        self._log_subprocess(
            argv,
            cwd=run_cwd,
            exit_code=process.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        return result

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
        run_cwd = cwd or self.cwd
        try:
            process = subprocess.run(
                cmd,
                cwd=run_cwd,
                env=run_env,
                shell=True,
                input=stdin.encode() if stdin is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=check,
            )
        except subprocess.CalledProcessError as error:
            result = CommandResult(
                stdout=_decode_output(error.stdout),
                stderr=_decode_output(error.stderr),
            )
            self._log_subprocess(
                cmd,
                cwd=run_cwd,
                exit_code=error.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
            if check:
                raise DetailedCalledProcessError(error) from error
            return result
        result = CommandResult(
            stdout=_decode_output(process.stdout),
            stderr=_decode_output(process.stderr),
        )
        self._log_subprocess(
            cmd,
            cwd=run_cwd,
            exit_code=process.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        return result

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


def run_cases(
    cases: list[CaseSpec],
    *,
    verbose: bool = False,
    log_path: pathlib.Path | None = None,
    output_logger: OutputLogger | None = None,
) -> int:
    if output_logger is None and log_path is not None:
        with managed_output_logger(log_path) as logger:
            return run_cases(cases, verbose=verbose, output_logger=logger)

    runner = CaseRunner(output_logger=output_logger)
    started = time.monotonic()
    failures: list[tuple[CaseSpec, BaseException]] = []
    skipped = 0
    for case in cases:
        runner.active_case_id = case.id
        if case.skip_reason:
            skipped += 1
            if verbose:
                print(f"SKIP {case.id}: {case.skip_reason}")
            runner.active_case_id = None
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
        finally:
            runner.active_case_id = None
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
