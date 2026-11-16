#!/usr/bin/env python3
"""Replay .github/workflows/pull-request.yml on this machine.

Run it as `nix run ./ci#local -- --cores N` from the repository root.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import json
import os
import pathlib
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import typing

import yaml

WORKFLOW = ".github/workflows/pull-request.yml"
RUNNER = "smallworld-arc"
COMBINE_JOB = "Coverage-Combine"
# These build through the nix daemon, which ignores our CPU affinity, so they
# run alone before the pool starts to keep the --cores bound honest.
SERIAL_JOBS = ("Build", "Downstream-Flake")
MARKER = ".smallworld-local-ci"
EXPRESSION = re.compile(r"\$\{\{\s*(.+?)\s*\}\}")
PSS = re.compile(r"^Pss:\s+(\d+) kB", re.MULTILINE)

Spec = typing.Dict[str, typing.Any]


@dataclasses.dataclass(frozen=True)
class Job:
    name: str
    spec: Spec
    matrix: dict[str, str]

    @property
    def label(self) -> str:
        suffix = ",".join(self.matrix.values())
        return f"{self.name}[{suffix}]" if suffix else self.name


@dataclasses.dataclass(frozen=True)
class Result:
    job: Job
    status: str
    seconds: float
    log: pathlib.Path | None
    peak_kb: int = 0


class MemorySampler(threading.Thread):
    """Tracks peak PSS per job by summing every process in the job's session."""

    def __init__(self, interval: float = 2.0) -> None:
        super().__init__(daemon=True)
        self.interval = interval
        self.sessions: dict[int, str] = {}
        self.peaks: dict[str, int] = {}
        self.total_peak = 0
        self.lock = threading.Lock()

    def run(self) -> None:
        while True:
            time.sleep(self.interval)
            self.sample()

    def sample(self) -> None:
        with self.lock:
            sessions = dict(self.sessions)
        usage: dict[str, int] = {}
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            try:
                stat = pathlib.Path(entry.path, "stat").read_text()
                # Split after the last ")": the command name may contain spaces.
                label = sessions.get(int(stat.rpartition(")")[2].split()[3]))
                if label is None:
                    continue
                rollup = pathlib.Path(entry.path, "smaps_rollup").read_text()
            except (OSError, ValueError, IndexError):
                continue
            match = PSS.search(rollup)
            if match:
                usage[label] = usage.get(label, 0) + int(match.group(1))
        with self.lock:
            for label, kb in usage.items():
                self.peaks[label] = max(self.peaks.get(label, 0), kb)
            self.total_peak = max(self.total_peak, sum(usage.values()))


class Runner:
    def __init__(
        self,
        workflow: Spec,
        workdir: pathlib.Path,
        source: pathlib.Path,
        commit: str,
        cores: int,
    ) -> None:
        self.workflow = workflow
        self.workdir = workdir
        self.source = source
        self.commit = commit
        self.cores = cores
        self.logs = workdir / "logs"
        self.artifacts = workdir / "artifacts"
        self.children: set[subprocess.Popen[bytes]] = set()
        self.lock = threading.Lock()
        self.cancelled = False
        self.memory = MemorySampler()
        self.memory.start()
        self.logs.mkdir()
        self.artifacts.mkdir()

    def expand(self, text: str, job: Job, checkout: pathlib.Path) -> str:
        context: dict[str, str] = {"github.workspace": str(checkout)}
        context.update({f"matrix.{k}": v for k, v in job.matrix.items()})
        for key, value in (self.workflow.get("env") or {}).items():
            context[f"env.{key}"] = str(value)

        def substitute(match: re.Match[str]) -> str:
            key = match.group(1)
            if key.startswith("secrets."):
                return ""
            if key not in context:
                raise SystemExit(f"{job.name}: unsupported expression `{key}`")
            return context[key]

        return EXPRESSION.sub(substitute, text)

    def environment(
        self, job: Job, checkout: pathlib.Path, step: Spec
    ) -> dict[str, str]:
        env = os.environ.copy()
        for scope in (self.workflow, job.spec, step):
            for key, value in (scope.get("env") or {}).items():
                env[key] = self.expand(str(value), job, checkout)
        limits = f"cores = {self.cores}\nmax-jobs = 1"
        env["NIX_CONFIG"] = "\n".join(filter(None, [env.get("NIX_CONFIG"), limits]))
        stem = str(self.logs / job.label)
        env.update(
            CI="true",
            GITHUB_ACTIONS="true",
            GITHUB_WORKSPACE=str(checkout),
            GITHUB_OUTPUT=f"{stem}.output",
            GITHUB_STEP_SUMMARY=f"{stem}.summary.md",
        )
        return env

    def execute(
        self,
        label: str,
        argv: list[str],
        cwd: pathlib.Path,
        env: dict[str, str],
        log: typing.BinaryIO,
        echo: bool,
    ) -> int:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        with self.lock:
            self.children.add(process)
        with self.memory.lock:
            self.memory.sessions[process.pid] = label
        assert process.stdout is not None
        for line in process.stdout:
            log.write(line)
            if echo:
                sys.stdout.buffer.write(b"    " + line)
                sys.stdout.buffer.flush()
        code = process.wait()
        with self.lock:
            self.children.discard(process)
        with self.memory.lock:
            del self.memory.sessions[process.pid]
        return code

    def reset(self, checkout: pathlib.Path) -> None:
        git(checkout, "reset", "-q", "--hard", self.commit)
        git(checkout, "clean", "-xfdq")

    def collect(self, job: Job, checkout: pathlib.Path, step: Spec) -> None:
        options = step.get("with") or {}
        name = self.expand(str(options.get("name", job.label)), job, checkout)
        entries = str(options.get("path", "")).split()
        # upload-artifact roots a lone directory at the artifact's top level.
        flatten = len(entries) == 1 and (checkout / entries[0]).is_dir()
        for entry in entries:
            path = checkout / entry
            target = self.artifacts / name / ("" if flatten else entry)
            if path.is_dir():
                shutil.copytree(path, target, dirs_exist_ok=True)
            elif path.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)

    def download(self, checkout: pathlib.Path, step: Spec) -> None:
        options = step.get("with") or {}
        target = checkout / str(options.get("path", "."))
        target.mkdir(parents=True, exist_ok=True)
        for artifact in sorted(self.artifacts.glob(str(options.get("pattern", "*")))):
            shutil.copytree(artifact, target, dirs_exist_ok=True)

    def run_job(self, job: Job, checkout: pathlib.Path, echo: bool) -> Result:
        self.reset(checkout)
        log_path = self.logs / f"{job.label}.log"
        started = time.monotonic()
        status = "pass"
        with log_path.open("wb") as log:
            for index, step in enumerate(job.spec.get("steps") or []):
                uses = str(step.get("uses", ""))
                if uses.startswith("actions/upload-artifact"):
                    self.collect(job, checkout, step)
                elif uses.startswith("actions/download-artifact"):
                    self.download(checkout, step)
                run = step.get("run")
                # Conditional steps all depend on secrets or on bot commits.
                if run is None or step.get("if", "always()") != "always()":
                    continue
                if status != "pass" or "pip install" in run:
                    continue
                script = self.logs / f"{job.label}.step{index}.sh"
                script.write_text(self.expand(run, job, checkout))
                argv = ["bash", "-e", str(script)]
                if job.spec.get("runs-on") != RUNNER:
                    argv = ["nix", "develop", str(checkout), "-c", *argv]
                log.write(f"##[group]{step.get('name', run)}\n".encode())
                log.flush()
                code = self.execute(
                    job.label,
                    argv,
                    checkout / str(step.get("working-directory", ".")),
                    self.environment(job, checkout, step),
                    log,
                    echo,
                )
                if code != 0:
                    status = "FAIL"
        with self.memory.lock:
            peak = self.memory.peaks.get(job.label, 0)
        return Result(job, status, time.monotonic() - started, log_path, peak)

    def cancel(self) -> None:
        self.cancelled = True
        with self.lock:
            for process in self.children:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass


def git(cwd: pathlib.Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, stdout=subprocess.PIPE, text=True
    ).stdout.strip()


def parse_ranges(text: str) -> set[int]:
    values: set[int] = set()
    for part in text.split(","):
        low, _, high = part.partition("-")
        values.update(range(int(low), int(high or low) + 1))
    return values


def prepare_workdir(workdir: pathlib.Path) -> None:
    if workdir.exists() and any(workdir.iterdir()):
        if not (workdir / MARKER).exists():
            raise SystemExit(f"refusing to wipe {workdir}: not a local-ci directory")
        # Nix store copies are read-only, so make everything writable first.
        subprocess.run(["chmod", "-R", "u+w", str(workdir)], check=True)
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / MARKER).touch()


def snapshot(
    repo: pathlib.Path, source: pathlib.Path, dirty: bool, merge: str | None
) -> str:
    commit = git(repo, "rev-parse", "HEAD")
    if git(repo, "status", "--porcelain", "--untracked-files=no"):
        if dirty:
            commit = git(repo, "stash", "create")
        else:
            print("warning: uncommitted changes are NOT tested (pass --dirty)")
    clone(repo, source, commit)
    if merge:
        base = git(repo, "rev-parse", merge)
        identity = ["-c", "user.name=local-ci", "-c", "user.email=local-ci@localhost"]
        git(source, *identity, "merge", "-q", "--no-edit", base)
        commit = git(source, "rev-parse", "HEAD")
    return commit


def clone(origin: pathlib.Path, target: pathlib.Path, commit: str) -> None:
    git(origin, "clone", "-q", "--shared", "--no-checkout", str(origin), str(target))
    git(target, "checkout", "-q", "--detach", commit)


def select_jobs(
    workflow: Spec, only: set[str] | None, shards: set[int] | None
) -> list[Job]:
    specs: dict[str, Spec] = workflow["jobs"]
    runnable = {
        name
        for name, spec in specs.items()
        if spec.get("runs-on") == RUNNER or name == COMBINE_JOB
    }
    wanted = set(runnable)
    if only is not None:
        unknown = only - runnable
        if unknown:
            raise SystemExit(f"unknown jobs {sorted(unknown)}; have {sorted(runnable)}")
        wanted = set()
        pending = list(only)
        while pending:
            name = pending.pop()
            if name in wanted or name not in runnable:
                continue
            wanted.add(name)
            if name != COMBINE_JOB:
                pending.extend(as_list(specs[name].get("needs")))
    jobs: list[Job] = []
    for name in specs:
        if name not in wanted:
            continue
        if "strategy" not in specs[name]:
            jobs.append(Job(name, specs[name], {}))
            continue
        # The matrix comes from Integration-Matrix, which only counts shards.
        count = int(workflow["env"]["INTEGRATION_SHARD_COUNT"])
        for shard in range(count):
            if shards is None or shard in shards:
                jobs.append(Job(name, specs[name], {"shard": str(shard)}))
    return jobs


def as_list(value: typing.Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def report(result: Result, done: int, total: int) -> None:
    minutes, seconds = divmod(int(result.seconds), 60)
    print(
        f"[{done:3}/{total}] {result.status:4} {result.job.label} "
        f"({minutes}m{seconds:02}s, peak {result.peak_kb / 2**20:.2f} GiB)",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="nix run ./ci#local --", description=__doc__.splitlines()[0]
    )
    parser.add_argument(
        "-j",
        "--cores",
        type=int,
        default=len(os.sched_getaffinity(0)),
        help="Maximum CPU cores to use (default: all)",
    )
    parser.add_argument(
        "--only", help="Comma-separated job names; their `needs` are added"
    )
    parser.add_argument("--shards", help="Integration shards to run, e.g. 0-3,17")
    parser.add_argument(
        "--dirty", action="store_true", help="Include uncommitted tracked changes"
    )
    parser.add_argument(
        "--merge", metavar="REF", help="Merge REF first, as CI merges into main"
    )
    parser.add_argument("--pr-title", help="Also check this title with conventional.sh")
    parser.add_argument(
        "--workdir", type=pathlib.Path, help="Scratch directory (wiped on each run)"
    )
    ns = parser.parse_args()
    if ns.cores < 1:
        parser.error("--cores must be at least 1")

    repo = pathlib.Path(git(pathlib.Path.cwd(), "rev-parse", "--show-toplevel"))
    workdir = (ns.workdir or repo.with_name(repo.name + ".local-ci")).resolve()
    cpus = sorted(os.sched_getaffinity(0))[: ns.cores]
    os.sched_setaffinity(0, cpus)

    prepare_workdir(workdir)
    source = workdir / "source"
    commit = snapshot(repo, source, ns.dirty, ns.merge)
    workflow: Spec = yaml.safe_load((source / WORKFLOW).read_text())
    jobs = select_jobs(
        workflow,
        set(ns.only.split(",")) if ns.only else None,
        parse_ranges(ns.shards) if ns.shards else None,
    )
    print(f"commit {commit[:12]}, {len(jobs)} jobs, {len(cpus)} cores, in {workdir}")

    runner = Runner(workflow, workdir, source, commit, len(cpus))
    results: list[Result] = []
    failed: set[str] = set()

    def record(result: Result) -> None:
        results.append(result)
        if result.status == "FAIL":
            failed.add(result.job.name)
        report(result, len(results), len(jobs))

    def blocked(job: Job) -> bool:
        return bool(failed.intersection(as_list(job.spec.get("needs"))))

    if ns.pr_title is not None:
        script = source / ".github/workflows/scripts/conventional.sh"
        if subprocess.run(["bash", str(script), ns.pr_title]).returncode != 0:
            failed.add("PR-Title")

    serial = [job for job in jobs if job.name in SERIAL_JOBS]
    pooled = [job for job in jobs if job.name not in (*SERIAL_JOBS, COMBINE_JOB)]
    combine = [job for job in jobs if job.name == COMBINE_JOB]
    slots: queue.Queue[pathlib.Path] = queue.Queue()
    for index in range(min(len(cpus), max(len(pooled), 1))):
        checkout = workdir / f"checkout-{index}"
        clone(source, checkout, commit)
        slots.put(checkout)

    def pooled_job(job: Job) -> Result:
        if runner.cancelled or blocked(job):
            return Result(job, "skip", 0.0, None)
        checkout = slots.get()
        try:
            return runner.run_job(job, checkout, echo=False)
        finally:
            slots.put(checkout)

    try:
        first = workdir / "checkout-0"
        for job in serial:
            print(f"==> {job.label}", flush=True)
            record(
                Result(job, "skip", 0.0, None)
                if blocked(job)
                else runner.run_job(job, first, echo=True)
            )
        if any(job.name == "Lint" for job in pooled):
            print("==> prebuilding the lint shell", flush=True)
            env = runner.environment(pooled[0], first, {})
            subprocess.run(
                ["nix", "develop", ".#lint", "-c", "true"], cwd=first, env=env
            )
        with concurrent.futures.ThreadPoolExecutor(len(cpus)) as pool:
            futures = [pool.submit(pooled_job, job) for job in pooled]
            try:
                for future in concurrent.futures.as_completed(futures):
                    record(future.result())
            except KeyboardInterrupt:
                runner.cancel()
                raise
        for job in combine:
            print(f"==> {job.label}", flush=True)
            record(runner.run_job(job, first, echo=False))
    except KeyboardInterrupt:
        runner.cancel()
        print("interrupted")
        return 130

    print()
    for result in results:
        if result.status == "FAIL":
            print(f"FAIL {result.job.label}: {result.log}")
            if result.log is not None:
                lines = result.log.read_text(errors="replace").splitlines()
                for line in [ln for ln in lines if ln.startswith("FAIL ")][:20]:
                    print(f"    {line}")
    skipped = sum(result.status == "skip" for result in results)
    passed = sum(result.status == "pass" for result in results)
    failures = sum(result.status == "FAIL" for result in results)
    print(f"{passed} passed, {failures} failed, {skipped} skipped")
    memory = {
        "concurrent_peak_kb": runner.memory.total_peak,
        "job_peak_kb": {result.job.label: result.peak_kb for result in results},
    }
    (workdir / "memory.json").write_text(json.dumps(memory, indent=2) + "\n")
    heaviest = max(results, key=lambda result: result.peak_kb, default=None)
    print(f"peak memory, all jobs at once: {runner.memory.total_peak / 2**20:.1f} GiB")
    if heaviest is not None:
        print(
            f"heaviest job: {heaviest.job.label} at {heaviest.peak_kb / 2**20:.2f} GiB"
        )
    print(f"logs: {runner.logs}\nartifacts: {runner.artifacts}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
