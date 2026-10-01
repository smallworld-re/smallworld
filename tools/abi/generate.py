"""Build-time ABI table generation: runs stage 1 and stage 2.

The setuptools hook (build_hook.py) calls :func:`generate` on every wheel and
editable build. By hand:

    python tools/abi/generate.py --inplace            # write smallworld/platforms/abi/_data
    python tools/abi/generate.py --inplace --if-stale # only if an input changed
    python tools/abi/generate.py --out-dir DIR
    python tools/abi/generate.py --check              # build in a scratch dir, run
                                                      # every check, compare in-tree data
    python tools/abi/generate.py --report             # the provenance report
    python tools/abi/generate.py --compare DIR1 DIR2  # tables byte-identical?

Stage 1 (pypcode, angr, archinfo) and stage 2 (standard library, capstone,
smallworld's platform modules with everything else blocked) run as separate
subprocesses with this environment. Deliberately not ``-I``/``-E`` for this
interpreter: pip's build isolation reaches its build dependencies through
PYTHONPATH. Stage 1 runs with TMPDIR, TEMP and TMP pointed at a private
directory (mode 0700) inside the staging directory, because pyvex unpickles
a parser cache it finds in the temporary directory
(``$TMPDIR/pyvex_ffi_parser_cache.*``), and a shared ``/tmp`` would let any
local user plant one and run code in the build.

Which pypcode and angr stage 1 sees is whatever the build environment holds:
pyproject.toml's build-isolation pins choose pypcode 4.0.0 + angr 10.0.0 on
Python 3.12 and later and pypcode 3.3.3 + angr 9.2.194 on 3.10, but any
allow-listed set (overlay/versions.py) yields byte-identical tables.

Environment:

``SMALLWORLD_ABI_STAGE1_PYTHON``
    The interpreter stage 1 runs under (default: this one). Set it to dump
    from another interpreter's packages; nix does, because uv2nix installs
    the runtime lock's pypcode 3.3.3 / angr 9.2.194 into the build
    environment and nix/abi-build-tools provides a pypcode 4.0.0 / angr
    10.0.0 interpreter. When set, stage 1 always runs with ``-I``, so it
    sees only that interpreter's own packages; it may be any Python version.
    The allow-list and the pinned file digests still apply. Stage 2 always
    runs under this interpreter, and the ``--if-stale`` digest records the
    stage-1 interpreter's dependency versions.

``SMALLWORLD_ABI_ALLOW_MISSING``
    ``1``, ``true`` or ``yes`` ships no tables (``0``, ``false``, ``no`` or
    unset: generate them; anything else is an error). The opt-out is checked
    before anything else is loaded, so it works even with a broken overlay.
    It does not stop pip or uv from installing the build requirements
    (pypcode, angr) into an isolated build environment first; where they
    have no wheels, build with ``--no-build-isolation``.

Builds on a Python without a pinned dependency set (3.9, 3.11), and opted-out
builds, write a no-data marker instead: a ``_data`` package whose
``AVAILABLE`` is False and whose ``REASON`` says why. An editable build never
replaces real in-tree tables with that marker; it keeps them, and if their
inputs have changed since they were built it marks them ``STALE`` (the
registry then warns when it loads them) and warns on stderr.
"""

import argparse
import filecmp
import glob
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import types
import typing

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DATA_REL = os.path.join("smallworld", "platforms", "abi", "_data")
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import emit  # noqa: E402
from common import INPUT_PATTERNS, PREFIX, GeneratorError  # noqa: E402

OPT_OUT_ENV = "SMALLWORLD_ABI_ALLOW_MISSING"
STAGE1_PYTHON_ENV = "SMALLWORLD_ABI_STAGE1_PYTHON"
DIGEST_FILE = "_inputs.sha256"
#: Files whose bytes depend on which dependency set built the tables.
VARIANT_FILES = ("_build_info.py", DIGEST_FILE)

_DIGEST_PATTERNS = ("pyproject.toml",) + INPUT_PATTERNS
_TRUE = ("1", "true", "yes")
_FALSE = ("", "0", "false", "no")

_versions_module: typing.Optional[types.ModuleType] = None


def _versions() -> types.ModuleType:
    """overlay/versions.py, loaded on its own (stdlib only), so that deciding
    whether to generate never imports the rest of the overlay."""
    global _versions_module
    if _versions_module is None:
        spec = importlib.util.spec_from_file_location(
            "_smallworld_abi_versions", os.path.join(HERE, "overlay", "versions.py")
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _versions_module = module
    return _versions_module


def opted_out() -> bool:
    """Whether SMALLWORLD_ABI_ALLOW_MISSING asks for no tables."""
    raw = os.environ.get(OPT_OUT_ENV, "")
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise GeneratorError(
        f"{OPT_OUT_ENV}={raw!r} is not understood: use 1, true or yes to build "
        "without ABI tables, or 0, false, no or unset to generate them"
    )


def stage1_python() -> str:
    """The stage-1 interpreter. Raises GeneratorError for a bad override."""
    override = os.environ.get(STAGE1_PYTHON_ENV)
    if not override:
        return sys.executable
    found = shutil.which(override)
    if found is None or not os.path.isfile(found):
        raise GeneratorError(
            f"{STAGE1_PYTHON_ENV}={override!r} is not an executable file; set it "
            "to the path of a Python interpreter with pypcode and angr installed, "
            "or unset it to run stage 1 under this interpreter"
        )
    return found


def _installed_version(distribution: str, python: str) -> str:
    """The version of `distribution` visible to `python`, read from package
    metadata (never imported)."""
    if python == sys.executable:
        from importlib import metadata

        try:
            return metadata.version(distribution)
        except metadata.PackageNotFoundError:
            return "-"
    proc = subprocess.run(
        [
            python,
            "-I",
            "-c",
            "import sys\nfrom importlib import metadata\n"
            "try:\n print(metadata.version(sys.argv[1]))\n"
            "except metadata.PackageNotFoundError:\n print('-')",
            distribution,
        ],
        stdout=subprocess.PIPE,
        universal_newlines=True,
    )
    return proc.stdout.strip() or "-"


def sources_digest(src_root: str = ROOT) -> str:
    """A digest of every in-tree generator input (the overlay, the generator,
    the platform sources and pyproject.toml)."""
    digest = hashlib.sha256()
    files = set()
    for pattern in _DIGEST_PATTERNS:
        for path in glob.glob(os.path.join(src_root, pattern)):
            files.add(os.path.relpath(path, src_root).replace(os.sep, "/"))
    for rel in sorted(files):
        digest.update(rel.encode() + b"\0")
        with open(os.path.join(src_root, rel), "rb") as fh:
            digest.update(fh.read() + b"\0")
    return digest.hexdigest()


def input_digest(src_root: str = ROOT) -> str:
    """:func:`sources_digest` plus the dependency versions stage 1 would see,
    the Python version and the opt-out: the ``--if-stale`` key."""
    digest = hashlib.sha256(sources_digest(src_root).encode())
    python = stage1_python()
    for distribution in ("pypcode", "angr", "archinfo"):
        digest.update(
            f"{distribution}={_installed_version(distribution, python)}\0".encode()
        )
    digest.update(f"python={sys.version_info[0]}.{sys.version_info[1]}\0".encode())
    digest.update(f"{OPT_OUT_ENV}={opted_out()}\0".encode())
    return digest.hexdigest()


def outputs_digest(out_dir: str) -> str:
    """A digest of the generated modules in `out_dir`, so ``--if-stale``
    also regenerates tables someone edited by hand."""
    digest = hashlib.sha256()
    for name in sorted(os.listdir(out_dir)):
        if name.endswith(".py"):
            with open(os.path.join(out_dir, name), "rb") as fh:
                digest.update(name.encode() + b"\0" + fh.read() + b"\0")
    return digest.hexdigest()


def _read_digests(out_dir: str) -> typing.Dict[str, str]:
    """The ``full``, ``sources`` and ``outputs`` digests recorded in
    `out_dir`."""
    try:
        with open(os.path.join(out_dir, DIGEST_FILE), encoding="ascii") as fh:
            lines = fh.read().split()
    except OSError:
        return {}
    return dict(zip(lines[0::2], lines[1::2]))


def is_fresh(out_dir: str, src_root: str = ROOT) -> bool:
    """Whether `out_dir` was generated from the current inputs and has not
    been edited since."""
    recorded = _read_digests(out_dir)
    return recorded.get("full") == input_digest(src_root) and recorded.get(
        "outputs"
    ) == outputs_digest(out_dir)


def _mark_stale(out_dir: str, reason: typing.Optional[str]) -> None:
    """Record in the kept tables' ``__init__.py`` why they are stale (``None``:
    they are not). The registry warns once when it loads stale tables; this
    is the only way the news reaches users, because pip and uv hide a
    successful build's output."""
    path = os.path.join(out_dir, "__init__.py")
    with open(path, encoding="utf-8") as fh:
        lines = [
            line for line in fh.read().splitlines() if not line.startswith("STALE = ")
        ]
    if reason is not None:
        lines.append(f"STALE = {emit.Emitter().value(reason)}")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def has_tables(out_dir: str) -> bool:
    """Whether `out_dir` holds real tables (not the no-data marker)."""
    try:
        with open(os.path.join(out_dir, "__init__.py"), encoding="utf-8") as fh:
            return "\nAVAILABLE = True\n" in fh.read()
    except OSError:
        return False


def no_data_reason(
    version_info: typing.Optional[typing.Sequence[int]] = None,
) -> typing.Optional[str]:
    """Why this build ships no tables, or ``None`` if it generates them.
    Raises GeneratorError for a bad SMALLWORLD_ABI_ALLOW_MISSING."""
    if opted_out():
        return f"ABI table generation was switched off at build time ({OPT_OUT_ENV} was set)"
    reason: typing.Optional[str] = _versions().no_data_reason(
        version_info or sys.version_info[:3]
    )
    return reason


def marker_text(reason: str) -> str:
    return emit.header(
        "No ABI tables: this build of smallworld ships none. Every lookup in "
        "smallworld.platforms.abi raises ABITablesUnavailable with REASON."
    ) + (
        f"\nAVAILABLE = False\nREASON = {emit.Emitter().value(reason)}\n"
        "FEATURES = ()\nRECORDS = ()\n"
    )


def _run(
    step: str,
    command: typing.List[str],
    env: typing.Optional[typing.Dict[str, str]] = None,
) -> str:
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=env,
        )
    except OSError as e:
        raise GeneratorError(f"{step}: cannot run {command[0]}: {e}") from None
    if proc.returncode != 0:
        output = (proc.stderr or proc.stdout).strip().splitlines()
        tail = "\n".join(output[-60:])
        raise GeneratorError(f"{step} failed (exit {proc.returncode}):\n{tail}")
    return proc.stdout


def stage1_environment(private_tmp: str) -> typing.Dict[str, str]:
    """This environment with the temporary directory pointed at
    `private_tmp` (see the module docstring)."""
    env = dict(os.environ)
    for name in ("TMPDIR", "TEMP", "TMP"):
        env[name] = private_tmp
    return env


def _generate_tables(
    tmp: str, src_root: str, keep_snapshot: typing.Optional[str], report: bool
) -> typing.Tuple[typing.List[str], str]:
    snapshot = keep_snapshot or os.path.join(tmp, ".snapshot.json")
    python = stage1_python()
    # A separate stage-1 interpreter (nix's build tools) must see only its
    # own packages, not the build environment's PYTHONPATH.
    isolate = ["-I"] if os.environ.get(STAGE1_PYTHON_ENV) else []
    private_tmp = tempfile.mkdtemp(prefix=".stage1-tmp-", dir=tmp)
    try:
        _run(
            "stage 1 (dump pypcode, angr and archinfo)",
            [python] + isolate + [os.path.join(HERE, "stage1.py"), "--out", snapshot],
            env=stage1_environment(private_tmp),
        )
    finally:
        shutil.rmtree(private_tmp, ignore_errors=True)
    gen = os.path.join(tmp, "gen")
    command = [
        sys.executable,
        "-B",
        os.path.join(HERE, "stage2.py"),
        "--snapshot",
        snapshot,
        "--src",
        src_root,
        "--out-dir",
        gen,
    ]
    if report:
        command.append("--report")
    output = _run("stage 2 (normalize, apply the overlay, check, emit)", command)
    if not keep_snapshot:
        os.unlink(snapshot)
    for name in os.listdir(gen):
        os.replace(os.path.join(gen, name), os.path.join(tmp, name))
    os.rmdir(gen)
    return sorted(os.listdir(tmp)), output


def _warn(message: str) -> None:
    # stderr, not the build's log: setuptools hides announce() output
    # unless the build runs with -v.
    sys.stderr.write(f"{PREFIX}: WARNING: {message}\n")
    sys.stderr.flush()


def generate(
    out_dir: str,
    src_root: str = ROOT,
    editable: bool = False,
    keep_snapshot: typing.Optional[str] = None,
    version_info: typing.Optional[typing.Sequence[int]] = None,
    report: bool = False,
    log: typing.Callable[[str], None] = lambda message: None,
) -> typing.List[str]:
    """Write the ``_data`` package into `out_dir`, replacing it only once the
    new one is complete. Returns the file names in `out_dir`. Raises
    GeneratorError; on failure `out_dir` is left as it was."""
    try:
        return _generate(
            out_dir, src_root, editable, keep_snapshot, version_info, report, log
        )
    except OSError as e:
        raise GeneratorError(f"cannot write the ABI tables: {e}") from None


def _generate(
    out_dir: str,
    src_root: str,
    editable: bool,
    keep_snapshot: typing.Optional[str],
    version_info: typing.Optional[typing.Sequence[int]],
    report: bool,
    log: typing.Callable[[str], None],
) -> typing.List[str]:
    out_dir = os.path.abspath(out_dir)
    parent = os.path.dirname(out_dir)
    os.makedirs(parent, exist_ok=True)
    reason = no_data_reason(version_info)
    if reason is not None and editable and has_tables(out_dir):
        if _read_digests(out_dir).get("sources") == sources_digest(src_root):
            _mark_stale(out_dir, None)
            log(
                f"{PREFIX}: keeping the ABI tables already in {out_dir}; this "
                f"build would ship none ({reason})"
            )
        else:
            stale = (
                "their inputs (the overlay, the generator or the platform "
                "sources) changed after they were generated, and the editable "
                f"build that kept them could not regenerate them ({reason}); "
                "regenerate them on Python 3.10 or 3.12+ with "
                "`python tools/abi/generate.py --inplace`"
            )
            _mark_stale(out_dir, stale)
            _warn(f"keeping STALE ABI tables in {out_dir}: {stale}")
        return sorted(
            n for n in os.listdir(out_dir) if os.path.isfile(os.path.join(out_dir, n))
        )
    tmp = tempfile.mkdtemp(prefix=".abi-staging-", dir=parent)
    try:
        if reason is not None:
            with open(
                os.path.join(tmp, "__init__.py"), "w", encoding="utf-8", newline="\n"
            ) as fh:
                fh.write(marker_text(reason))
            files = ["__init__.py"]
            log(f"{PREFIX}: no ABI tables in this build: {reason}")
        else:
            files, output = _generate_tables(tmp, src_root, keep_snapshot, report)
            if output.strip():
                log(output.rstrip())
        with open(os.path.join(tmp, DIGEST_FILE), "w", encoding="ascii") as fh:
            fh.write(f"full {input_digest(src_root)}\n")
            fh.write(f"sources {sources_digest(src_root)}\n")
            fh.write(f"outputs {outputs_digest(tmp)}\n")
        files = sorted(set(files) | {DIGEST_FILE})
        if os.path.isdir(out_dir):
            # Refresh in place, which keeps the directory itself (and its
            # parent's mtime) stable for uv's cache keys.
            for name in os.listdir(out_dir):
                path = os.path.join(out_dir, name)
                shutil.rmtree(path) if os.path.isdir(path) else os.unlink(path)
            for name in files:
                os.replace(os.path.join(tmp, name), os.path.join(out_dir, name))
        else:
            os.replace(tmp, out_dir)
        return files
    finally:
        if os.path.isdir(tmp):
            shutil.rmtree(tmp, ignore_errors=True)


def compare(first: str, second: str) -> typing.List[str]:
    """The table files that differ between two ``_data`` directories
    (:data:`VARIANT_FILES` excepted)."""
    names = {n for d in (first, second) for n in os.listdir(d) if n.endswith(".py")}
    names -= set(VARIANT_FILES)
    differ = []
    for name in sorted(names):
        a, b = os.path.join(first, name), os.path.join(second, name)
        if not (
            os.path.isfile(a) and os.path.isfile(b) and filecmp.cmp(a, b, shallow=False)
        ):
            differ.append(name)
    return differ


def check(src_root: str = ROOT) -> int:
    """Generate into a scratch directory (running every stage-2 check) and
    compare the result with the in-tree tables, if there are any."""
    reason = no_data_reason()
    if reason is not None:
        print(f"{PREFIX}: --check needs a build that generates tables: {reason}")
        return 1
    with tempfile.TemporaryDirectory(prefix="abi-check-") as scratch:
        out = os.path.join(scratch, "_data")
        generate(out, src_root, report=True, log=print)
        in_tree = os.path.join(src_root, DATA_REL)
        if not has_tables(in_tree):
            print(f"{PREFIX}: check passed ({in_tree} holds no tables to compare)")
            return 0
        stale = compare(out, in_tree)
        if stale:
            print(
                f"{PREFIX}: the tables in {in_tree} are out of date ({', '.join(stale)}); "
                "rebuild them with `python tools/abi/generate.py --inplace`"
            )
            return 1
    print(f"{PREFIX}: check passed; the in-tree tables are current")
    return 0


def main(argv: typing.Optional[typing.List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    what = parser.add_mutually_exclusive_group(required=True)
    what.add_argument(
        "--inplace", action="store_true", help="write smallworld/platforms/abi/_data"
    )
    what.add_argument("--out-dir", help="write the _data package here")
    what.add_argument(
        "--check", action="store_true", help="run every check without writing"
    )
    what.add_argument(
        "--report", action="store_true", help="print the provenance report"
    )
    what.add_argument(
        "--compare", nargs=2, metavar="DIR", help="compare two _data directories"
    )
    parser.add_argument(
        "--if-stale", action="store_true", help="do nothing if no input changed"
    )
    parser.add_argument(
        "--keep-snapshot", metavar="PATH", help="also keep the stage-1 snapshot"
    )
    args = parser.parse_args(argv)
    try:
        if args.compare:
            empty = [d for d in args.compare if not has_tables(d)]
            if empty:
                print(
                    f"{PREFIX}: no ABI tables to compare in {', '.join(empty)} "
                    "(missing, or the no-data marker)"
                )
                return 1
            differ = compare(*args.compare)
            if differ:
                print(f"{PREFIX}: the tables differ: {', '.join(differ)}")
                return 1
            print(f"{PREFIX}: the tables are byte-identical")
            return 0
        if args.check:
            return check()
        if args.report:
            with tempfile.TemporaryDirectory(prefix="abi-report-") as scratch:
                generate(os.path.join(scratch, "_data"), report=True, log=print)
            return 0
        out = os.path.join(ROOT, DATA_REL) if args.inplace else args.out_dir
        if args.if_stale and is_fresh(out):
            return 0
        files = generate(
            out, editable=args.inplace, keep_snapshot=args.keep_snapshot, log=print
        )
    except GeneratorError as e:
        sys.stderr.write(f"\n{PREFIX}: {e}\n")
        return 2
    print(f"{PREFIX}: wrote {len(files)} files to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
