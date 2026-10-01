"""Stage 1: dump the raw ABI facts of the pypcode, angr and archinfo that are
installed in THIS interpreter.

Needs pypcode, angr and archinfo; never imports smallworld. It dumps only
what the overlay's joins ask for, and refuses any dependency set not on the
allow-list (overlay/versions.py). The JSON it writes has no absolute paths
and no timestamps, so it is byte-identical wherever it is built.

    python tools/abi/stage1.py --out snapshot.json
"""

import argparse
import importlib
import inspect
import logging
import os
import sys
import typing

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import cspec_xml  # noqa: E402
from common import dump_json, fail, sha256_bytes  # noqa: E402
from overlay import RECORDS, versions  # noqa: E402

SCHEMA = 1

Json = typing.Dict[str, typing.Any]

_INSTALL_HINT = (
    "The ABI tables are generated at build time from pypcode and angr, which "
    "pyproject.toml's [build-system] requires pins. If they are missing, build "
    "isolation is off (--no-build-isolation, --no-isolation): install a "
    "supported set first, for example\n"
    "    pip install 'pypcode==4.0.0' 'angr==10.0.0'     # Python >= 3.12\n"
    "    pip install 'pypcode==3.3.3' 'angr==9.2.194'    # Python 3.10\n"
    "If one of them is installed but crashes on import, a transitive dependency "
    "has probably drifted to a release it does not support (for example "
    "pycparser 3 under angr 9.2.x): the build-isolation environment is only "
    "constrained by tools/abi/build-constraints.txt (applied by uv through "
    "[tool.uv] build-constraint-dependencies; for pip, run `pip install "
    "--build-constraint tools/abi/build-constraints.txt .`, not PIP_CONSTRAINT). "
    "Either way, building with SMALLWORLD_ABI_ALLOW_MISSING=1 ships smallworld "
    "without ABI tables (the build requirements are still installed; without "
    "wheels for them, add --no-build-isolation)."
)


def _smallworld_loaded() -> typing.List[str]:
    return sorted(m for m in sys.modules if m.split(".", 1)[0] == "smallworld")


def import_dependencies() -> typing.Tuple[typing.Any, typing.Any, typing.Any]:
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    logging.getLogger("cle").setLevel(logging.CRITICAL)
    modules = {}
    problems = []
    for name in ("pypcode", "archinfo", "angr"):
        try:
            modules[name] = __import__(name)
        except Exception as e:  # ImportError, or a crash inside angr's import
            problems.append(f"  - {name}: {type(e).__name__}: {e}")
    if problems:
        fail(
            f"cannot import the ABI build dependencies on Python "
            f"{sys.version.split()[0]}:\n" + "\n".join(problems) + "\n" + _INSTALL_HINT
        )
    return modules["pypcode"], modules["angr"], modules["archinfo"]


def check_versions(
    pypcode: typing.Any, angr: typing.Any, archinfo: typing.Any
) -> versions.DependencySet:
    try:
        return versions.find(
            pypcode.__version__, angr.__version__, archinfo.__version__
        )
    except ValueError as e:
        fail(str(e))


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _ldefs_path(pypcode: typing.Any, language: str) -> typing.Optional[str]:
    for arch in pypcode.Arch.enumerate():
        if any(lang.id == language for lang in arch.languages):
            return typing.cast(str, arch.ldefpath)
    return None


def _source_lines(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        return sum(1 for _ in fh)


def ghidra_snapshot(pypcode: typing.Any, found: versions.DependencySet) -> Json:
    version = found.pypcode
    pins = versions.PinnedFiles(found)
    processors = os.path.join(os.path.dirname(pypcode.__file__), "processors")
    out: Json = {"prototypes": {}, "cspecs": {}, "languages": {}}
    problems = []
    for spec in RECORDS:
        join = spec.ghidra
        if join.key in out["prototypes"]:
            continue
        language = pypcode.ArchLanguage.from_id(join.language)
        if language is None:
            problems.append(
                f"{spec.id}: pypcode {version} has no language {join.language!r}"
            )
            continue
        compilers = {c.attrib.get("id"): c for c in language.ldef.findall("compiler")}
        compiler = compilers.get(join.compiler)
        if compiler is None:
            problems.append(
                f"{spec.id}: {join.language} has no compiler {join.compiler!r} "
                f"in pypcode {version} (it has {sorted(compilers)})"
            )
            continue
        path = os.path.join(language.archdir, compiler.attrib["spec"])
        rel = os.path.relpath(path, processors).replace(os.sep, "/")
        if not os.path.isfile(path):
            problems.append(
                f"{spec.id}: {join.language} compiler {join.compiler!r} references "
                f"{rel}, which pypcode {version} does not ship"
            )
            continue
        size = int(language.ldef.attrib.get("size", "32"))
        ldefs = _ldefs_path(pypcode, join.language)
        if ldefs is None:
            problems.append(f"{spec.id}: no .ldefs defines {join.language}")
            continue
        ldefs_rel = os.path.relpath(ldefs, processors).replace(os.sep, "/")
        raw = _read(path)
        sla = language.slafile_path
        sla_rel = os.path.relpath(sla, processors).replace(os.sep, "/")
        pinned = [
            pins.check(f"ghidra:{ldefs_rel}", _read(ldefs)),
            pins.check(f"ghidra:{sla_rel}", _read(sla)),
            pins.check(f"ghidra:{rel}", raw),
        ]
        if not all(pinned):
            continue  # reported below; never parse an unpinned file
        try:
            cspec = cspec_xml.parse_cspec(path, size // 8)
        except Exception as e:
            problems.append(f"{rel}: cannot parse: {type(e).__name__}: {e}")
            continue
        protos = [p for p in cspec["prototypes"] if p["name"] == join.prototype]
        if len(protos) != 1:
            problems.append(
                f"{spec.id}: {rel} has {len(protos)} prototypes {join.prototype!r}"
            )
            continue
        text = raw.decode("utf-8")
        out["cspecs"][rel] = {
            "sha256": sha256_bytes(raw),
            "lines": len(text.splitlines()),
        }
        prototype = protos[0]
        prototype["lines"] = list(cspec_xml.prototype_lines(text, join.prototype))
        entry = {
            "cspec": rel,
            "prototype": prototype,
            "data_organization": cspec["data_organization"],
            "stackpointer": cspec["stackpointer"],
            "returnaddress": cspec["returnaddress"],
        }
        out["prototypes"][join.key] = entry
        names = cspec_xml.register_names(entry)
        if cspec["stackpointer"]:
            names.add(cspec["stackpointer"]["register"])
        table = out["languages"].setdefault(join.language, {})
        table.update(cspec_xml.sleigh_registers(pypcode, join.language, names))
    if problems:
        fail(
            "the Ghidra compiler specs are missing or unreadable:\n  - "
            + "\n  - ".join(problems)
        )
    if pins.problems:
        fail(
            "the Ghidra files differ from the pinned ones:\n  - "
            + "\n  - ".join(pins.problems)
        )
    return out


def _location(value: typing.Any) -> typing.Optional[Json]:
    if value is None:
        return None
    kind = type(value).__name__
    if kind in ("SimRegArg", "SimLyingRegArg"):
        return {"reg": value.reg_name, "size": value.size}
    if kind == "SimStackArg":
        return {"stack": value.stack_offset, "size": value.size}
    if kind == "SimComboArg":
        return {"combo": [_location(v) for v in value.locations]}
    return {"other": kind}


class _RecordingRegisters:
    def __init__(self) -> None:
        self.read: typing.List[str] = []

    def __getattr__(self, name: str) -> int:
        self.read.append(name)
        return 0


class _RecordingState:
    def __init__(self) -> None:
        self.regs = _RecordingRegisters()


def _syscall_number_register(cc: typing.Any) -> typing.Optional[str]:
    """The register ``cc.syscall_num(state)`` reads, found by calling it with
    a state that records register reads."""
    state = _RecordingState()
    try:
        cc.syscall_num(state)
    except Exception:
        return None
    read = state.regs.read
    return read[0] if len(read) == 1 else None


def _class_location(cls: typing.Any, package: typing.Any) -> Json:
    path = inspect.getsourcefile(cls) or ""
    root = os.path.dirname(os.path.abspath(package.__file__))
    lines, first = inspect.getsourcelines(cls)
    return {
        "file": os.path.relpath(path, root).replace(os.sep, "/"),
        "lines": [first, first + len(lines) - 1],
    }


def _calling_convention(cls: typing.Any, angr: typing.Any) -> Json:
    cc: Json = {"class": cls.__name__, "source": _class_location(cls, angr)}
    for name in ("ARG_REGS", "FP_ARG_REGS", "CALLER_SAVED_REGS"):
        value = getattr(cls, name, None)
        cc[name] = list(value) if value is not None else None
    for name in (
        "RETURN_VAL",
        "OVERFLOW_RETURN_VAL",
        "FP_RETURN_VAL",
        "OVERFLOW_FP_RETURN_VAL",
        "RETURN_ADDR",
    ):
        cc[name] = _location(getattr(cls, name, None))
    for name in (
        "STACKARG_SP_DIFF",
        "STACKARG_SP_BUFF",
        "STACK_ALIGNMENT",
        "CALLEE_CLEANUP",
    ):
        value = getattr(cls, name, None)
        cc[name] = value if isinstance(value, (int, bool, type(None))) else repr(value)
    return cc


def _probes(cc_class: typing.Any, arch: typing.Any) -> Json:
    """What angr itself does with a struct return and with stack arguments,
    asked of its calling-convention code rather than read from class
    attributes: the register of the hidden struct-return pointer, and the
    stack offsets of the first three stack-passed ``int`` arguments."""
    from angr.sim_type import SimStruct, SimTypeFunction, SimTypeInt, SimTypeLongLong

    cc = cc_class(arch)
    probes: Json = {"sret_register": None, "stack_int_offsets": None}
    big = SimStruct(
        {name: SimTypeLongLong() for name in ("a", "b", "c", "d", "e")}, name="big"
    ).with_arch(arch)
    ref = cc.return_val(big)
    ptr: typing.Any = getattr(ref, "ptr_loc", None)
    if ptr is not None and type(ptr).__name__ == "SimRegArg":
        probes["sret_register"] = ptr.reg_name
    count = len(cc_class.ARG_REGS or ()) + 3
    proto = SimTypeFunction([SimTypeInt()] * count, SimTypeInt()).with_arch(arch)
    stack = [
        loc.stack_offset
        for loc in cc.arg_locs(proto)
        if type(loc).__name__ == "SimStackArg"
    ]
    probes["stack_int_offsets"] = stack[:3]
    return probes


def angr_snapshot(
    angr: typing.Any, archinfo: typing.Any, found: versions.DependencySet
) -> Json:
    from angr import calling_conventions

    pins = versions.PinnedFiles(found)
    out: Json = {"conventions": {}, "files": {"angr": {}, "archinfo": {}}}
    problems = []
    for spec in RECORDS:
        join = spec.angr
        if join.key in out["conventions"]:
            continue
        try:
            arch = getattr(archinfo, join.arch)(getattr(archinfo.Endness, join.endness))
        except Exception as e:
            problems.append(f"{spec.id}: archinfo.{join.arch}: {type(e).__name__}: {e}")
            continue
        default = calling_conventions.DEFAULT_CC.get(arch.name, {}).get(join.os)
        syscall = calling_conventions.SYSCALL_CC.get(arch.name, {}).get(join.os)
        if default is None:
            problems.append(
                f"{spec.id}: angr has no {join.os} calling convention for {arch.name}"
            )
            continue
        entry: Json = {
            "arch": arch.name,
            "default_cc": _calling_convention(default, angr),
            "syscall_cc": None,
            "elf_tls": None,
            "archinfo_source": _class_location(type(arch), archinfo),
            "arch_bytes": arch.bytes,
        }
        try:
            entry["probes"] = _probes(default, arch)
        except Exception as e:
            problems.append(f"{spec.id}: probing {default.__name__}: {e!r}")
            continue
        if syscall is not None:
            entry["syscall_cc"] = _calling_convention(syscall, angr)
            entry["syscall_cc"]["syscall_number_register"] = _syscall_number_register(
                syscall
            )
            source = inspect.getsourcelines(syscall.syscall_num)
            entry["syscall_cc"]["syscall_num_lines"] = [
                source[1],
                source[1] + len(source[0]) - 1,
            ]
        tls = getattr(arch, "elf_tls", None)
        if tls is not None:
            entry["elf_tls"] = {
                name: getattr(tls, name)
                for name in (
                    "variant",
                    "tcbhead_size",
                    "head_offsets",
                    "dtv_offsets",
                    "pthread_offsets",
                    "tp_offset",
                    "dtv_entry_offset",
                )
            }
        out["conventions"][join.key] = entry
        for package, located in (
            ("angr", entry["default_cc"]["source"]),
            ("archinfo", entry["archinfo_source"]),
        ):
            module = angr if package == "angr" else archinfo
            root = os.path.dirname(os.path.abspath(module.__file__))
            path = os.path.join(root, located["file"])
            pins.check(f"{package}:{located['file']}", _read(path))
            out["files"][package][located["file"]] = _source_lines(path)
        # The probes build angr types (sim_type.py), and archinfo's TLS
        # layout comes from its TLSArchInfo (tls.py): pin those too.
        sim_type = importlib.import_module("angr.sim_type")
        extra = [("angr", angr, sim_type.__file__)]
        if tls is not None:
            extra.append(("archinfo", archinfo, inspect.getsourcefile(type(tls))))
        for package, module, path in extra:
            if path is None:
                problems.append(f"{spec.id}: cannot locate the {package} source to pin")
                continue
            root = os.path.dirname(os.path.abspath(module.__file__))
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            pins.check(f"{package}:{rel}", _read(path))
        syscall_cc = entry["syscall_cc"]
        if syscall_cc and syscall_cc["source"]["file"] not in out["files"]["angr"]:
            problems.append(
                f"{spec.id}: angr's syscall calling convention is in "
                f"{syscall_cc['source']['file']}, which stage 1 does not pin"
            )
    if problems:
        fail("angr calling-convention data is missing:\n  - " + "\n  - ".join(problems))
    if pins.problems:
        fail(
            "the angr and archinfo files differ from the pinned ones:\n  - "
            + "\n  - ".join(pins.problems)
        )
    return out


def main(argv: typing.Optional[typing.List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="where to write the snapshot JSON")
    args = parser.parse_args(argv)
    if _smallworld_loaded():
        fail("stage 1 must not import smallworld")
    pypcode, angr, archinfo = import_dependencies()
    found = check_versions(pypcode, angr, archinfo)
    snapshot = {
        "schema": SCHEMA,
        "versions": {
            "pypcode": found.pypcode,
            "ghidra": found.ghidra,
            "angr": found.angr,
            "archinfo": found.archinfo,
        },
        "ghidra": ghidra_snapshot(pypcode, found),
        "angr": angr_snapshot(angr, archinfo, found),
    }
    leaked = _smallworld_loaded()
    if leaked:
        fail(f"stage 1 imported smallworld (through a dependency): {leaked}")
    dump_json(snapshot, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
