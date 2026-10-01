"""Stage 2: turn a stage-1 snapshot plus the overlay into ABI records, check
them, and write the ``_data`` package.

Pure: the standard library, capstone, and smallworld's utils, exceptions and
platforms modules loaded from the source tree by stub_loader (smallworld
itself, angr and pypcode are blocked). Runs on Python >= 3.9.

    python tools/abi/stage2.py --snapshot snap.json --src . --out-dir DIR
    python tools/abi/stage2.py --snapshot snap.json --src . --report

Per field (overlay/authority.py) a value is generated from its dependency,
derived by a Rule, or curated in the overlay. The explanation invariant: every
generated value equals the dependency's value, that value after named Rules,
or exactly one Deviation, and a Deviation that no longer matches what the
dependency says fails the build.
"""

import argparse
import dataclasses
import enum
import fnmatch
import json
import os
import re
import subprocess
import sys
import typing

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import emit  # noqa: E402
import stub_loader  # noqa: E402
from common import INPUT_PATTERNS, GeneratorError, fail, sha256_file  # noqa: E402
from overlay import (  # noqa: E402
    MASTER_SEED_CEILING,
    RECORDS,
    authority,
    rules,
    versions,
)
from overlay.schema import (  # noqa: E402
    DEPENDENCY_CITES,
    Cite,
    Deviation,
    RecordSpec,
    effective_confidence,
    master_seed_count,
)

Json = typing.Dict[str, typing.Any]

_SPAN = re.compile(
    r"^(?P<name>[A-Za-z0-9_]+)(\[(?P<lo>\d+):(?P<hi>\d+)\])?(&(?P<mask>0x[0-9A-Fa-f]+))?$"
)

_FEATURE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

#: Confidence levels, least verified first.
CONFIDENCE_ORDER = ("low", "medium", "high")

_NON_VALUE_ROLES = {
    "stack-pointer",
    "tls",
    "global-pointer",
    "toc",
    "platform-register",
    "link",
    "reserved",
    "zero",
}


class Problems:
    """Collects every problem, so one run reports them all."""

    def __init__(self) -> None:
        self.items: typing.List[str] = []

    def add(self, message: str) -> None:
        self.items.append(message)

    def extend(self, messages: typing.Iterable[str]) -> None:
        self.items.extend(messages)

    def __bool__(self) -> bool:
        return bool(self.items)


@dataclasses.dataclass
class Cell:
    """One field's final value and where it came from."""

    value: typing.Any
    tag: str
    rules: typing.Tuple[str, ...] = ()
    deviations: typing.Tuple[str, ...] = ()
    confidence: str = "high"
    cite: typing.Tuple[str, ...] = ()


@dataclasses.dataclass
class Result:
    records: typing.List[typing.Any]
    cells: typing.Dict[str, Cell]
    applied: typing.List[str]
    residuals: typing.List[Json]
    report: typing.List[str]


# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------


class Registers:
    """Builds RegEntry values for one record from its PlatformDef and
    register file."""

    def __init__(
        self, sw: stub_loader.Smallworld, spec: RecordSpec, problems: Problems
    ):
        self.sw = sw
        self.spec = spec
        self.file = spec.register_file
        self.problems = problems
        platforms = sw.platforms
        self.platform = platforms.Platform(
            platforms.Architecture[spec.architecture],
            platforms.Byteorder[spec.byteorder],
        )
        self.platdef = platforms.PlatformDef.for_platform(self.platform)
        self.spans = sw.model._platformdef_spans(self.platdef)
        order = list(self.platdef.registers)
        modeled = []
        for root in self.file.roots:
            span = self.spans.get(root)
            if span is None or span[0] != root:
                problems.add(
                    f"{spec.id}: register file root {root!r} is not a PlatformDef root"
                )
                continue
            modeled.append(root)
        self.universe = tuple(sorted(modeled, key=order.index)) + tuple(
            self.file.unmodeled_roots
        )
        self._index = {root: i for i, root in enumerate(self.universe)}

    def reg_class(self, root: str) -> typing.Any:
        klass = self.file.classes.get(root)
        if klass is None:
            self.problems.add(
                f"{self.spec.id}: register file gives no class for {root!r}"
            )
            klass = "special"
        return self.sw.enums.RegClass(klass)

    def root_of(self, name: str) -> str:
        span = self.spans.get(name)
        return span[0] if span is not None else name

    def entry(
        self,
        name: str,
        roles: typing.Iterable[str] = (),
        byte_range: typing.Optional[typing.Tuple[int, int]] = None,
        mask: typing.Optional[int] = None,
    ) -> typing.Any:
        """The RegEntry for `name` (or the bytes `byte_range` of the root
        `name`), with `roles` sorted into Role order."""
        enums = self.sw.enums
        role_order = list(enums.Role)
        ordered = tuple(sorted({enums.Role(r) for r in roles}, key=role_order.index))
        if name in self.file.unmodeled:
            width = self.file.unmodeled[name]
            return self.sw.model.RegEntry(
                name=name,
                root=name,
                offset=0,
                width=0,
                abi_width=width,
                root_width=0,
                partial=False,
                abi_name=self.file.abi_name(name),
                abi_aliases=tuple(self.file.abi_aliases.get(name, ())),
                unmodeled=True,
                reg_class=self.reg_class(name),
                roles=ordered,
                preserved_mask=mask,
            )
        span = self.spans.get(name)
        if span is None:
            raise GeneratorError(
                f"{self.spec.id}: {name!r} is not a register of {self.platform}"
            )
        root, lo, hi = span
        width = hi - lo
        if byte_range is not None:
            if name != root:
                raise GeneratorError(
                    f"{self.spec.id}: a byte range needs a root, not {name!r}"
                )
            lo, hi = byte_range
        root_width = self.platdef.registers[root].size
        return self.sw.model.RegEntry(
            name=name,
            root=root,
            offset=lo,
            width=width,
            abi_width=hi - lo,
            root_width=root_width,
            partial=not (lo == 0 and hi - lo == root_width),
            abi_name=self.file.abi_name(name),
            abi_aliases=tuple(self.file.abi_aliases.get(name, ())),
            unmodeled=False,
            reg_class=self.reg_class(root),
            roles=ordered,
            preserved_mask=mask,
        )

    def parse_span(
        self, text: str
    ) -> typing.Tuple[
        str, typing.Optional[typing.Tuple[int, int]], typing.Optional[int]
    ]:
        match = _SPAN.match(text)
        if match is None:
            raise GeneratorError(f"{self.spec.id}: bad register span {text!r}")
        byte_range = None
        if match.group("lo") is not None:
            byte_range = (int(match.group("lo")), int(match.group("hi")))
        mask = int(match.group("mask"), 16) if match.group("mask") else None
        return match.group("name"), byte_range, mask

    def span_key(self, text: str) -> typing.Tuple[int, int]:
        """Register-file order of a span string."""
        name, byte_range, _ = self.parse_span(text)
        root = self.root_of(name)
        offset = byte_range[0] if byte_range else self.spans.get(name, (root, 0, 0))[1]
        return (self._index.get(root, len(self._index)), offset)


# ---------------------------------------------------------------------------
# Dependency values
# ---------------------------------------------------------------------------


class GhidraNames:
    """Ghidra register name -> PlatformDef name (Rule R-CANONICALIZE)."""

    def __init__(self, sw: stub_loader.Smallworld, registers: Registers, sleigh: Json):
        self.sw = sw
        self.registers = registers
        self.sleigh = sleigh

    def __call__(self, ghidra_name: str) -> typing.Tuple[str, bool]:
        platdef = self.registers.platdef
        lowered = ghidra_name.lower()
        name = self.sw.naming.canonicalize_register(lowered, platdef)
        if name is None:
            for container in self.sleigh.get(ghidra_name, {}).get("containing", []):
                name = self.sw.naming.canonicalize_register(container.lower(), platdef)
                if name is not None:
                    break
        if name is None:
            raise GeneratorError(
                f"{self.registers.spec.id}: Ghidra register {ghidra_name!r} has no "
                f"{type(platdef).__name__} register (add a Rule or a register view)"
            )
        return name, name != lowered


def ghidra_values(
    spec: RecordSpec,
    entry: Json,
    names: GhidraNames,
    thread_pointer: typing.Optional[str],
    registers: Registers,
) -> typing.Dict[str, typing.Tuple[typing.Any, typing.Set[str]]]:
    """The Ghidra-authoritative fields of one record, normalized."""
    proto = entry["prototype"]
    out: typing.Dict[str, typing.Tuple[typing.Any, typing.Set[str]]] = {}

    def regs(pentries: typing.Iterable[Json], field: str) -> None:
        values, used = [], set()
        for pentry in pentries:
            loc = pentry["loc"]
            if loc["kind"] != "register":
                raise GeneratorError(
                    f"{spec.id}: {field} has a {loc['kind']} pentry (add a Rule)"
                )
            name, changed = names(loc["name"])
            if changed:
                used.add("R-CANONICALIZE")
            values.append(name)
        out[field] = (tuple(values), used)

    inputs = (proto["input"] or {}).get("entries", [])
    outputs = (proto["output"] or {}).get("entries", [])
    in_regs = [e for e in inputs if e["loc"]["kind"] != "stack"]
    out_regs = [e for e in outputs if e["loc"]["kind"] != "stack"]
    regs(
        [e for e in in_regs if e["storage_class"] not in ("float", "hiddenret")],
        "int_args.registers",
    )
    regs([e for e in in_regs if e["storage_class"] == "float"], "fp_args.registers")
    regs(
        [e for e in out_regs if e["storage_class"] != "float"], "returns.int_registers"
    )
    regs([e for e in out_regs if e["storage_class"] == "float"], "returns.fp_registers")

    stack = [e for e in inputs if e["loc"]["kind"] == "stack"]
    if stack:
        first = min(stack, key=lambda e: e["loc"]["offset"])
        out["stack.first_arg_offset"] = (first["loc"]["offset"], {"R-STACK-SLOT"})
        out["stack.slot_size"] = (first.get("align") or 1, {"R-STACK-SLOT"})

    hidden = [e for e in inputs if e["storage_class"] == "hiddenret"]
    if hidden:
        name, changed = names(hidden[0]["loc"]["name"])
        out["sret.register"] = (name, {"R-CANONICALIZE"} if changed else set())
    else:
        actions = [
            a["tag"]
            for r in (proto["output"] or {}).get("rules", [])
            for a in r["actions"]
        ]
        if "hidden_return" in actions and out["int_args.registers"][0]:
            out["sret.register"] = (
                out["int_args.registers"][0][0],
                {"R-SRET-FIRST-INT"},
            )

    callee, used = [], set()
    for ref in proto.get("unaffected") or []:
        if ref["kind"] != "register":
            raise GeneratorError(
                f"{spec.id}: <unaffected> has a {ref['kind']} entry (add a Rule)"
            )
        name, changed = names(ref["name"])
        if changed:
            used.add("R-CANONICALIZE")
        if thread_pointer is not None and registers.root_of(name) == thread_pointer:
            used.add("R-ROLE-FILTER")
            continue
        callee.append(name)
    out["preservation.callee_saved"] = (
        tuple(sorted(dict.fromkeys(callee), key=registers.span_key)),
        used,
    )
    if entry.get("stackpointer"):
        name, changed = names(entry["stackpointer"]["register"])
        out["special.stack_pointer"] = (name, {"R-CANONICALIZE"} if changed else set())
    return out


def _angr_register(spec: RecordSpec, registers: Registers, name: str) -> str:
    if name not in registers.spans:
        raise GeneratorError(
            f"{spec.id}: angr register {name!r} is not a PlatformDef register"
        )
    return name


def angr_values(
    spec: RecordSpec, conv: Json, registers: Registers
) -> typing.Dict[str, typing.Tuple[typing.Any, typing.Set[str]]]:
    out: typing.Dict[str, typing.Tuple[typing.Any, typing.Set[str]]] = {}
    ra = conv["default_cc"]["RETURN_ADDR"]
    if ra is not None and "stack" in ra:
        out["return_mechanics.ra_register"] = (None, set())
        out["return_mechanics.ra_stack_offset"] = (ra["stack"], set())
        out["return_mechanics.ra_size"] = (ra["size"], set())
    elif ra is not None and "reg" in ra:
        out["return_mechanics.ra_register"] = (
            _angr_register(spec, registers, ra["reg"]),
            set(),
        )
        out["return_mechanics.ra_stack_offset"] = (None, set())
        out["return_mechanics.ra_size"] = (ra["size"], set())
    syscall = conv.get("syscall_cc")
    if syscall is not None:
        number = syscall.get("syscall_number_register")
        if number is not None:
            out["syscall.number_register"] = (
                _angr_register(spec, registers, number),
                {"R-ANGR-SYSCALL-NUMBER"},
            )
        ret = syscall.get("RETURN_VAL")
        if ret is not None and "reg" in ret:
            out["syscall.return_register"] = (
                _angr_register(spec, registers, ret["reg"]),
                set(),
            )
    return out


def archinfo_values(
    spec: RecordSpec, conv: Json
) -> typing.Dict[str, typing.Tuple[typing.Any, typing.Set[str]]]:
    tls = conv.get("elf_tls")
    if tls is None:
        return {}
    out: typing.Dict[str, typing.Tuple[typing.Any, typing.Set[str]]] = {
        "special.tls.variant": (tls["variant"], set()),
        "special.tls.tp_offset": (tls["tp_offset"], set()),
    }
    if len(tls["dtv_offsets"]) == 1:
        out["special.tls.dtv_offset"] = (tls["dtv_offsets"][0], set())
    return out


# ---------------------------------------------------------------------------
# Overlay checks
# ---------------------------------------------------------------------------


def _freeze(value: typing.Any) -> typing.Any:
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def _dependency_versions(dependency: str) -> typing.Set[str]:
    return {
        getattr(s, "ghidra" if dependency == "ghidra" else dependency)
        for s in versions.SUPPORTED
    }


def check_cite(cite: Cite, where: str, snapshot: Json, problems: Problems) -> None:
    for problem in cite.problems():
        problems.add(f"{where}: {problem}")
    if cite.kind not in DEPENDENCY_CITES:
        return
    version = cite.get("version")
    if version not in _dependency_versions(cite.kind):
        problems.add(f"{where}: {cite.text()} names an unsupported {cite.kind} version")
        return
    current = snapshot["versions"]["ghidra" if cite.kind == "ghidra" else cite.kind]
    if version != current:
        return  # checked when that version builds
    location = cite.get("location")
    path, _, lines = location.partition(":")
    if cite.kind == "ghidra":
        known = {k: v["lines"] for k, v in snapshot["ghidra"]["cspecs"].items()}
    else:
        known = snapshot["angr"]["files"][cite.kind]
    if path not in known:
        problems.add(
            f"{where}: {cite.text()} names a file the {cite.kind} {version} snapshot does not record"
        )
        return
    last = max(int(n) for n in re.findall(r"\d+", lines))
    if last > known[path]:
        problems.add(
            f"{where}: {cite.text()} is past the end of {path} ({known[path]} lines)"
        )


def check_deviation(
    deviation: Deviation, spec: RecordSpec, snapshot: Json, problems: Problems
) -> None:
    where = f"deviation {deviation.id}"
    if deviation.record != spec.id:
        problems.add(f"{where}: record {deviation.record!r} is not {spec.id!r}")
    source = authority.GENERATED.get(deviation.field)
    if source is None:
        problems.add(
            f"{where}: {deviation.field} is not a generated field (use a Hand)"
        )
    elif source != deviation.dependency:
        problems.add(
            f"{where}: {deviation.field} comes from {source}, not {deviation.dependency}"
        )
    if deviation.klass not in ("a", "b", "c", "d"):
        problems.add(f"{where}: klass must be a, b, c or d")
    if deviation.keying and not deviation.versions:
        problems.add(f"{where}: a keying deviation names the versions it applies to")
    if not deviation.observed:
        problems.add(
            f"{where}: observed is empty; a deviation names at least one "
            f"{deviation.dependency} version and the value it gives"
        )
    known = _dependency_versions(deviation.dependency)
    for version, observed in deviation.observed.items():
        if version not in known:
            problems.add(
                f"{where}: observed names unsupported {deviation.dependency} {version}"
            )
        if _freeze(observed) == _freeze(deviation.abi_value):
            problems.add(
                f"{where}: {deviation.dependency} {version} already gives the ABI value"
            )
    current = snapshot["versions"][
        "ghidra" if deviation.dependency == "ghidra" else deviation.dependency
    ]
    if current in deviation.observed and not any(
        c.kind == deviation.dependency and c.get("version") == current
        for c in deviation.cite
    ):
        problems.add(
            f"{where}: cites no {deviation.dependency} {current} lines for the value it overrides"
        )
    _, cite_problems = effective_confidence(deviation.confidence, deviation.cite)
    problems.extend(f"{where}: {p}" for p in cite_problems)
    for cite in deviation.cite:
        check_cite(cite, where, snapshot, problems)


# ---------------------------------------------------------------------------
# Building records
# ---------------------------------------------------------------------------


def check_expectations(
    spec: RecordSpec,
    cells: typing.Dict[str, "Cell"],
    snapshot: Json,
    problems: Problems,
) -> None:
    """Every Expect names a generated field, cites its source, and matches
    the final value."""
    for expect in spec.expectations:
        where = f"{spec.id}: expectation on {expect.field}"
        _, cite_problems = effective_confidence("high", expect.cite)
        problems.extend(f"{where}: {p}" for p in cite_problems)
        for cite in expect.cite:
            check_cite(cite, where, snapshot, problems)
        if expect.field not in authority.GENERATED:
            problems.add(f"{where}: expectations check generated fields only")
            continue
        cell = cells.get(expect.field)
        if cell is None:
            if expect.value is not None:
                problems.add(
                    f"{spec.id}: {expect.field} was not generated, but the overlay "
                    f"expects {expect.value!r}"
                )
            continue
        if cell.value != _freeze(expect.value):
            problems.add(
                f"{spec.id}: {expect.field} is generated as {cell.value!r}, but the "
                f"overlay expects {expect.value!r} "
                f"({'; '.join(c.text() for c in expect.cite)}): fix the join, or "
                "explain the dependency's value with a Deviation"
            )


def _unwrap_optional(tp: typing.Any) -> typing.Tuple[typing.Any, bool]:
    if typing.get_origin(tp) is typing.Union:
        args = [a for a in typing.get_args(tp) if a is not type(None)]
        if len(args) == 1:
            return args[0], True
    return tp, False


class Builder:
    """Converts overlay-level values into schema values, driven by the
    schema's own field types."""

    def __init__(
        self, sw: stub_loader.Smallworld, registers: Registers, spec: RecordSpec
    ):
        self.sw = sw
        self.registers = registers
        self.spec = spec

    def convert(self, value: typing.Any, tp: typing.Any, path: str) -> typing.Any:
        tp, optional = _unwrap_optional(tp)
        if value is None:
            if optional:
                return None
            raise GeneratorError(f"{self.spec.id}: {path} may not be None")
        origin = typing.get_origin(tp)
        if origin is tuple:
            if not isinstance(value, (tuple, list)):
                raise GeneratorError(
                    f"{self.spec.id}: {path} must be a tuple, not {value!r}"
                )
            args = typing.get_args(tp)
            if len(args) == 2 and args[1] is Ellipsis:
                return tuple(
                    self.convert(v, args[0], f"{path}[{i}]")
                    for i, v in enumerate(value)
                )
            if len(args) != len(value):
                raise GeneratorError(f"{self.spec.id}: {path} needs {len(args)} items")
            return tuple(
                self.convert(v, a, f"{path}[{i}]")
                for i, (v, a) in enumerate(zip(value, args))
            )
        if tp is self.sw.model.RegEntry:
            if isinstance(value, tp):
                return value
            if not isinstance(value, str):
                raise GeneratorError(f"{self.spec.id}: {path} must name a register")
            return self.registers.entry(value)
        if isinstance(tp, type) and issubclass(tp, enum.Enum):
            if isinstance(value, tp):
                return value
            try:
                return tp(value)
            except ValueError:
                raise GeneratorError(
                    f"{self.spec.id}: {path}: {value!r} is not a {tp.__name__}"
                ) from None
        if isinstance(tp, type) and dataclasses.is_dataclass(tp):
            if isinstance(value, tp):
                return value
            fields = dataclasses.fields(tp)
            if isinstance(value, dict):
                names = {f.name for f in fields}
                if set(value) != names:
                    raise GeneratorError(
                        f"{self.spec.id}: {path} needs keys {sorted(names)}, got {sorted(value)}"
                    )
                return tp(
                    **{
                        f.name: self.convert(value[f.name], f.type, f"{path}.{f.name}")
                        for f in fields
                    }
                )
            if isinstance(value, (tuple, list)) and len(value) == len(fields):
                return tp(
                    *[
                        self.convert(v, f.type, f"{path}.{f.name}")
                        for v, f in zip(value, fields)
                    ]
                )
            raise GeneratorError(
                f"{self.spec.id}: {path} must be a dict or tuple for {tp.__name__}"
            )
        if tp is int and (isinstance(value, bool) or not isinstance(value, int)):
            raise GeneratorError(
                f"{self.spec.id}: {path} must be an int, not {value!r}"
            )
        if tp in (str, bool) and not isinstance(value, tp):
            raise GeneratorError(
                f"{self.spec.id}: {path} must be a {tp.__name__}, not {value!r}"
            )
        return value

    def build(
        self,
        cls: type,
        prefix: str,
        cells: typing.Dict[str, Cell],
        used: typing.Set[str],
    ) -> typing.Any:
        kwargs = {}
        for f in dataclasses.fields(cls):
            path = prefix + f.name
            if path in cells:
                used.add(path)
                kwargs[f.name] = self.convert(cells[path].value, f.type, path)
                continue
            inner, _ = _unwrap_optional(f.type)
            if (
                isinstance(inner, type)
                and dataclasses.is_dataclass(inner)
                and any(k.startswith(path + ".") for k in cells)
            ):
                kwargs[f.name] = self.build(inner, path + ".", cells, used)
                continue
            raise GeneratorError(
                f"{self.spec.id}: the overlay gives no value for {path}"
            )
        return cls(**kwargs)


def build_preservation(
    sw: stub_loader.Smallworld, registers: Registers, cells: typing.Dict[str, Cell]
) -> typing.Any:
    """The partition: callee-saved (generated), neither (curated),
    caller-saved (R-COMPLEMENT), with roles by R-ROLE-FILTER."""
    spec = registers.spec
    rf = registers.file

    def root(path: str) -> typing.Optional[str]:
        cell = cells.get(path)
        return (
            registers.root_of(cell.value)
            if cell and isinstance(cell.value, str)
            else None
        )

    special = {
        "stack-pointer": root("special.stack_pointer"),
        "frame-pointer": root("special.frame_pointer"),
        "tls": root("special.tls.register"),
    }

    def roles_for(name: str, kind: str) -> typing.Set[str]:
        r = registers.root_of(name)
        roles = set(rf.roles.get(r, ()))
        if kind == "callee":
            roles |= set(rf.callee_roles.get(r, ()))
        roles |= {role for role, special_root in special.items() if special_root == r}
        if kind == "callee":
            klass = rf.classes.get(r)
            if klass == "int" and not roles & _NON_VALUE_ROLES:
                roles.add("value")
            elif klass in ("fp", "vector") and not roles:
                roles.add("fp-value")
        return roles

    placed: typing.Dict[str, typing.List[typing.Tuple[str, typing.Any]]] = {}
    lists: typing.Dict[str, typing.List[typing.Any]] = {"callee": [], "neither": []}
    for kind, path in (
        ("callee", "preservation.callee_saved"),
        ("neither", "preservation.neither"),
    ):
        for text in cells[path].value:
            name, byte_range, mask = registers.parse_span(text)
            entry = registers.entry(name, roles_for(name, kind), byte_range, mask)
            if entry.root not in registers.universe:
                raise GeneratorError(
                    f"{spec.id}: {path} names {text!r}, outside the register universe"
                )
            lists[kind].append(entry)
            placed.setdefault(entry.root, []).append((kind, entry))

    caller = []
    for r in registers.universe:
        entries = [e for _, e in placed.get(r, [])]
        if any(e.preserved_mask is not None for e in entries):
            defined = rf.defined_masks.get(r)
            if defined is None:
                raise GeneratorError(
                    f"{spec.id}: {r} is split by bits but has no defined mask"
                )
            covered = 0
            for e in entries:
                covered |= e.preserved_mask or 0
            rest = defined & ~covered
            if rest:
                caller.append(registers.entry(r, roles_for(r, "caller"), None, rest))
            # Every bit of a bit-split root belongs to exactly one class: the
            # undefined (reserved) bits are neither.
            width = rf.unmodeled.get(r) or registers.platdef.registers[r].size
            reserved = ((1 << (8 * width)) - 1) & ~defined & ~covered
            if reserved:
                lists["neither"].append(registers.entry(r, (), None, reserved))
            continue
        width = rf.unmodeled.get(r) or registers.platdef.registers[r].size
        ranges = sorted((e.offset, e.end) for e in entries)
        cursor = 0
        gaps = []
        for lo, hi in ranges:
            if lo > cursor:
                gaps.append((cursor, lo))
            cursor = max(cursor, hi)
        if cursor < width:
            gaps.append((cursor, width))
        for lo, hi in gaps:
            byte_range = None if (lo, hi) == (0, width) else (lo, hi)
            caller.append(registers.entry(r, roles_for(r, "caller"), byte_range))

    def ordered(entries: typing.List[typing.Any]) -> typing.Tuple[typing.Any, ...]:
        index = {r: i for i, r in enumerate(registers.universe)}
        return tuple(sorted(entries, key=lambda e: (index[e.root], e.offset)))

    return sw.model.Preservation(
        callee_saved=ordered(lists["callee"]),
        caller_saved=ordered(caller),
        neither=ordered(lists["neither"]),
        universe=registers.universe,
    )


def _parent_is_none(path: str, hand: typing.Mapping[str, typing.Any]) -> bool:
    parts = path.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[:i])
        if parent in hand and hand[parent].value is None:
            return True
    return False


def assemble(
    spec: RecordSpec, snapshot: Json, sw: stub_loader.Smallworld, problems: Problems
) -> typing.Tuple[typing.Any, typing.Dict[str, Cell], typing.List[str]]:
    """One record, its cells, and the deviations applied in this build."""
    registers = Registers(sw, spec, problems)
    versions_now = snapshot["versions"]
    ghidra_entry = snapshot["ghidra"]["prototypes"][spec.ghidra.key]
    angr_entry = snapshot["angr"]["conventions"][spec.angr.key]
    names = GhidraNames(
        sw, registers, snapshot["ghidra"]["languages"][spec.ghidra.language]
    )
    tls_hand = spec.hand.get("special.tls.register")
    thread_pointer = (
        registers.root_of(tls_hand.value) if tls_hand and tls_hand.value else None
    )

    tags = {
        "ghidra": f"gen:ghidra:{spec.ghidra.key}",
        "angr": f"gen:angr:{angr_entry['default_cc']['class']}",
        "archinfo": f"gen:archinfo:{spec.angr.arch}",
    }
    generated: typing.Dict[str, typing.Tuple[str, typing.Any, typing.Set[str]]] = {}
    for dependency, values in (
        ("ghidra", ghidra_values(spec, ghidra_entry, names, thread_pointer, registers)),
        ("angr", angr_values(spec, angr_entry, registers)),
        ("archinfo", archinfo_values(spec, angr_entry)),
    ):
        for path, (value, applied_rules) in values.items():
            if authority.GENERATED.get(path) == dependency:
                generated[path] = (dependency, _freeze(value), applied_rules)

    cells: typing.Dict[str, Cell] = {}
    for path, hand in spec.hand.items():
        if path in authority.GENERATED or path in authority.DERIVED:
            problems.add(
                f"{spec.id}: {path} is generated; override it with a Deviation, not a Hand"
            )
            continue
        confidence, cite_problems = effective_confidence(hand.confidence, hand.cite)
        problems.extend(f"{spec.id}: {path}: {p}" for p in cite_problems)
        for cite in hand.cite:
            check_cite(cite, f"{spec.id}: {path}", snapshot, problems)
        cells[path] = Cell(
            value=_freeze(hand.value),
            tag=f"hand:{spec.id}",
            confidence=confidence,
            cite=tuple(c.text() for c in hand.cite),
        )

    by_field: typing.Dict[str, typing.List[Deviation]] = {}
    for deviation in spec.deviations:
        check_deviation(deviation, spec, snapshot, problems)
        by_field.setdefault(deviation.field, []).append(deviation)
    applied: typing.List[str] = []
    for path, dependency in authority.GENERATED.items():
        if _parent_is_none(path, spec.hand):
            if path in generated and generated[path][1] not in ((), None):
                problems.add(
                    f"{spec.id}: the overlay says {path.rsplit('.', 1)[0]} is None, but {dependency} gives {generated[path][1]!r}"
                )
            continue
        deviations = by_field.pop(path, [])
        if len(deviations) > 1:
            problems.add(
                f"{spec.id}: {path} has {len(deviations)} deviations; exactly one may apply"
            )
            continue
        if path not in generated:
            problems.add(
                f"{spec.id}: {dependency} gives no value for {path} (join or dump it, or add a Deviation)"
            )
            continue
        _, value, applied_rules = generated[path]
        unknown = sorted(r for r in applied_rules if r not in rules.BY_ID)
        if unknown:
            problems.add(f"{spec.id}: {path} uses undefined rules {unknown}")
        version = versions_now["ghidra" if dependency == "ghidra" else dependency]
        cell = Cell(
            value=value, tag=tags[dependency], rules=tuple(sorted(applied_rules))
        )
        if deviations:
            deviation = deviations[0]
            abi_value = _freeze(deviation.abi_value)
            cell.deviations = (deviation.id,)
            cell.confidence, _ = effective_confidence(
                deviation.confidence, deviation.cite
            )
            cell.cite = tuple(c.text() for c in deviation.cite)
            if version in deviation.observed:
                observed = _freeze(deviation.observed[version])
                if value != observed:
                    problems.add(
                        f"stale deviation {deviation.id} ({spec.id}: {path}): the overlay says "
                        f"{dependency} {version} gives {observed!r}, but it gives {value!r}; "
                        "update or drop the deviation"
                    )
                    continue
                cell.value = abi_value
                applied.append(deviation.id)
            elif value != abi_value:
                problems.add(
                    f"unexplained difference ({spec.id}: {path}): {dependency} {version} gives "
                    f"{value!r}, the deviation {deviation.id} gives {abi_value!r} and does not "
                    f"list {dependency} {version} in observed"
                )
                continue
        cells[path] = cell
    for path, deviations in by_field.items():
        for deviation in deviations:
            problems.add(
                f"deviation {deviation.id}: {path} is not generated for {spec.id}"
            )
    check_expectations(spec, cells, snapshot, problems)

    # identity and sources come from the spec and its joins
    keying = tuple(
        sw.model.GhidraKeying(
            deviation_id=d.id,
            field=d.field,
            # Every observed version, so the value does not depend on which
            # dependency set built the tables.
            ghidra_value=json.dumps(
                {v: _freeze(d.observed[v]) for v in sorted(d.observed)},
                sort_keys=True,
            ),
            abi_value=json.dumps(_freeze(d.abi_value)),
            versions=d.versions,
        )
        for d in spec.deviations
        if d.keying
    )
    sources = sw.model.Sources(
        ghidra_language=spec.ghidra.language,
        ghidra_compiler=spec.ghidra.compiler,
        ghidra_prototype=spec.ghidra.prototype,
        ghidra_join_klass=None,
        ghidra_keying=keying,
        angr_simcc=f"angr.calling_conventions.{angr_entry['default_cc']['class']}",
        archinfo=f"archinfo.{spec.angr.arch}",
    )
    for path, value in (
        ("id", spec.id),
        ("platform", registers.platform),
        ("variant", spec.variant),
        ("sources", sources),
    ):
        cells[path] = Cell(value=value, tag="derived:joins")
    expected_id = f"{spec.architecture}/{spec.byteorder}:{spec.variant}"
    if spec.id != expected_id:
        problems.add(f"{spec.id}: the id should be {expected_id!r}")

    for path in ("preservation.callee_saved", "preservation.neither"):
        if path not in cells:
            problems.add(f"{spec.id}: no value for {path}")
    if problems:
        return None, cells, applied
    preservation = build_preservation(sw, registers, cells)
    cells["preservation.caller_saved"] = Cell(
        value=tuple(f"{e.name}[{e.offset}:{e.end}]" for e in preservation.caller_saved),
        tag="derived:R-COMPLEMENT",
        rules=("R-COMPLEMENT", "R-ROLE-FILTER"),
    )
    cells["preservation.universe"] = Cell(
        value=preservation.universe, tag="derived:R-COMPLEMENT"
    )
    # A record is only as verified as its least verified entry: its
    # confidence is the minimum of its curated confidence and every entry's
    # (so a master-seed marker anywhere caps it at medium).
    if "confidence" in cells and cells["confidence"].value not in CONFIDENCE_ORDER:
        problems.add(
            f"{spec.id}: confidence {cells['confidence'].value!r} is not one of "
            f"{', '.join(CONFIDENCE_ORDER)}"
        )
        return None, cells, applied
    if "confidence" in cells:
        rank = {name: i for i, name in enumerate(CONFIDENCE_ORDER)}
        lowest = min(
            (c.confidence for k, c in cells.items() if k != "confidence"),
            key=rank.__getitem__,
            default="high",
        )
        claimed = cells["confidence"]
        if rank[lowest] < rank.get(claimed.value, len(rank)):
            claimed.value = lowest
            claimed.rules = ("R-CONFIDENCE-MIN",)
        claimed.confidence = claimed.value
    work = {k: v for k, v in cells.items() if not k.startswith("preservation.")}
    work["preservation"] = Cell(value=preservation, tag="derived")

    builder = Builder(sw, registers, spec)
    used: typing.Set[str] = set()
    record = builder.build(sw.model.ABIDef, "", work, used)
    for path in sorted(set(work) - used):
        problems.add(
            f"{spec.id}: the overlay gives {path}, which is not a field of the schema"
        )
    return record, cells, applied


# ---------------------------------------------------------------------------
# Oracles
# ---------------------------------------------------------------------------


def oracle_residuals(
    spec: RecordSpec,
    record: typing.Any,
    snapshot: Json,
    names: GhidraNames,
    problems: Problems,
    silent: typing.List[Json],
) -> typing.List[Json]:
    """Disagreements between the oracles and the final record. A probe that
    gave no answer is a problem; any other oracle that gave no answer (a
    ``None``) is appended to `silent`, which the caller reports."""
    out: typing.List[Json] = []
    v = snapshot["versions"]

    def compare(
        dependency: str, field: str, oracle: typing.Any, final: typing.Any
    ) -> None:
        version = v["ghidra" if dependency == "ghidra" else dependency]
        if oracle is None:
            silent.append(
                {
                    "dependency": dependency,
                    "version": version,
                    "record": spec.id,
                    "field": field,
                }
            )
            return
        oracle, final = _freeze(oracle), _freeze(final)
        if oracle != final:
            out.append(
                {
                    "dependency": dependency,
                    "version": version,
                    "record": spec.id,
                    "field": field,
                    "oracle": oracle,
                    "final": final,
                }
            )

    ghidra = snapshot["ghidra"]["prototypes"][spec.ghidra.key]
    angr = snapshot["angr"]["conventions"][spec.angr.key]
    cc = angr["default_cc"]
    rm = record.return_mechanics

    # angr against the Ghidra-generated and curated fields
    compare(
        "angr",
        "int_args.registers",
        cc["ARG_REGS"],
        record.int_arg_registers(form="name"),
    )
    compare(
        "angr",
        "fp_args.registers",
        cc["FP_ARG_REGS"],
        record.fp_arg_registers(form="name"),
    )
    compare(
        "angr",
        "returns.int_registers",
        [r["reg"] for r in (cc["RETURN_VAL"], cc["OVERFLOW_RETURN_VAL"]) if r],
        record.int_return_registers(form="name"),
    )
    compare(
        "angr",
        "returns.fp_registers",
        [r["reg"] for r in (cc["FP_RETURN_VAL"], cc["OVERFLOW_FP_RETURN_VAL"]) if r],
        record.fp_return_registers(form="name"),
    )
    compare(
        "angr",
        "preservation.caller_saved",
        sorted(cc["CALLER_SAVED_REGS"] or []),
        sorted(record.caller_saved(klass="int", names_only=True, form="root")),
    )
    compare(
        "angr",
        "stack.first_arg_offset",
        cc["STACKARG_SP_DIFF"],
        record.stack.first_arg_offset,
    )
    compare(
        "angr", "stack.alignment", cc.get("STACK_ALIGNMENT"), record.stack.alignment
    )
    compare(
        "angr",
        "return_mechanics.callee_cleanup",
        cc.get("CALLEE_CLEANUP"),
        rm.callee_cleanup,
    )
    # What angr's calling-convention code does, asked by stage 1's probes.
    probes = angr.get("probes") or {}
    if record.sret is not None and record.sret.register is not None:
        if probes.get("sret_register") is None:
            problems.add(
                f"{spec.id}: angr's struct-return probe gave no register, so "
                "sret.register is unchecked (fix the probe, or the join)"
            )
        else:
            compare(
                "angr",
                "sret.register",
                probes["sret_register"],
                record.sret.register.name,
            )
    offsets = probes.get("stack_int_offsets") or []
    if len(offsets) < 2:
        problems.add(
            f"{spec.id}: angr's stack-argument probe gave {offsets!r}, so the "
            "stack offset and slot size are unchecked (fix the probe, or the join)"
        )
    else:
        compare(
            "angr", "stack.first_arg_offset", offsets[0], record.stack.first_arg_offset
        )
        compare(
            "angr", "stack.slot_size", offsets[1] - offsets[0], record.stack.slot_size
        )
    compare("archinfo", "stack.slot_size", angr["arch_bytes"], record.stack.slot_size)
    syscall = angr.get("syscall_cc") or {}
    if record.syscall is not None:
        sc = record.syscall
        compare(
            "angr",
            "syscall.arg_registers",
            syscall.get("ARG_REGS"),
            tuple(e.name for e in sc.arg_registers),
        )
        saved = syscall.get("CALLER_SAVED_REGS")
        compare(
            "angr",
            "syscall.clobbered",
            None if saved is None else sorted(saved),
            sorted({e.name for e in sc.clobbered} | {sc.return_register.name}),
        )

    # Ghidra against the angr-generated and curated fields
    ra = (
        ghidra["prototype"].get("returnaddress")
        or ghidra.get("returnaddress")
        or [None]
    )[0]
    on_stack = ra is not None and ra.get("kind") == "stack"
    compare(
        "ghidra",
        "return_mechanics.ra_stack_offset",
        ra.get("offset") if on_stack else None,
        rm.ra_stack_offset,
    )
    compare(
        "ghidra",
        "return_mechanics.ra_size",
        ra.get("size") if on_stack else None,
        rm.ra_size,
    )
    extrapop = ghidra["prototype"].get("extrapop")
    compare(
        "ghidra",
        "return_mechanics.callee_cleanup",
        (
            extrapop != rm.ra_size
            if isinstance(extrapop, int) and rm.ra_stack_offset is not None
            else None
        ),
        rm.callee_cleanup,
    )
    killed = [
        names(r["name"])[0]
        for r in ghidra["prototype"].get("killedbycall") or []
        if r["kind"] == "register"
    ]
    compare(
        "ghidra",
        "preservation.caller_saved",
        [n for n in killed if not record.is_caller_saved(n)],
        [],
    )
    data = ghidra["data_organization"]
    sizes = record.data_model.sizes
    for key, attr in (
        ("pointer_size", "pointer"),
        ("char_size", "char"),
        ("short_size", "short"),
        ("integer_size", "int"),
        ("long_size", "long"),
        ("long_long_size", "long_long"),
        ("float_size", "float"),
        ("double_size", "double"),
        ("long_double_size", "long_double"),
        ("wchar_size", "wchar_t"),
    ):
        compare(
            "ghidra", f"data_model.sizes.{attr}", data.get(key), getattr(sizes, attr)
        )
    compare(
        "ghidra",
        "data_model.char_signed",
        data.get("char_signed"),
        record.data_model.char_signed,
    )
    return out


def match_acks(
    specs: typing.Sequence[RecordSpec],
    residuals: typing.List[Json],
    snapshot: Json,
    problems: Problems,
) -> None:
    used: typing.Set[str] = set()
    acks = [(spec, ack) for spec in specs for ack in spec.oracle_acks]
    seen: typing.Dict[str, str] = {}
    for spec, ack in acks:
        if ack.id in seen:
            problems.add(
                f"oracle ack id {ack.id} is used by both {seen[ack.id]} and {spec.id}"
            )
        seen[ack.id] = spec.id
        if not ack.field_pattern.startswith(spec.id + ":"):
            problems.add(
                f"oracle ack {ack.id}: its field pattern {ack.field_pattern!r} "
                f"must name its own record ({spec.id}:...)"
            )
    by_record = {spec.id: spec.oracle_acks for spec in specs}
    for residual in residuals:
        key = f"{residual['record']}:{residual['field']}"
        matches = [
            ack
            for ack in by_record.get(residual["record"], ())
            if ack.dependency == residual["dependency"]
            and fnmatch.fnmatchcase(key, ack.field_pattern)
            and (ack.versions is None or residual["version"] in ack.versions)
        ]
        if not matches:
            problems.add(
                f"unacknowledged oracle disagreement: {residual['dependency']} "
                f"{residual['version']} says {key} is {residual['oracle']!r}, the "
                f"record says {residual['final']!r} (fix the record, or add an OracleAck)"
            )
        for ack in matches:
            # An ack pins what it accepts: the oracle's value and the final
            # value. A different disagreement on the same field is new.
            if (_freeze(ack.oracle), _freeze(ack.final)) != (
                residual["oracle"],
                residual["final"],
            ):
                problems.add(
                    f"oracle ack {ack.id} accepts {residual['dependency']} saying "
                    f"{ack.oracle!r} against {ack.final!r} for {key}, but now it is "
                    f"{residual['oracle']!r} against {residual['final']!r}; re-check "
                    "the disagreement and update the ack"
                )
        used.update(ack.id for ack in matches)
    for spec, ack in acks:
        _, cite_problems = effective_confidence("high", ack.cite)
        problems.extend(f"oracle ack {ack.id}: {p}" for p in cite_problems)
        for cite in ack.cite:
            check_cite(cite, f"oracle ack {ack.id}", snapshot, problems)
        current = snapshot["versions"][
            "ghidra" if ack.dependency == "ghidra" else ack.dependency
        ]
        applies = ack.versions is None or current in ack.versions
        if applies and ack.id not in used:
            problems.add(
                f"stale oracle ack {ack.id}: {ack.dependency} {current} no longer disagrees on {ack.field_pattern}"
            )


def check_silent_oracles(
    specs: typing.Sequence[RecordSpec], silent: typing.List[Json], problems: Problems
) -> None:
    """An oracle that gave no answer is a counted note, unless the field has
    an OracleAck or an Expect: then the check the overlay relies on did not
    happen, which is an error."""
    by_record = {spec.id: spec for spec in specs}
    for note in silent:
        spec = by_record[note["record"]]
        key = f"{note['record']}:{note['field']}"
        acked = [
            ack.id
            for ack in spec.oracle_acks
            if ack.dependency == note["dependency"]
            and fnmatch.fnmatchcase(key, ack.field_pattern)
            and (ack.versions is None or note["version"] in ack.versions)
        ]
        expected = [e for e in spec.expectations if e.field == note["field"]]
        if acked or expected:
            problems.add(
                f"{note['dependency']} {note['version']} gives no value for {key}, "
                f"which {', '.join(acked) or 'an Expect'} relies on being checked"
            )


# ---------------------------------------------------------------------------
# The whole build
# ---------------------------------------------------------------------------


def build(
    snapshot: Json,
    sw: stub_loader.Smallworld,
    specs: typing.Sequence[RecordSpec] = RECORDS,
    ceiling: int = MASTER_SEED_CEILING,
) -> Result:
    """Build and check every record. Raises GeneratorError listing every
    problem."""
    problems = Problems()
    if snapshot.get("schema") != 1:
        raise GeneratorError(
            "the stage-1 snapshot has an unknown schema; rerun stage 1"
        )
    records, cells, applied, residuals = [], {}, [], []
    silent: typing.List[Json] = []
    failed: typing.Set[str] = set()
    for rule in rules.RULES:
        for cite in rule.cite:
            check_cite(cite, f"rule {rule.id}", snapshot, problems)
    deviation_ids: typing.Dict[str, str] = {}
    for spec in specs:
        for deviation in spec.deviations:
            if deviation.id in deviation_ids:
                problems.add(
                    f"deviation id {deviation.id} is used by both "
                    f"{deviation_ids[deviation.id]} and {spec.id}"
                )
            deviation_ids[deviation.id] = spec.id
    features: typing.Dict[str, str] = {}
    for spec in specs:
        if not _FEATURE.match(spec.feature):
            problems.add(f"{spec.id}: feature {spec.feature!r} is not kebab-case")
        elif spec.feature in features:
            problems.add(
                f"{spec.id}: feature {spec.feature!r} is also {features[spec.feature]}'s"
            )
        features[spec.feature] = spec.id
        for cite in spec.register_file.cite:
            check_cite(
                cite, f"register file {spec.register_file.name}", snapshot, problems
            )
        # Each record gets its own Problems, so one record's failure neither
        # hides nor stops another's checks.
        record_problems = Problems()
        try:
            record, record_cells, record_applied = assemble(
                spec, snapshot, sw, record_problems
            )
        except GeneratorError as e:
            record_problems.add(str(e))
            record = None
        problems.extend(record_problems.items)
        if record is None:
            # Nothing was built, so there are no residuals, and its acks
            # would all look stale: they are not checked.
            failed.add(spec.id)
            continue
        # A record that was built is checked in full (structure, oracles,
        # acks) even when it or another record has problems, so one run
        # reports everything.
        cells.update({f"{spec.id}|{k}": v for k, v in record_cells.items()})
        applied += record_applied
        records.append(record)
        registers = Registers(sw, spec, Problems())
        names = GhidraNames(
            sw, registers, snapshot["ghidra"]["languages"][spec.ghidra.language]
        )
        residuals += oracle_residuals(spec, record, snapshot, names, problems, silent)
    problems.extend(sw.validate.check_records(records))
    built = [s for s in specs if s.id not in failed]
    match_acks(built, residuals, snapshot, problems)
    check_silent_oracles(built, silent, problems)
    seeds = master_seed_count(specs)
    if seeds > ceiling:
        problems.add(
            f"the overlay carries {seeds} master-seed markers, more than its "
            f"MASTER_SEED_CEILING of {ceiling}; cite the new values instead"
        )
    if problems:
        raise GeneratorError(
            f"{len(problems.items)} problem(s) building the ABI tables:\n  - "
            + "\n  - ".join(problems.items)
        )
    report = make_report(specs, cells, applied, residuals, seeds, ceiling, snapshot)
    report.append(f"oracle notes (an oracle gave no answer): {len(silent)}")
    report += [
        f"  note: {n['dependency']} {n['version']} gives nothing for "
        f"{n['record']}:{n['field']}"
        for n in silent
    ]
    return Result(records, cells, applied, residuals, report)


def make_report(
    specs: typing.Sequence[RecordSpec],
    cells: typing.Dict[str, Cell],
    applied: typing.List[str],
    residuals: typing.List[Json],
    seeds: int,
    ceiling: int,
    snapshot: Json,
) -> typing.List[str]:
    v = snapshot["versions"]
    lines = [
        f"dependency set: pypcode {v['pypcode']} (Ghidra {v['ghidra']}), angr {v['angr']}, archinfo {v['archinfo']}",
        f"master-seed markers: {seeds} (ceiling {ceiling})",
    ]
    for spec in specs:
        mine = {
            k.split("|", 1)[1]: c
            for k, c in cells.items()
            if k.startswith(spec.id + "|")
        }
        count: typing.Dict[str, int] = {}
        for cell in mine.values():
            kind = "deviation" if cell.deviations else cell.tag.split(":", 1)[0]
            count[kind] = count.get(kind, 0) + 1
        lines.append(
            f"{spec.id}: " + ", ".join(f"{n} {k}" for k, n in sorted(count.items()))
        )
        for path, cell in sorted(mine.items()):
            if cell.confidence != "high":
                lines.append(f"  {cell.confidence}: {path} ({'; '.join(cell.cite)})")
        for deviation in spec.deviations:
            state = (
                "applied" if deviation.id in applied else "not needed at this version"
            )
            lines.append(
                f"  deviation {deviation.id} ({deviation.klass}) on {deviation.field}: {state}"
            )
        for ack in spec.oracle_acks:
            lines.append(
                f"  oracle ack {ack.id}: {ack.dependency} on {ack.field_pattern}"
            )
    for residual in residuals:
        lines.append(
            f"  residual {residual['dependency']} {residual['record']}:{residual['field']}: "
            f"{residual['oracle']!r} vs {residual['final']!r}"
        )
    return lines


# ---------------------------------------------------------------------------
# Writing the package
# ---------------------------------------------------------------------------


def _module_name(spec: RecordSpec) -> str:
    return re.sub(r"[^a-z0-9]+", "_", spec.register_file.name.split("-")[0].lower())


def _record_name(record: typing.Any) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", record.id).upper()


def input_manifest(src_root: str) -> typing.Dict[str, str]:
    import glob

    files = set()
    for pattern in INPUT_PATTERNS:
        for path in glob.glob(os.path.join(src_root, pattern)):
            files.add(os.path.relpath(path, src_root).replace(os.sep, "/"))
    return {f: sha256_file(os.path.join(src_root, f)) for f in sorted(files)}


def package_files(
    result: Result,
    snapshot: Json,
    src_root: str,
    specs: typing.Sequence[RecordSpec] = RECORDS,
) -> typing.Dict[str, str]:
    """name -> text of every file of the generated package."""
    files: typing.Dict[str, str] = {}
    by_module: typing.Dict[str, typing.List[typing.Any]] = {}
    for spec, record in zip(specs, result.records):
        by_module.setdefault(_module_name(spec), []).append(record)
    init_imports = []
    order = []
    for module, records in sorted(by_module.items()):
        files[f"{module}.py"] = emit.module(
            f"The {module} family records.",
            [(_record_name(r), r) for r in records],
        )
        init_imports.append(
            f"from .{module} import {', '.join(_record_name(r) for r in records)}"
        )
    for record in result.records:
        order.append(_record_name(record))
    records_tuple = (
        "(\n" + "".join(f"    {n},\n" for n in order) + ")"
        if len(order) != 1
        else f"({order[0]},)"
    )
    features = tuple(sorted(spec.feature for spec in specs))
    features_text = emit.Emitter().value(features, 0, "features", len("FEATURES = "))
    files["__init__.py"] = (
        emit.header(
            "The ABI record tables: RECORDS is what smallworld.platforms.abi "
            "loads, and FEATURES what its table_features() reports (one name "
            "per record; see tools/abi/overlay/__init__.py)."
        )
        + "\n"
        + "\n".join(init_imports)
        + "\n\nAVAILABLE = True\nREASON = None\n"
        + f"FEATURES = {features_text}\n"
        + f"RECORDS = {records_tuple}\n"
    )
    cells = {
        key: (cell.tag, cell.rules, cell.deviations, cell.confidence, cell.cite)
        for key, cell in sorted(result.cells.items())
        if key.split("|", 1)[1] not in ("platform", "sources")
    }
    files["_provenance.py"] = emit.module(
        "Provenance of every field: (tag, rules, deviations, confidence, citations), "
        "keyed by 'record id|field'. Identical for every supported dependency set.",
        [
            ("SCHEMA", emit.SCHEMA),
            ("GENERATOR", emit.GENERATOR_VERSION),
            ("MASTER_SEED_COUNT", master_seed_count(specs)),
            ("MASTER_SEED_CEILING", MASTER_SEED_CEILING),
            ("RULES", {r.id: r.summary for r in rules.RULES}),
            ("INPUTS", input_manifest(src_root)),
            ("CELLS", cells),
        ],
    )
    v = snapshot["versions"]
    files["_build_info.py"] = emit.module(
        "Which dependency set built these tables (the only file that differs "
        "between supported sets).",
        [
            ("PYTHON", ".".join(str(n) for n in sys.version_info[:2])),
            ("VERSIONS", dict(v)),
            (
                "CSPECS",
                {k: c["sha256"] for k, c in snapshot["ghidra"]["cspecs"].items()},
            ),
            ("DEVIATIONS_APPLIED", tuple(sorted(result.applied))),
        ],
    )
    for name, text in files.items():
        compile(text, name, "exec")
    return files


def records_fingerprint(records: typing.Iterable[typing.Any]) -> str:
    return json.dumps(emit.fingerprint(tuple(records)), sort_keys=True)


def write_package(out_dir: str, files: typing.Dict[str, str]) -> None:
    os.makedirs(out_dir, exist_ok=True)
    for name, text in sorted(files.items()):
        with open(
            os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n"
        ) as fh:
            fh.write(text)


def verify_written(out_dir: str, src_root: str, expected: str) -> None:
    """Import the written package in a fresh interpreter, check its records,
    and compare them with the ones built here."""
    proc = subprocess.run(
        [
            sys.executable,
            "-B",
            os.path.abspath(__file__),
            "--verify",
            out_dir,
            "--src",
            src_root,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if proc.returncode != 0:
        raise GeneratorError(
            f"the written tables do not import cleanly:\n{proc.stderr.strip()}"
        )
    if proc.stdout.strip() != expected:
        raise GeneratorError(
            "the written tables do not reproduce the records built in memory"
        )


def verify_main(directory: str, src_root: str) -> int:
    stub_loader.install_blocker()
    sw = stub_loader.load(src_root)
    data = stub_loader.mount_data_package(stub_loader.STUB, directory)
    problems = sw.validate.check_records(data.RECORDS)
    if data.AVAILABLE is not True:
        fail(f"the generated tables say AVAILABLE = {data.AVAILABLE!r}, not True")
    if problems:
        fail("the generated tables are invalid:\n  - " + "\n  - ".join(problems))
    leaked = stub_loader.blocked_modules()
    if leaked:
        fail(f"loading the generated tables imported {leaked}")
    print(records_fingerprint(data.RECORDS))
    return 0


def main(argv: typing.Optional[typing.List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", help="the stage-1 snapshot JSON")
    parser.add_argument(
        "--src", required=True, help="source tree root (contains smallworld/)"
    )
    parser.add_argument("--out-dir", help="write the _data package here")
    parser.add_argument(
        "--report", action="store_true", help="print the provenance report"
    )
    parser.add_argument("--verify", metavar="DIR", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.verify:
        return verify_main(args.verify, args.src)
    if not args.snapshot:
        parser.error("--snapshot is required")
    stub_loader.install_blocker()
    try:
        sw = stub_loader.load(args.src)
    except Exception as e:
        fail(
            f"cannot load smallworld/platforms from {args.src} without importing smallworld: {type(e).__name__}: {e}"
        )
    with open(args.snapshot, encoding="utf-8") as fh:
        snapshot = json.load(fh)
    try:
        result = build(snapshot, sw)
        if args.report:
            print("\n".join(result.report))
        if args.out_dir:
            files = package_files(result, snapshot, args.src)
            write_package(args.out_dir, files)
            verify_written(args.out_dir, args.src, records_fingerprint(result.records))
    except GeneratorError as e:
        fail(str(e))
    leaked = stub_loader.blocked_modules()
    if leaked:
        fail(f"stage 2 imported blocked modules: {leaked}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
