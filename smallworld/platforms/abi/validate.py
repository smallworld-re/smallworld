"""Structural checks for ABI records.

:func:`check_record` and :func:`check_records` return a tuple of problem
descriptions (empty when the records are well formed) rather than raising, so
a test or the table generator can report every problem at once. They check
the invariants the query API relies on: deep immutability, sorted roles,
consistent partial flags, a preservation partition in register-file order
that is disjoint and complete by byte (and, for bit-split registers, by
bit), register names, psABI spellings and widths that match the live
:class:`~smallworld.platforms.defs.PlatformDef`, a ``first_arg_offset`` that
covers the return address and reserved areas, and registry-level uniqueness
of ids, keys and defaults.
"""

import dataclasses
import enum
import typing

from ..defs.platformdef import PlatformDef
from ..platforms import ABI, Platform
from .enums import ReturnKind, Role
from .model import ABIDef, RegEntry, _platformdef_spans

_SCALARS = (str, int, bool, type(None), enum.Enum, Platform)


def _walk(
    value: typing.Any, path: str
) -> typing.Iterator[typing.Tuple[str, typing.Any]]:
    """Yield ``(path, value)`` for `value` and everything inside it."""
    yield path, value
    if isinstance(value, tuple):
        for i, item in enumerate(value):
            yield from _walk(item, f"{path}[{i}]")
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        for field in dataclasses.fields(value):
            yield from _walk(getattr(value, field.name), f"{path}.{field.name}")


def _enum_problems(hint: typing.Any, item: typing.Any, path: str) -> typing.List[str]:
    """Problems with `item` against annotation `hint`: every enum the hint
    requires, directly, as Optional, or inside a tuple, must be a member."""
    if item is None:
        return []
    origin = typing.get_origin(hint)
    args = typing.get_args(hint)
    if origin is typing.Union:
        options = [a for a in args if a is not type(None)]
        return _enum_problems(options[0], item, path) if len(options) == 1 else []
    if isinstance(hint, type) and issubclass(hint, enum.Enum):
        if not isinstance(item, hint):
            return [f"{path}: {item!r} is not a {hint.__name__}"]
        return []
    if origin is tuple and isinstance(item, tuple):
        if len(args) == 2 and args[1] is Ellipsis:
            element_hints = [args[0]] * len(item)
        elif len(args) == len(item):
            element_hints = list(args)
        else:
            return []
        problems = []
        for i, (element_hint, element) in enumerate(zip(element_hints, item)):
            problems.extend(_enum_problems(element_hint, element, f"{path}[{i}]"))
        return problems
    return []


def _check_enum_fields(value: typing.Any, path: str) -> typing.List[str]:
    """Enum-typed fields, and enums inside tuple fields, must hold members,
    not their string values (the schema enums are ``str`` subclasses, so a
    string would compare equal)."""
    problems = []
    hints = typing.get_type_hints(type(value))
    for field in dataclasses.fields(value):
        problems.extend(
            _enum_problems(
                hints.get(field.name),
                getattr(value, field.name),
                f"{path}.{field.name}",
            )
        )
    return problems


def _check_entry(entry: RegEntry, path: str) -> typing.List[str]:
    problems = []
    if not all(isinstance(r, Role) for r in entry.roles):
        problems.append(f"{path}: roles must be Role members")
    else:
        order = list(Role)
        if list(entry.roles) != sorted(set(entry.roles), key=order.index):
            problems.append(f"{path}: roles must be sorted and unique")
    if entry.offset < 0 or entry.abi_width <= 0:
        problems.append(f"{path}: bad byte range [{entry.offset}, {entry.end})")
    if entry.unmodeled:
        if entry.width != 0 or entry.root_width != 0 or entry.root != entry.name:
            problems.append(
                f"{path}: unmodeled entries have width 0, root_width 0, root == name"
            )
    else:
        if entry.end > entry.root_width:
            problems.append(f"{path}: byte range exceeds root_width {entry.root_width}")
        partial = not (entry.offset == 0 and entry.abi_width == entry.root_width)
        if entry.partial != partial:
            problems.append(f"{path}: partial should be {partial}")
    if entry.preserved_mask is not None and not (
        0 < entry.preserved_mask < 1 << (8 * entry.abi_width)
    ):
        problems.append(
            f"{path}: preserved_mask must be None or a positive mask of the "
            f"entry's {entry.abi_width} bytes"
        )
    return problems


def _check_partition(record: ABIDef) -> typing.List[str]:
    problems: typing.List[str] = []
    p = record.preservation
    if len(set(p.universe)) != len(p.universe):
        problems.append("preservation.universe: duplicate roots")
    order = {root: i for i, root in enumerate(p.universe)}
    by_root: typing.Dict[str, typing.List[typing.Tuple[str, RegEntry]]] = {}
    for kind in ("callee_saved", "caller_saved", "neither"):
        entries = getattr(p, kind)
        keys = []
        for i, entry in enumerate(entries):
            path = f"preservation.{kind}[{i}] ({entry.name})"
            if entry.root not in order:
                problems.append(f"{path}: root {entry.root!r} is not in the universe")
                continue
            keys.append((order[entry.root], entry.offset))
            by_root.setdefault(entry.root, []).append((kind, entry))
        if keys != sorted(keys):
            problems.append(f"preservation.{kind}: not in register-file order")
    for root in p.universe:
        entries = by_root.get(root, [])
        if not entries:
            problems.append(f"preservation: universe root {root!r} has no entries")
            continue
        # Bit-split registers: every masked entry of a root covers the same
        # bytes, and their masks (bits of that value, whatever the byte
        # order) split it with no bit left over.
        masked = [
            (k, e, e.preserved_mask) for k, e in entries if e.preserved_mask is not None
        ]
        spans = [(k, e) for k, e in entries if e.preserved_mask is None]
        if masked:
            ranges = {(e.offset, e.abi_width) for _, e, _ in masked}
            if len(ranges) > 1:
                problems.append(
                    f"preservation: masked entries of {root} must share offset "
                    "and abi_width"
                )
                continue
            covered_bits = 0
            for i, (kind_a, a, mask_a) in enumerate(masked):
                for kind_b, b, mask_b in masked[i + 1 :]:
                    if mask_a & mask_b:
                        problems.append(
                            f"preservation: {kind_a} {a.name} and {kind_b} "
                            f"{b.name} overlap on {root}"
                        )
                covered_bits |= mask_a
            abi_width = masked[0][1].abi_width
            missing = ((1 << (8 * abi_width)) - 1) & ~covered_bits
            if missing:
                problems.append(
                    f"preservation: {root} bits {missing:#x} are in no class"
                )
            # For the byte checks, the masked entries are one span.
            spans.append(("masked", masked[0][1]))
        for i, (kind_a, a) in enumerate(spans):
            for kind_b, b in spans[i + 1 :]:
                if a.offset < b.end and b.offset < a.end:
                    problems.append(
                        f"preservation: {kind_a} {a.name} and {kind_b} {b.name} "
                        f"overlap on {root}"
                    )
        width = max(e.root_width for _, e in entries) or max(e.end for _, e in entries)
        # Completeness: the byte ranges tile the root.
        covered = 0
        gap: typing.Optional[typing.Tuple[int, int]] = None
        for _, e in sorted(spans, key=lambda ke: ke[1].offset):
            if e.offset > covered:
                gap = (covered, e.offset)
                break
            covered = max(covered, e.end)
        if gap is None and covered < width:
            gap = (covered, width)
        if gap is not None:
            problems.append(
                f"preservation: {root} bytes [{gap[0]}, {gap[1]}) are in no class"
            )
    return problems


def _check_platformdef(record: ABIDef) -> typing.List[str]:
    try:
        platdef = PlatformDef.for_platform(record.platform)
    except ValueError:
        return [f"no PlatformDef for {record.platform}"]
    problems = []
    spans = _platformdef_spans(platdef)
    folded: typing.Dict[str, typing.Tuple[str, typing.Tuple[str, int, int]]] = {}
    for name, span in spans.items():
        folded.setdefault(name.casefold(), (name, span))
    for path, value in _walk(record, "record"):
        if not isinstance(value, RegEntry):
            continue
        # The query predicates look a spelling up in the PlatformDef first
        # (ignoring case), so a psABI name or alias that is a PlatformDef
        # register must name exactly this entry's bytes, or the predicates
        # would answer for other bytes (W16 on x16 is the 4-byte w16).
        entry_span = (value.root, value.offset, value.end)
        for label, spelling in [("abi_name", value.abi_name)] + [
            ("abi alias", alias) for alias in value.abi_aliases
        ]:
            match = folded.get(spelling.casefold())
            if match is not None and match[1] != entry_span:
                pd_name, (pd_root, pd_lo, pd_hi) = match
                problems.append(
                    f"{path}: {label} {spelling!r} is the PlatformDef's "
                    f"{pd_name} ({pd_root} bytes [{pd_lo}, {pd_hi})), not "
                    f"{value.root} bytes [{value.offset}, {value.end})"
                )
        named = spans.get(value.name)
        if value.unmodeled:
            if named is not None:
                problems.append(f"{path}: {value.name} is modeled by the PlatformDef")
            continue
        if named is None:
            problems.append(f"{path}: {value.name} is not a PlatformDef register")
            continue
        root, offset, end = named
        size = end - offset
        if root != value.root:
            problems.append(f"{path}: root of {value.name} is {root}, not {value.root}")
        if size != value.width:
            problems.append(f"{path}: {value.name} is {size} bytes, not {value.width}")
        root_size = platdef.registers[root].size
        if root_size != value.root_width:
            problems.append(
                f"{path}: {root} is {root_size} bytes, not {value.root_width}"
            )
        if not (offset <= value.offset and value.end <= offset + size):
            problems.append(f"{path}: ABI bytes fall outside {value.name}")
    names = list(platdef.registers)
    universe = record.preservation.universe
    modeled = [r for r in universe if r in platdef.registers]
    if modeled != list(universe[: len(modeled)]):
        problems.append("preservation.universe: unmodeled roots must come last")
    if modeled != sorted(modeled, key=names.index):
        problems.append("preservation.universe: not in PlatformDef register order")
    for name in record.returns.pointer_mirror:
        if name not in spans:
            problems.append(
                f"returns.pointer_mirror: {name} is not a PlatformDef register"
            )
    sp = spans.get(platdef.sp_register)
    if sp is not None and sp[0] != record.stack_pointer:
        problems.append(
            f"special.stack_pointer: {record.stack_pointer} is not the parent of "
            f"{platdef.sp_register}"
        )
    return problems


def check_record(record: ABIDef) -> typing.Tuple[str, ...]:
    """Every structural problem with `record`; ``()`` if there is none."""
    problems: typing.List[str] = []
    expected_id = (
        f"{record.platform.architecture.name}/{record.platform.byteorder.name}"
        f":{record.variant}"
    )
    if record.id != expected_id:
        problems.append(f"id should be {expected_id!r}")
    for path, value in _walk(record, "record"):
        if not (
            isinstance(value, (tuple,) + _SCALARS)
            or (dataclasses.is_dataclass(value) and not isinstance(value, type))
        ):
            problems.append(f"{path}: {type(value).__name__} is not immutable")
        elif dataclasses.is_dataclass(value) and not isinstance(value, Platform):
            params = getattr(type(value), "__dataclass_params__")
            if not params.frozen:
                problems.append(f"{path}: {type(value).__name__} is not frozen")
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            problems.extend(_check_enum_fields(value, path))
        if isinstance(value, RegEntry):
            problems.extend(_check_entry(value, path))
    problems.extend(_check_partition(record))
    problems.extend(_check_platformdef(record))
    # A spelling the record itself resolves (ignoring case) must name one
    # root.
    roots_by_spelling: typing.Dict[str, str] = {}
    collisions: typing.Dict[typing.Tuple[str, str, str], str] = {}
    for _, entry in record._partition():
        for spelling in dict.fromkeys((entry.abi_name, *entry.abi_aliases, entry.name)):
            key = spelling.casefold()
            root = roots_by_spelling.setdefault(key, entry.root)
            if root != entry.root:
                collisions.setdefault((key, root, entry.root), spelling)
    for (_, first, second), spelling in collisions.items():
        problems.append(f"{spelling!r} names both {first} and {second}")
    if record.returns.pointer_mirror and not record.returns.pointer_registers:
        problems.append(
            "returns.pointer_mirror is set, but there is no primary pointer "
            "return in returns.pointer_registers"
        )
    for name in record.callee_saved_values():
        if not record.is_callee_saved_value(name):
            problems.append(
                f"{name} is in callee_saved_values() but not wholly a "
                "callee-saved value"
            )
    # Arguments and results are clobbered by the call; the stack pointer is
    # preserved.
    for name in record.int_arg_registers() + record.fp_arg_registers(form="root"):
        if record.preservation_of(name) is not None and not record.is_caller_saved(
            name
        ):
            problems.append(f"argument register {name} is not caller-saved")
    for name in record.int_return_registers() + record.fp_return_registers(form="root"):
        if record.preservation_of(name) is not None and not record.is_caller_saved(
            name
        ):
            problems.append(f"return register {name} is not caller-saved")
    if not record.is_callee_saved(record.stack_pointer):
        problems.append(f"stack pointer {record.stack_pointer} is not callee-saved")
    if record.is_family_default and record.abi is None:
        problems.append("a family default must have an ABI family")
    # The first stack argument lies beyond everything the caller put between
    # it and the entry sp.
    stack = record.stack
    pushed_ra = (
        record.return_mechanics.ra_size
        if record.return_mechanics.kind is ReturnKind.POP_RET
        else 0
    )
    below_first_arg = (
        pushed_ra + stack.shadow_space + stack.linkage_area + stack.param_save_area
    )
    if stack.first_arg_offset < below_first_arg:
        problems.append(
            f"stack.first_arg_offset {stack.first_arg_offset} is less than the "
            f"{below_first_arg} bytes of return address, shadow space, linkage "
            "area and parameter save area below the first stack argument"
        )
    return tuple(f"{record.id}: {p}" for p in problems)


def check_records(records: typing.Iterable[ABIDef]) -> typing.Tuple[str, ...]:
    """Every problem with `records` as a registry record set.

    Besides :func:`check_record` on each record: ids and keys are unique;
    each platform has at most one default and at most one default per ABI
    family; every platform default belongs to the SYSTEMV family and is its
    family default; and every SYSTEMV family default is its platform's
    default. So ``resolve(platform)`` and ``resolve(platform, ABI.SYSTEMV)``
    return the same record.
    """
    from .registry import _Registry

    records = tuple(records)
    problems: typing.List[str] = []
    for record in records:
        problems.extend(check_record(record))
    try:
        registry = _Registry(records, "check_records()")
    except (TypeError, ValueError) as e:
        problems.append(str(e))
        return tuple(problems)
    # resolve(platform) with no family and no variant means the platform's
    # SYSTEMV family default, so every platform default must be exactly that.
    for platform, default in registry.default.items():
        if default.abi is not ABI.SYSTEMV or not default.is_family_default:
            problems.append(
                f"{default.id}: a platform default must be the SYSTEMV family "
                "default"
            )
    for (platform, family), record in registry.family_default.items():
        if family is ABI.SYSTEMV and registry.default.get(platform) is not record:
            problems.append(
                f"{record.id}: the SYSTEMV family default must be the platform "
                "default"
            )
    return tuple(problems)


__all__ = ["check_record", "check_records"]
