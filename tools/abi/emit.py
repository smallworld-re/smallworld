"""Deterministic emitter for the generated ``_data`` package.

It writes black-style Python: one constructor keyword per line, trailing
commas, double quotes, enums as ``Type.NAME``, masks in hex. The same records
always give the same bytes, on every supported Python (it never formats an
enum through ``str()``/f-strings, whose output changed in 3.11), so the
tables built from different dependency sets can be compared byte for byte.

Records are written through the schema's own constructors, walked
generically: any frozen dataclass of the schema emits as a keyword call.
Repeated :class:`RegEntry` values are hoisted into module-level constants.
"""

import dataclasses
import enum
import json
import re
import textwrap
import typing

SCHEMA = "smallworld-abi/1"
GENERATOR_VERSION = "1"

HEADER = '''"""GENERATED ABI tables ({schema}, generator {generator}). Do not edit, do not commit.

{what}

Written at build time by tools/abi from the Ghidra compiler specifications
bundled in pypcode, from angr and archinfo, and from the overlay in
tools/abi/overlay. The tables are derived from, and modify, Ghidra (Apache
License 2.0), angr and archinfo (BSD 2-Clause): see NOTICE and LICENSES/ in
smallworld/platforms/abi.
"""
'''

#: Where the generated modules import each schema module from (they live in
#: ``smallworld/platforms/abi/_data``).
_RELATIVE_MODULES = (
    (".platforms.abi.model", "..model"),
    (".platforms.abi.enums", "..enums"),
    (".platforms.platforms", "...platforms"),
)

_LINE = 88


def header(what: str) -> str:
    return HEADER.format(
        schema=SCHEMA, generator=GENERATOR_VERSION, what=textwrap.fill(what, 76)
    )


def _is_record(value: typing.Any) -> bool:
    return dataclasses.is_dataclass(value) and not isinstance(value, type)


def _string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


class Emitter:
    """Renders schema values; remembers the imports and hoisted constants
    they need."""

    def __init__(self, hoist: typing.Tuple[str, ...] = ("RegEntry",)) -> None:
        self.hoist = hoist
        self.imports: typing.Dict[str, typing.Set[str]] = {}
        self._hoisted: typing.Dict[typing.Any, str] = {}
        self._hoisted_text: typing.List[typing.Tuple[str, str]] = []
        self._names: typing.Set[str] = set()

    # -- imports ------------------------------------------------------------

    def _import(self, cls: type) -> str:
        module = cls.__module__
        for suffix, relative in _RELATIVE_MODULES:
            if module.endswith(suffix):
                self.imports.setdefault(relative, set()).add(cls.__name__)
                return cls.__name__
        raise TypeError(f"cannot emit {cls.__module__}.{cls.__name__}")

    def import_block(self) -> str:
        lines = []
        for module in sorted(
            self.imports, key=lambda m: (-len(m) + len(m.lstrip(".")), m)
        ):
            names = sorted(self.imports[module])
            one_line = f"from {module} import {', '.join(names)}"
            if len(one_line) <= _LINE:
                lines.append(one_line)
            else:
                body = "".join(f"    {name},\n" for name in names)
                lines.append(f"from {module} import (\n{body})")
        return "\n".join(lines) + "\n" if lines else ""

    # -- values -------------------------------------------------------------

    def value(
        self,
        value: typing.Any,
        indent: int = 0,
        field: str = "",
        lead: int = 0,
        tail: int = 0,
    ) -> str:
        """`value` as source text; `lead` and `tail` are the columns before
        and after it on its line (black joins a one-item tuple that fits)."""
        pad = "    " * indent
        inner = "    " * (indent + 1)
        if value is None or isinstance(value, bool):
            return repr(value)
        if isinstance(value, enum.Enum):
            return f"{self._import(type(value))}.{value.name}"
        if isinstance(value, int):
            if "mask" in field and value >= 0:
                return f"0x{value:X}"
            return str(value)
        if isinstance(value, str):
            return _string(value)
        if _is_record(value):
            if type(value).__name__ in self.hoist and indent > 0:
                return self._hoist_record(value)
            return self._record(value, indent)
        if isinstance(value, tuple):
            if not value:
                return "()"
            items = [
                self.value(item, indent + 1, field, len(inner), 1) for item in value
            ]
            if len(items) == 1 and "\n" not in items[0]:
                joined = f"({items[0]},)"
                if lead + len(joined) + tail <= _LINE:
                    return joined
            return "(\n" + "".join(f"{inner}{item},\n" for item in items) + f"{pad})"
        if isinstance(value, dict):
            if not value:
                return "{}"
            rows = []
            for k in sorted(value):
                key = self.value(k, indent + 1)
                lead = len(inner) + len(key) + 2
                rows.append(
                    f"{inner}{key}: {self.value(value[k], indent + 1, str(k), lead, 1)},\n"
                )
            return "{\n" + "".join(rows) + f"{pad}}}"
        raise TypeError(f"cannot emit {type(value).__name__}: {value!r}")

    def _record(self, value: typing.Any, indent: int) -> str:
        pad = "    " * indent
        inner = "    " * (indent + 1)
        name = self._import(type(value))
        rows = []
        for f in dataclasses.fields(value):
            lead = len(inner) + len(f.name) + 1
            text = self.value(getattr(value, f.name), indent + 1, f.name, lead, 1)
            rows.append(f"{inner}{f.name}={text},\n")
        return f"{name}(\n" + "".join(rows) + f"{pad})"

    def _hoist_record(self, value: typing.Any) -> str:
        key = fingerprint(value)
        name = self._hoisted.get(key)
        if name is None:
            base = "_" + re.sub(r"[^A-Za-z0-9]", "_", str(value.name)).upper()
            name, n = base, 1
            while name in self._names:
                n += 1
                name = f"{base}_{n}"
            self._names.add(name)
            self._hoisted[key] = name
            self._hoisted_text.append((name, self._record(value, 0)))
        return name

    def constants_block(self) -> str:
        return "".join(f"{name} = {text}\n\n" for name, text in self._hoisted_text)


def module(
    what: str, assignments: typing.Sequence[typing.Tuple[str, typing.Any]]
) -> str:
    """A generated module: header, imports, hoisted constants, assignments.

    An assignment value that is a ``str`` starting with ``"@"`` is written as
    the Python expression after the ``@`` (for references to imported
    names)."""
    emitter = Emitter()
    body = []
    for name, value in assignments:
        if isinstance(value, str) and value.startswith("@"):
            text = value[1:]
        else:
            text = emitter.value(value, 0, name.lower(), len(name) + 3)
        body.append(f"{name} = {text}\n")
    parts = [header(what)]
    imports = emitter.import_block()
    if imports:
        parts.append("\n" + imports)
    constants = emitter.constants_block()
    if constants:
        parts.append("\n" + constants.rstrip("\n") + "\n")
    parts.append("\n" + "\n".join(body))
    return "".join(parts)


def fingerprint(value: typing.Any) -> typing.Any:
    """A hashable, type-exact rendering of a schema value (dataclass
    equality is not enough: ``ABIDef`` compares by id only)."""
    if _is_record(value):
        return (
            type(value).__name__,
            tuple(
                (f.name, fingerprint(getattr(value, f.name)))
                for f in dataclasses.fields(value)
            ),
        )
    if isinstance(value, enum.Enum):
        return (type(value).__name__, value.name)
    if isinstance(value, tuple):
        return ("tuple",) + tuple(fingerprint(v) for v in value)
    if isinstance(value, dict):
        return ("dict",) + tuple((k, fingerprint(value[k])) for k in sorted(value))
    return (type(value).__name__, value)
