"""The typed overlay: the only hand-written input to the ABI tables.

Everything the generator cannot take from a dependency is stated here, with a
citation, and so is every place where the ABI departs from a dependency. The
types are plain frozen dataclasses so the overlay imports on Python 3.9 with
no third-party packages (TOML would need 3.11; YAML is not a dependency).

* :class:`Cite` -- where a value comes from.
* :class:`Hand` -- a curated value for one field of one record.
* :class:`Rule` -- a named, non-identity transform of a dependency value.
* :class:`Deviation` -- the ABI value where a dependency says something else,
  keyed by dependency version, so the final tables are the same whichever
  supported dependency set built them.
* :class:`Expect` -- a cited value a generated field must have (the
  documents as an oracle, for fields only one dependency provides).
* :class:`OracleAck` -- an accepted disagreement between an oracle (a
  dependency that is not the authority for a field) and the final value.
* :class:`GhidraJoin`, :class:`AngrJoin` -- which dependency record a record
  is generated from.
* :class:`RegisterFile` -- the registers a family's preservation partition
  covers, with their classes and fixed roles.
* :class:`RecordSpec` -- one ABI record: its joins, curated values,
  deviations and oracle acknowledgements.
"""

import dataclasses
import re
import typing

#: The required parts of each citation kind.
CITE_PARTS: typing.Dict[str, typing.Tuple[str, ...]] = {
    "psabi": ("doc", "version", "section"),
    "gcc": ("location", "ref"),
    "llvm": ("location", "ref"),
    "glibc": ("location", "ref"),
    "kernel": ("location", "tag"),
    "probe": ("path",),
    "manpage": ("page", "version"),
    "ghidra": ("version", "location"),
    "angr": ("version", "location"),
    "archinfo": ("version", "location"),
    "master_seed": ("record", "field", "hint"),
}

#: Citation kinds that name a line range in a pinned dependency.
DEPENDENCY_CITES = ("ghidra", "angr", "archinfo")

_LOCATION = re.compile(r"^[A-Za-z0-9_./+-]+:\d+(-\d+)?(,\d+(-\d+)?)*$")

CONFIDENCES = ("high", "medium", "low")


@dataclasses.dataclass(frozen=True)
class Cite:
    """A citation. Build one with the constructor for its kind."""

    kind: str
    parts: typing.Tuple[str, ...]

    @classmethod
    def psabi(cls, doc: str, version: str, section: str) -> "Cite":
        """A psABI or vendor ABI document, by version and section."""
        return cls("psabi", (doc, version, section))

    @classmethod
    def gcc(cls, location: str, ref: str) -> "Cite":
        return cls("gcc", (location, ref))

    @classmethod
    def llvm(cls, location: str, ref: str) -> "Cite":
        return cls("llvm", (location, ref))

    @classmethod
    def glibc(cls, location: str, ref: str) -> "Cite":
        return cls("glibc", (location, ref))

    @classmethod
    def kernel(cls, location: str, tag: str) -> "Cite":
        return cls("kernel", (location, tag))

    @classmethod
    def probe(cls, path: str) -> "Cite":
        return cls("probe", (path,))

    @classmethod
    def manpage(cls, page: str, version: str) -> "Cite":
        return cls("manpage", (page, version))

    @classmethod
    def ghidra(cls, version: str, location: str) -> "Cite":
        """Lines of a Ghidra file (relative to pypcode's processors/)."""
        return cls("ghidra", (version, location))

    @classmethod
    def angr(cls, version: str, location: str) -> "Cite":
        """Lines of an angr source file (relative to the angr package)."""
        return cls("angr", (version, location))

    @classmethod
    def archinfo(cls, version: str, location: str) -> "Cite":
        return cls("archinfo", (version, location))

    @classmethod
    def master_seed(cls, record: str, field: str, hint: str = "") -> "Cite":
        """The transitional marker for a value seeded from the research
        master dataset and not yet re-verified. It names no file and never
        resolves; it caps the entry's confidence at medium."""
        return cls("master_seed", (record, field, hint))

    @property
    def is_master_seed(self) -> bool:
        return self.kind == "master_seed"

    def get(self, part: str) -> str:
        return self.parts[CITE_PARTS[self.kind].index(part)]

    def text(self) -> str:
        """A one-line rendering, for provenance and reports."""
        if self.kind == "psabi":
            doc, version, section = self.parts
            return f"{doc} {version} {section}"
        if self.kind == "master_seed":
            record, field, _ = self.parts
            return f"master_seed({record}, {field})"
        return f"{self.kind}:" + " @ ".join(self.parts)

    def problems(self) -> typing.List[str]:
        """Why this citation is malformed; ``[]`` if it is well formed."""
        names = CITE_PARTS.get(self.kind)
        if names is None:
            return [f"unknown citation kind {self.kind!r}"]
        if len(self.parts) != len(names):
            return [f"{self.kind} citation needs {names}, got {self.parts!r}"]
        problems = []
        for name, value in zip(names, self.parts):
            if name == "hint":
                continue
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{self.kind} citation has an empty {name}")
        if any("research/" in p or "scratch/" in p for p in self.parts):
            problems.append(f"{self.text()}: citations never point into research/")
        if "location" in names and not _LOCATION.match(self.get("location")):
            problems.append(
                f"{self.text()}: location must be file:line or file:first-last"
            )
        return problems


def effective_confidence(
    confidence: str, cite: typing.Sequence[Cite]
) -> typing.Tuple[str, typing.List[str]]:
    """An entry's confidence after the master-seed cap, and any problems."""
    problems = []
    if confidence not in CONFIDENCES:
        problems.append(f"unknown confidence {confidence!r}")
    if not cite:
        problems.append("every overlay entry cites its source")
    for c in cite:
        problems.extend(c.problems())
    if cite and all(c.is_master_seed for c in cite) and confidence == "high":
        confidence = "medium"
    return confidence, problems


@dataclasses.dataclass(frozen=True)
class Hand:
    """A curated value for one field of one record."""

    value: typing.Any
    cite: typing.Tuple[Cite, ...]
    confidence: str = "high"
    note: str = ""


@dataclasses.dataclass(frozen=True)
class Rule:
    """A named transform of a dependency value (normalization or derivation)."""

    id: str
    summary: str
    cite: typing.Tuple[Cite, ...]


@dataclasses.dataclass(frozen=True)
class Expect:
    """A cited value a generated field must have.

    For fields only one dependency provides (and so no dependency oracle
    checks), the documents are the oracle: the build fails if the generated
    value, after any Deviation, differs from ``value``.
    """

    field: str
    value: typing.Any
    cite: typing.Tuple[Cite, ...]


@dataclasses.dataclass(frozen=True)
class Deviation:
    """The ABI value of a dependency-authoritative field that the dependency
    gets wrong (or cannot express), per dependency version.

    ``observed`` maps each dependency version this deviation overrides to
    the value that version gives, after normalization. Under a listed
    version the build fails unless the dependency still gives exactly that
    value (a stale deviation). Under an unlisted version the dependency must
    already give ``abi_value``.
    """

    id: str
    record: str
    field: str
    dependency: str
    observed: typing.Mapping[str, typing.Any]
    abi_value: typing.Any
    klass: str
    """``a`` representation, ``b`` inexpressible, ``c`` dependency bug,
    ``d`` version drift."""
    root_cause: str
    cite: typing.Tuple[Cite, ...]
    keying: bool = False
    versions: typing.Optional[str] = None
    upstream: typing.Optional[str] = None
    confidence: str = "high"


@dataclasses.dataclass(frozen=True)
class OracleAck:
    """An accepted disagreement between an oracle and a final value.

    ``field_pattern`` is an :mod:`fnmatch` pattern over ``"<record>:<field>"``
    and must start with the ack's own record id. ``oracle`` and ``final``
    pin the disagreement it accepts: the oracle's value and the record's.
    Any other disagreement on the field fails the build. ``versions`` limits
    it to some versions of the oracle (``None``: all).
    """

    id: str
    dependency: str
    root_cause: str
    field_pattern: str
    oracle: typing.Any
    final: typing.Any
    cite: typing.Tuple[Cite, ...]
    versions: typing.Optional[typing.Tuple[str, ...]] = None


@dataclasses.dataclass(frozen=True)
class GhidraJoin:
    """The Ghidra prototype a record is generated from."""

    language: str
    compiler: str
    prototype: str

    @property
    def key(self) -> str:
        return f"{self.language}/{self.compiler}/{self.prototype}"


@dataclasses.dataclass(frozen=True)
class AngrJoin:
    """The angr calling conventions (and archinfo arch) a record uses."""

    arch: str
    """The archinfo class, e.g. ``ArchAMD64``."""
    endness: str
    """``LE`` or ``BE``."""
    os: str
    """The ``DEFAULT_CC``/``SYSCALL_CC`` key, e.g. ``Linux``."""

    @property
    def key(self) -> str:
        return f"{self.arch}/{self.endness}/{self.os}"


@dataclasses.dataclass(frozen=True)
class RegisterFile:
    """The register universe of a family's preservation partition."""

    name: str
    roots: typing.Tuple[str, ...]
    """Modeled roots in the partition (any order; the generator sorts them
    into PlatformDef register order)."""
    classes: typing.Mapping[str, str]
    """RegClass value of every root and unmodeled register."""
    unmodeled: typing.Mapping[str, int]
    """Every register an ABI field names that smallworld does not model
    (x87 ``st0``, ``mxcsr``), with its ABI width in bytes."""
    unmodeled_roots: typing.Tuple[str, ...]
    """The unmodeled registers in the partition; they sit after the modeled
    roots, in this order."""
    roles: typing.Mapping[str, typing.Tuple[str, ...]]
    """Fixed roles of a root's partition entries, whatever their class."""
    callee_roles: typing.Mapping[str, typing.Tuple[str, ...]]
    """Roles of a root's callee-saved entries only."""
    defined_masks: typing.Mapping[str, int]
    """For bit-split registers: the bits that belong to some class."""
    abi_name: typing.Callable[[str], str]
    """The psABI spelling of a register name."""
    cite: typing.Tuple[Cite, ...]
    abi_aliases: typing.Mapping[str, typing.Tuple[str, ...]] = dataclasses.field(
        default_factory=dict
    )
    """Other psABI spellings of a register name (AArch64 ``ip0`` for
    ``x16``), emitted as ``RegEntry.abi_aliases``."""


@dataclasses.dataclass(frozen=True)
class RecordSpec:
    """Everything the overlay says about one record."""

    id: str
    architecture: str
    byteorder: str
    variant: str
    ghidra: GhidraJoin
    angr: AngrJoin
    register_file: RegisterFile
    hand: typing.Mapping[str, Hand]
    feature: str = ""
    """The table feature name this record provides (see
    ``overlay.RECORDS``); ``smallworld.platforms.abi.table_features()``
    reports it when the record ships."""
    expectations: typing.Tuple[Expect, ...] = ()
    deviations: typing.Tuple[Deviation, ...] = ()
    oracle_acks: typing.Tuple[OracleAck, ...] = ()


def master_seed_count(records: typing.Iterable[RecordSpec]) -> int:
    """How many overlay entries still rest only on a master-seed marker."""
    count = 0
    for spec in records:
        entries: typing.List[typing.Sequence[Cite]] = [
            h.cite for h in spec.hand.values()
        ]
        entries += [d.cite for d in spec.deviations]
        entries += [a.cite for a in spec.oracle_acks]
        entries += [e.cite for e in spec.expectations]
        count += sum(
            1 for cite in entries if cite and all(c.is_master_seed for c in cite)
        )
    return count
