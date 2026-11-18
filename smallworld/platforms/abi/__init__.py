"""Calling-convention (ABI) definitions.

One immutable :class:`ABIDef` per ``(Platform, variant)``, the ABI analogue of
:class:`~smallworld.platforms.defs.PlatformDef`::

    from smallworld.platforms import ABI, Architecture, Byteorder, Platform, abi

    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    d = abi.resolve(platform)             # the platform's default (SYSTEMV) record
    d.int_arg_registers()                 # ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
    d.is_callee_saved_value("rbx")        # True

    d = abi.maybe_resolve(platform, ABI.WINDOWS)  # None if not modelled
    d = abi.resolve(platform, variant="ms-x64")   # a variant, any family

The tables themselves are generated when smallworld is built or installed
(see :mod:`.registry`). Importing this package loads them, once; the import
never raises because of them. ``import smallworld`` does not import this
package, so it loads no tables. When the tables are missing or did not load,
every lookup, including ``maybe_resolve``, raises
:class:`ABITablesUnavailable` with the reason. That is the case in builds
that did not generate tables: source checkouts, and Python 3.9 and 3.11
builds.

Import discipline: this package imports only the standard library, capstone,
:mod:`smallworld.utils`, :mod:`smallworld.platforms.platforms`,
:mod:`smallworld.platforms.defs` and :mod:`smallworld.exceptions.exceptions`,
so any layer of smallworld (models, emulators, analyses) can import it without
an import cycle. Importing it as ``smallworld.platforms.abi`` still runs
``smallworld/__init__.py``, which loads the rest of smallworld; the
discipline bounds this package's own imports, not that.

Feature checks. A downstream package checks for what it needs by name
rather than by version number, because features land in any order:

* :data:`API_FEATURES` is a fixed frozenset naming the features of this
  package's code (``REQUIRED - abi.API_FEATURES``). It is empty in this
  release and says nothing about whether tables are installed.
* :func:`tables_available` and :func:`table_features` describe the
  generated tables: whether they loaded, and the feature names they declare.
"""

import typing

from . import enums, errors, model, validate
from .enums import (
    Confidence,
    EntryCondition,
    EntryValue,
    FloatABI,
    FloatEncoding,
    FpExhaust,
    FpFile,
    FpIndex,
    FpRoute,
    FpuKind,
    FunctionPointerFormat,
    IntAlloc,
    IntRepr,
    Justify,
    ModeKind,
    PairAlign,
    PairOrder,
    PreservationKind,
    ProcessForm,
    RegClass,
    ReturnKind,
    Role,
    SignalKind,
    Split,
    SretLocation,
    StackPointerTarget,
    SyscallErrorConvention,
    TlsKind,
    UnknownTypePolicy,
    VaListKind,
    VarargsPolicy,
)
from .errors import ABITablesUnavailable, UnrealizableLocation, UnsupportedSignature
from .model import (
    ABIDef,
    CAligns,
    CSizes,
    DataModel,
    EntryReg,
    EntryState,
    ExceptionFrame,
    ExtensionRule,
    FpArgSpec,
    GhidraKeying,
    IntArgSpec,
    Linkage,
    ModeReq,
    Preservation,
    ProcessEntry,
    RegEntry,
    ReturnMechanics,
    ReturnSpec,
    Sources,
    SpecialRegisters,
    StackSpec,
    StructReturn,
    SyscallABI,
    Tls,
    VaList,
    VaListField,
    Varargs,
    VarargsSignal,
)

# isort: split
# The registry loads the tables when it is imported, so it comes last: the
# names above are bound by then, and the data module may import them.
from . import registry
from .registry import (
    all_records,
    by_id,
    default_variant,
    maybe_resolve,
    mechanics_for,
    resolve,
    table_features,
    tables_available,
    variants,
)

#: The features of this package's code; see the module docstring. Fixed for
#: a release; it does not depend on the installed tables.
API_FEATURES: typing.FrozenSet[str] = frozenset()


__all__ = [
    # modules
    "enums",
    "errors",
    "model",
    "registry",
    "validate",
    # features
    "API_FEATURES",
    # lookups
    "all_records",
    "by_id",
    "default_variant",
    "maybe_resolve",
    "mechanics_for",
    "resolve",
    "table_features",
    "tables_available",
    "variants",
    # errors
    "ABITablesUnavailable",
    "UnrealizableLocation",
    "UnsupportedSignature",
    # records
    "ABIDef",
    "CAligns",
    "CSizes",
    "DataModel",
    "EntryReg",
    "EntryState",
    "ExceptionFrame",
    "ExtensionRule",
    "FpArgSpec",
    "GhidraKeying",
    "IntArgSpec",
    "Linkage",
    "ModeReq",
    "Preservation",
    "ProcessEntry",
    "RegEntry",
    "ReturnMechanics",
    "ReturnSpec",
    "Sources",
    "SpecialRegisters",
    "StackSpec",
    "StructReturn",
    "SyscallABI",
    "Tls",
    "VaList",
    "VaListField",
    "Varargs",
    "VarargsSignal",
    # enums
    "Confidence",
    "EntryCondition",
    "EntryValue",
    "FloatABI",
    "FloatEncoding",
    "FpExhaust",
    "FpFile",
    "FpIndex",
    "FpRoute",
    "FpuKind",
    "FunctionPointerFormat",
    "IntAlloc",
    "IntRepr",
    "Justify",
    "ModeKind",
    "PairAlign",
    "PairOrder",
    "PreservationKind",
    "ProcessForm",
    "RegClass",
    "ReturnKind",
    "Role",
    "SignalKind",
    "Split",
    "SretLocation",
    "StackPointerTarget",
    "SyscallErrorConvention",
    "TlsKind",
    "UnknownTypePolicy",
    "VaListKind",
    "VarargsPolicy",
]
