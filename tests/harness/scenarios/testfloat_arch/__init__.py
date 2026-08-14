"""Per-architecture guest kernels for the testfloat scenario.

One module per architecture family. Each exports an ``ArchSupport`` named
``SUPPORT``; this package merges them so adding an architecture means adding a
module and one line below, and never editing the scenario runner.

To add an architecture:

1. Write ``tests/testfloat/testfloat.<variant>.s`` with four loops at
   ``ENTRY_F32_BINARY``/``ENTRY_F32_UNARY``/``ENTRY_F64_BINARY``/
   ``ENTRY_F64_UNARY``, all leaving through one label at ``EXIT_OFFSET``. The
   existing pattern rules in ``tests/Makefile`` build it with no changes.
2. Add a module here with the patch tables and a ``TestFloatSpec`` naming the
   input, output and count registers.
3. Nothing to register: modules here are discovered automatically.
4. Check the byte surgery with ``run_case.py testfloat <variant> --check-patches``
   before trusting a single result.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, Optional, Tuple

from .base import (
    ANGR_NO_FP,
    ENTRY_F32_BINARY,
    ENTRY_F32_UNARY,
    ENTRY_F64_BINARY,
    ENTRY_F64_UNARY,
    EXIT_OFFSET,
    GHIDRA_FLUSHES_SUBNORMALS,
    ArchSupport,
    Kernel,
    TestFloatSpec,
    encode_patch,
    kernel_key,
    normalise_disasm,
    op_shape,
)


def _discover() -> Tuple[ArchSupport, ...]:
    """Every sibling module that exports an ``ArchSupport`` named ``SUPPORT``.

    Discovery rather than a hand-maintained list so that adding an architecture
    touches exactly one new file. Modules are visited in name order to keep the
    variant listing stable.
    """
    found = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        if info.name == "base":
            continue
        try:
            module = importlib.import_module(f"{__name__}.{info.name}")
        except Exception as exc:  # noqa: BLE001 - re-raised with context below
            # Deliberately fatal rather than skipped: a module that fails to
            # import is a broken architecture, and silently dropping it would
            # turn missing coverage into a passing run. Name it, though, so the
            # failure does not read as a fault in every other architecture.
            raise RuntimeError(
                f"testfloat architecture module {info.name!r} failed to import: "
                f"{exc}"
            ) from exc
        support = getattr(module, "SUPPORT", None)
        if isinstance(support, ArchSupport):
            found.append(support)
    return tuple(found)


_FAMILIES = _discover()

SPECS: Dict[str, TestFloatSpec] = {}
VARIANT_SKIPS: Dict[str, str] = {}
for _family in _FAMILIES:
    _clash = set(_family.specs) & set(SPECS)
    if _clash:
        raise RuntimeError(f"testfloat architecture names collide: {sorted(_clash)}")
    SPECS.update(_family.specs)
    VARIANT_SKIPS.update(_family.variant_skips)


def skip_reason(arch: str, engine: str, func: str) -> Optional[str]:
    """Why this (arch, engine, function) cannot run, or None if it can.

    Every reason here is an upstream defect rather than a gap in SmallWorld, and
    each was reduced to a minimal case before being recorded.
    """
    for family in _FAMILIES:
        if arch in family.specs and family.function_skip is not None:
            return family.function_skip(arch, engine, func)
    return None


__all__ = [
    "ANGR_NO_FP",
    "ENTRY_F32_BINARY",
    "ENTRY_F32_UNARY",
    "ENTRY_F64_BINARY",
    "ENTRY_F64_UNARY",
    "EXIT_OFFSET",
    "GHIDRA_FLUSHES_SUBNORMALS",
    "ArchSupport",
    "Kernel",
    "SPECS",
    "TestFloatSpec",
    "VARIANT_SKIPS",
    "encode_patch",
    "kernel_key",
    "normalise_disasm",
    "op_shape",
    "skip_reason",
]
