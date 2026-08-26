"""Load and save colorizer expected-results ("truth") data.

The colorizer scenarios compare the hints a run produces against
recorded expected values. Those live in `truth/<scenario>.json` rather
than inline in the test scripts, which keeps the scripts readable and
lets `regen_truth.py` rewrite them mechanically.

A truth file holds three things:

    all_pcs      every pc the traces visit
    summ         pc -> the summary hints reported at that pc, in order
    derivations  (pc, operand name, set of source SrcDsts) per operand

Objects are encoded as JSON dicts carrying a "__type__" naming the
class to rebuild; sets are encoded as lists and restored to sets by
the fields that hold them. Only the classes in _TYPES are accepted, so
a truth file can't name arbitrary code.
"""

import dataclasses
import json
import os
import typing

from smallworld.analyses.colorizer_read_write import (
    MemoryLvalInfo,
    ReadInfo,
    RegisterInfo,
    SrcDst,
)
from smallworld.hinting.hints import (
    DynamicMemoryValueSummaryHint,
    DynamicRegisterValueSummaryHint,
)
from smallworld.instructions.bsid import BSIDMemoryReferenceOperand
from smallworld.instructions.instructions import RegisterOperand
from smallworld.platforms.defs.platformdef import RegisterDef

TRUTH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "truth")

_TYPES = {
    c.__name__: c
    for c in (
        DynamicMemoryValueSummaryHint,
        DynamicRegisterValueSummaryHint,
        MemoryLvalInfo,
        ReadInfo,
        RegisterInfo,
        SrcDst,
        RegisterDef,
        BSIDMemoryReferenceOperand,
        RegisterOperand,
    )
}

# Operand classes are not dataclasses, so name their fields explicitly.
_OPERAND_FIELDS = {
    "BSIDMemoryReferenceOperand": (
        "segment",
        "base",
        "index",
        "scale",
        "offset",
        "size",
    ),
    "RegisterOperand": ("name",),
}


def encode(value: typing.Any) -> typing.Any:
    """Convert an object graph to JSON-safe data."""
    name = type(value).__name__
    if name in _OPERAND_FIELDS:
        out = {"__type__": name}
        out.update({f: encode(getattr(value, f)) for f in _OPERAND_FIELDS[name]})
        return out
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        out = {"__type__": name}
        out.update(
            {
                f.name: encode(getattr(value, f.name))
                for f in dataclasses.fields(value)
                if f.init
            }
        )
        return out
    if isinstance(value, (set, frozenset)):
        # sorted for a stable diff; the loader restores the set
        return sorted((encode(v) for v in value), key=json.dumps)
    if isinstance(value, (list, tuple)):
        return [encode(v) for v in value]
    return value


def decode(value: typing.Any) -> typing.Any:
    """Rebuild an object graph from JSON-safe data."""
    if isinstance(value, list):
        return [decode(v) for v in value]
    if isinstance(value, dict):
        name = value.get("__type__")
        if name is None:
            return {k: decode(v) for k, v in value.items()}
        if name not in _TYPES:
            raise ValueError(f"unknown type in truth data: {name!r}")
        kwargs = {k: decode(v) for k, v in value.items() if k != "__type__"}
        return _TYPES[name](**kwargs)
    return value


def path_for(scenario: str) -> str:
    return os.path.join(TRUTH_DIR, f"{scenario}.json")


def load(scenario: str):
    """Return (all_pcs, summ, derivations) for a scenario.

    `scenario` is the test's base name, e.g. "test_colorizer_1".
    """
    with open(path_for(scenario)) as f:
        raw = json.load(f)
    all_pcs = set(raw["all_pcs"])
    summ = {int(pc): decode(hints) for pc, hints in raw["summ"].items()}
    derivations = [
        (d["pc"], d["operand"], set(decode(d["sources"]))) for d in raw["derivations"]
    ]
    return all_pcs, summ, derivations


def save(scenario: str, all_pcs, summ, derivations) -> str:
    """Write a scenario's truth file; returns the path written."""
    os.makedirs(TRUTH_DIR, exist_ok=True)
    raw = {
        "all_pcs": sorted(all_pcs),
        "summ": {str(pc): encode(summ[pc]) for pc in sorted(summ)},
        "derivations": [
            {"pc": pc, "operand": operand, "sources": encode(sources)}
            for pc, operand, sources in derivations
        ],
    }
    path = path_for(scenario)
    with open(path, "w") as f:
        json.dump(raw, f, indent=1)
        f.write("\n")
    return path
