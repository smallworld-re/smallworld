"""Seed a record's curated overlay entries from the research master dataset.

Each SW-01 data PR runs this once for its own records, pastes the output into
tools/abi/overlay/<family>.py, and then replaces every marker it can with a
real citation. The master is not vendored (pass its path); this script is
deleted once the last family is seeded.

    python tools/abi/seed_from_master.py research/abi_master.json X86_64/LITTLE:sysv

Every value it prints carries ``Cite.master_seed(record, field, hint)``, where
the hint is the master's agree-list for that field with research paths
reduced to document names, so it points nowhere. The generator caps such
entries at medium confidence and counts them against MASTER_SEED_CEILING.
"""

import argparse
import json
import re
import sys
import typing

# overlay field -> (master section, getter over the master record)
_FIELDS: typing.Dict[str, typing.Tuple[str, typing.Callable[[dict], typing.Any]]] = {
    "stack.alignment": ("stack.alignment", lambda r: r["stack"]["alignment"]),
    "stack.red_zone": ("stack.red_zone", lambda r: r["stack"]["red_zone"]),
    "stack.shadow_space": ("stack", lambda r: r["stack"]["shadow_space"]),
    "data_model.name": ("data_model", lambda r: r["data_model"]["model"]),
    "data_model.char_signed": ("data_model", lambda r: r["data_model"]["char_signed"]),
    "data_model.wchar_signed": (
        "data_model",
        lambda r: r["data_model"]["wchar_t_signed"],
    ),
    "special.frame_pointer": (
        "special",
        lambda r: _name(r["special"]["frame_pointer"]),
    ),
    "special.static_chain": ("special", lambda r: _name(r["special"]["static_chain"])),
    "special.tls.register": (
        "special.tls",
        lambda r: _name(r["special"]["tls"]["register"]),
    ),
    "syscall.instructions": ("syscall", lambda r: (r["syscall"]["instruction"],)),
    "syscall.arg_registers": ("syscall", lambda r: tuple(r["syscall"]["arg_regs"])),
    "syscall.clobbered": ("syscall", lambda r: tuple(r["syscall"]["clobbered"] or ())),
    "syscall.return2_register": ("syscall", lambda r: r["syscall"]["return2_reg"]),
    "return_mechanics.callee_cleanup": (
        "return_mechanics",
        lambda r: r["return_mechanics"]["callee_cleanup"],
    ),
    "return_mechanics.delay_slot": (
        "return_mechanics",
        lambda r: r["return_mechanics"]["delay_slot"],
    ),
}


def _size_getter(key: str) -> typing.Callable[[dict], typing.Any]:
    return lambda record: record["data_model"]["sizes"][key]


for _key in (
    "short",
    "int",
    "long",
    "long_long",
    "pointer",
    "float",
    "double",
    "long_double",
):
    _FIELDS[f"data_model.sizes.{_key}"] = ("data_model", _size_getter(_key))


def _name(entry: typing.Optional[dict]) -> typing.Optional[str]:
    return None if entry is None else (entry.get("name") or entry.get("source_name"))


def hint(record: dict, section: str) -> str:
    """The master's agree-list for `section`, research paths reduced to
    document names."""
    provenance = record.get("provenance", {}).get(section) or {}
    agree = "; ".join(provenance.get("agree", []))
    decided = provenance.get("decided_by") or ""
    text = "; ".join(p for p in (agree, decided) if p)
    return re.sub(r"(?:research/)?(?:scratch/)?[\w./-]*/([\w.-]+)", r"\1", text)


def seed(master: dict, record_id: str) -> typing.List[str]:
    records = {r["id"]: r for r in master["records"]}
    record = records.get(record_id)
    if record is None:
        raise SystemExit(f"no record {record_id!r} in the master")
    lines = [
        f"# Seeded from the master for {record_id}; replace markers with citations."
    ]
    for field, (section, get) in sorted(_FIELDS.items()):
        try:
            value = get(record)
        except (KeyError, TypeError):
            continue
        lines.append(
            f"{field!r}: Hand({value!r}, (Cite.master_seed({record_id!r}, "
            f"{section!r}, {hint(record, section)!r}),), 'medium'),"
        )
    return lines


def main(argv: typing.Optional[typing.List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("master", help="path to research/abi_master.json")
    parser.add_argument("record", help="record id, e.g. X86_64/LITTLE:sysv")
    args = parser.parse_args(argv)
    with open(args.master, encoding="utf-8") as fh:
        master = json.load(fh)
    print("\n".join(seed(master, args.record)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
