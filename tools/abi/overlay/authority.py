"""Which dependency is the authority for each generated field (spec 4.2).

Every other field of a record is curated in the overlay (a Hand), derived
by a Rule, or taken from the record's joins (``sources.*``).
"""

import typing

#: field path -> the dependency the value is generated from.
GENERATED: typing.Dict[str, str] = {
    # Ghidra compiler spec (12.1 / 11.4.2): arguments, returns, stack
    # offset and slot, callee-saved (role-filtered), sret, stack pointer.
    "int_args.registers": "ghidra",
    "fp_args.registers": "ghidra",
    "returns.int_registers": "ghidra",
    "returns.fp_registers": "ghidra",
    "stack.first_arg_offset": "ghidra",
    "stack.slot_size": "ghidra",
    "preservation.callee_saved": "ghidra",
    "sret.register": "ghidra",
    "special.stack_pointer": "ghidra",
    # angr: the return address and the syscall number and return registers.
    "return_mechanics.ra_register": "angr",
    "return_mechanics.ra_stack_offset": "angr",
    "return_mechanics.ra_size": "angr",
    "syscall.number_register": "angr",
    "syscall.return_register": "angr",
    # archinfo: TLS layout, where it models the platform.
    "special.tls.variant": "archinfo",
    "special.tls.tp_offset": "archinfo",
    "special.tls.dtv_offset": "archinfo",
}

#: field path -> the Rule that derives it from the rest of the record.
DERIVED: typing.Dict[str, str] = {
    "preservation.caller_saved": "R-COMPLEMENT",
    "preservation.universe": "R-COMPLEMENT",
}

DEPENDENCIES = ("ghidra", "angr", "archinfo")
