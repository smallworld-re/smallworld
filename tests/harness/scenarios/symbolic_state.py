from __future__ import annotations

import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)
from .raw_binary import RawBinarySpec

_SPECS = {
    "amd64": RawBinarySpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        result_register="rax",
        arg_register="rdi",
        engines=("angr",),
    )
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "symbolic_state":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld

    arch, engine = split_variant(variant)

    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "symbolic_state", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address)
    assert spec.arg_register is not None
    getattr(cpu, spec.arg_register).set_label("arg1")

    emulator = make_emulator(smallworld, platform, engine)
    assert isinstance(emulator, smallworld.emulators.SymbolicEmulator)
    assert isinstance(emulator, smallworld.emulators.Emulator)
    emulator.enable_linear()
    emulator.add_exit_point(code.address + code.get_capacity())

    results = list(machine.symbolic_emulate(emulator))

    for m in results:
        # Bit of a hack; I know by inspection there should be two constraints,
        # and that both of them should reference arg1
        for constraint in m.get_constraints():
            if "arg1" not in constraint.variables:
                raise ValueError(
                    "Unexpected constraint for state at {m.get_cpu().rip}: {constraint}"
                )
            print(f"Constraint: {constraint}")
            for symbol, value in m.concretize_symbols(constraint):
                if value is not None:
                    val_str = " ".join(map(lambda x: f"{x:02x}", value))
                else:
                    val_str = "UNSAT!"
                print(f"Symbol {symbol} concretized to {val_str}")

    if len(results) != 2:
        raise smallworld.exceptions.AnalysisError(
            f"Expected 2 result states, got {len(results)}"
        )

    return 1
