from __future__ import annotations

import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    maybe_enable_linear,
    set_register,
    split_variant,
)

_ARCH = "tricore"
_ENGINE = "panda"
_PLATFORM = PlatformSpec("TRICORE", "LITTLE")
_ENTRY_OFFSET = 0x4
_MODEL_ADDRESS = 0x1000
_STACK_BASE = 0x2000
_STACK_SIZE = 0x4000
_STATIC_BUFFER_ADDRESS = 0x10000
_STATIC_BUFFER_VALUE = 0x04A1
_CALL_MNEMONICS = frozenset({"call", "calla", "fcall", "fcalla"})


def can_run(scenario: str, variant: str) -> bool:
    arch, engine = split_variant(variant)
    return scenario == "model_return" and arch == _ARCH and engine == _ENGINE


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if args:
        raise SystemExit(f"{scenario} does not take extra arguments: {' '.join(args)}")

    import smallworld

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, _PLATFORM)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "static_buf", _ARCH)
    machine.add(code)

    stack = smallworld.state.memory.stack.Stack.for_platform(
        platform, _STACK_BASE, _STACK_SIZE
    )
    machine.add(stack)

    call_site = code.address + _ENTRY_OFFSET
    set_register(cpu, "pc", call_site)
    stack.push_integer(0xFFFFFFFF, 8, "fake return address")
    set_register(cpu, "sp", stack.get_pointer())

    platform_value = platform
    abi_value = smallworld.platforms.ABI.NONE
    model_calls = 0

    class ReturnAddressModel(smallworld.state.models.Model):
        name = "return_address_model"
        platform = platform_value
        abi = abi_value
        static_space_required = 4

        def model(self, emulator: smallworld.emulators.Emulator) -> None:
            nonlocal model_calls

            model_calls += 1
            if model_calls > 1:
                raise AssertionError(
                    "TriCore/PANDA re-entered the model instead of resuming after the call"
                )

            ra = emulator.read_register("ra")
            if ra != call_site:
                raise AssertionError(
                    f"TriCore/PANDA returned unexpected ra {hex(ra)}; expected {hex(call_site)}"
                )
            insns, _ = emulator.disassemble(
                emulator.read_memory_content(ra, 4), ra, count=1
            )
            if not insns or insns[0].mnemonic not in _CALL_MNEMONICS:
                raise AssertionError(
                    "TriCore/PANDA did not expose a call instruction at the return address"
                )

            data = _STATIC_BUFFER_VALUE.to_bytes(4, "little")
            emulator.write_memory(_STATIC_BUFFER_ADDRESS, data)
            emulator.write_register("a2", _STATIC_BUFFER_ADDRESS)

    model = ReturnAddressModel(_MODEL_ADDRESS)
    model.static_buffer_address = _STATIC_BUFFER_ADDRESS
    machine.add(model)

    emulator = make_emulator(smallworld, platform, _ENGINE)
    maybe_enable_linear(smallworld, emulator, _ENGINE)
    emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    result = final_machine.get_cpu().d2.get()
    if not isinstance(result, int):
        result = emulator.eval_atmost(result, 1)[0]
    print(hex(result))
    return 0
