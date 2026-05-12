from __future__ import annotations

import typing

from .common import read_c_string, resolve_string_pointer

_TRICORE_ARCH = "tricore"
_PANDA_ENGINE = "panda"
_TRICORE_PANDA_CALL_MNEMONICS = frozenset({"call", "calla", "fcall", "fcalla"})
_TRICORE_PANDA_RETURN_MNEMONIC = "ret"


def _uses_tricore_panda_compatibility(arch: str, engine: str) -> bool:
    return arch == _TRICORE_ARCH and engine == _PANDA_ENGINE


def _iter_code_instructions(emulator, code):
    for offset, value in code.items():
        instructions, _ = emulator.disassemble(value.to_bytes(), code.address + offset)
        yield from instructions


def install_tricore_panda_raw_binary_call_return_compatibility(
    arch: str,
    engine: str,
    emulator,
    code,
) -> None:
    if not _uses_tricore_panda_compatibility(arch, engine):
        return

    # PANDA's TriCore support does not yet expose the architectural call stack
    # that raw binaries use for `call`/`ret`, so the harness tracks return PCs
    # until upstream TriCore call-frame support makes this removable.
    shadow_returns: list[int] = []

    def record_return_address(inner_emulator) -> None:
        instruction = inner_emulator.current_instruction()
        shadow_returns.append(inner_emulator.read_register("pc") + instruction.size)

    def restore_return_address(inner_emulator) -> None:
        if not shadow_returns:
            raise RuntimeError("TriCore PANDA shadow return stack underflow")
        inner_emulator.write_register("pc", shadow_returns.pop())

    for instruction in _iter_code_instructions(emulator, code):
        if instruction.mnemonic in _TRICORE_PANDA_CALL_MNEMONICS:
            emulator.hook_instruction(instruction.address, record_return_address)
        elif instruction.mnemonic == _TRICORE_PANDA_RETURN_MNEMONIC:
            emulator.hook_instruction(instruction.address, restore_return_address)


def install_tricore_panda_hooking_compatibility(
    arch: str,
    engine: str,
    smallworld,
    machine,
    code,
    *,
    pc_register: str,
    string_source,
    callsite_offsets: typing.Mapping[str, int],
) -> bool:
    if not _uses_tricore_panda_compatibility(arch, engine):
        return False

    missing = {"gets", "puts"} - set(callsite_offsets)
    if missing:
        missing_names = ", ".join(sorted(missing))
        raise ValueError(
            f"TriCore PANDA hooking compatibility needs callsite offsets for {missing_names}"
        )

    # PANDA currently mishandles TriCore function-hook returns for this raw
    # fixture, so hook the call instructions themselves and step past them.
    def skip_current_call(emulator: smallworld.emulators.Emulator) -> None:
        pc = emulator.read_register(pc_register)
        emulator.write_register(pc_register, pc + emulator.current_instruction().size)

    def gets_hook(emulator: smallworld.emulators.Emulator) -> None:
        pointer = resolve_string_pointer(emulator, string_source)
        emulator.write_memory_content(pointer, input().encode("utf-8") + b"\0")
        skip_current_call(emulator)

    def puts_hook(emulator: smallworld.emulators.Emulator) -> None:
        pointer = resolve_string_pointer(emulator, string_source)
        print(read_c_string(emulator, pointer))
        skip_current_call(emulator)

    machine.add(
        smallworld.state.models.Hook(code.address + callsite_offsets["gets"], gets_hook)
    )
    machine.add(
        smallworld.state.models.Hook(code.address + callsite_offsets["puts"], puts_hook)
    )
    return True
