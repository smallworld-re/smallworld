"""Styx fuzz scenario — the Styx counterpart to ``fuzz.py``.

Provides two scenario names:

* ``"styx"``: non-fuzzing emulation under the Styx backend, equivalent to the
  simple ``fuzz:<arch>`` variant. Useful as a smoke test of StyxEmulator on
  the ARM fuzz binaries without involving AFL++.
* ``"styx.afl_fuzz"``: AFL-driven fuzzing via ``Machine.fuzz_with_file`` (the
  unified entry point auto-detects ``StyxEmulator`` and routes through
  ``styxafl``). Mirrors ``fuzz.afl_fuzz`` but uses the Styx backend.

Scope: 32-bit ARM only (``armhf``, ``armel``) — Styx has no 64-bit ARM target.
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
from typing import Optional, Sequence

from .common import PlatformSpec, TestsPath, make_emulator, make_platform

SCENARIO_PREFIXES = (
    ("styx", "styx"),
    ("styx.afl_fuzz", "styx.afl_fuzz"),
)

NATIVE_PARITY = True


@dataclasses.dataclass(frozen=True)
class _StyxFuzzSpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    exit_offset: int
    arg_register: Optional[str] = None
    binary_name: Optional[str] = None
    heap_base: int = 0x2000
    heap_size: int = 0x4000
    argument_size: int = 4


_SIMPLE_SPECS = {
    "armhf": _StyxFuzzSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        exit_offset=92,
        heap_size=0x1000,
    ),
    "armel": _StyxFuzzSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        exit_offset=92,
        heap_size=0x1000,
    ),
}


_AFL_SPECS = {
    "armhf": _StyxFuzzSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        exit_offset=92,
    ),
    "armel": _StyxFuzzSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        exit_offset=92,
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario == "styx":
        return variant in _SIMPLE_SPECS
    if scenario == "styx.afl_fuzz":
        return variant in _AFL_SPECS
    return False


def _load_code(smallworld, spec: _StyxFuzzSpec, variant: str):
    if spec.binary_name is not None:
        path = TestsPath / "fuzz" / spec.binary_name
    else:
        arch = variant.split(".", 1)[0]
        path = TestsPath / "fuzz" / f"fuzz.{arch}.bin"
    return smallworld.state.memory.code.Executable.from_filepath(
        path.as_posix(), address=0x1000
    )


def _configure_argument(
    smallworld, machine, cpu, platform, spec: _StyxFuzzSpec, size_addr: int
) -> None:
    # All ARM specs route the buffer pointer through r0; no stack push needed.
    if spec.arg_register is None:
        return
    getattr(cpu, spec.arg_register).set_content(size_addr)


def _run_simple(variant: str, args: Sequence[str]) -> int:
    import smallworld

    parser = argparse.ArgumentParser(prog=f"run_case.py styx {variant}")
    parser.add_argument(
        "-c", "--crash", default=False, action="store_true", help="use crashing input"
    )
    ns = parser.parse_args(list(args))

    spec = _SIMPLE_SPECS[variant]
    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    code = _load_code(smallworld, spec, variant)
    heap = smallworld.state.memory.heap.BumpAllocator(spec.heap_base, spec.heap_size)

    user_input = b"bad!AAAAAAAA" if ns.crash else b"goodgoodgood"
    size_addr = heap.allocate_integer(
        len(user_input),
        4,
        "user input size",
        smallworld.platforms.Byteorder[spec.platform.byteorder],
    )
    heap.allocate_bytes(user_input, "user input")

    getattr(cpu, spec.pc_register).set_content(0x1000)
    _configure_argument(smallworld, machine, cpu, platform, spec, size_addr)

    machine.add(heap)
    machine.add(cpu)
    machine.add(code)

    try:
        emulator = make_emulator(smallworld, platform, "styx")
        emulator.add_exit_point(0x1000 + spec.exit_offset)
        final_machine = machine.emulate(emulator)
        value = getattr(final_machine.get_cpu(), spec.result_register)
        print(value)
    except smallworld.exceptions.EmulationError as error:
        print(error)
    return 0


def _run_afl(variant: str, args: Sequence[str]) -> int:
    import smallworld

    parser = argparse.ArgumentParser(prog=f"run_case.py styx.afl_fuzz {variant}")
    parser.add_argument("input_file", help="File path AFL will mutate")
    ns = parser.parse_args(list(args))

    spec = _AFL_SPECS[variant]
    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    code = _load_code(smallworld, spec, variant)
    heap = smallworld.state.memory.heap.BumpAllocator(spec.heap_base, spec.heap_size)

    user_input = b"goodgoodgood"
    size_addr = heap.allocate_integer(
        len(user_input),
        4,
        "user input size",
        smallworld.platforms.Byteorder[spec.platform.byteorder],
    )
    heap.allocate_bytes(user_input, "user input")

    getattr(cpu, spec.pc_register).set_content(0x1000)
    _configure_argument(smallworld, machine, cpu, platform, spec, size_addr)

    machine.add(heap)
    machine.add(cpu)
    machine.add(code)

    def input_callback(emulator, input_bytes, persistent_round, data):
        if len(input_bytes) > 0x1000:
            return False
        emulator.write_memory_content(size_addr, bytes(input_bytes))
        return None

    emulator = make_emulator(smallworld, platform, "styx")
    emulator.add_exit_point(0x1000 + spec.exit_offset)
    machine.fuzz_with_file(emulator, input_callback, ns.input_file)
    return 0


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if scenario == "styx":
        return _run_simple(variant, args)
    if scenario == "styx.afl_fuzz":
        return _run_afl(variant, args)
    raise SystemExit(f"unsupported styx fuzz scenario: {scenario}")
