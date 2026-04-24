from __future__ import annotations

import dataclasses
import pathlib
import subprocess
import sys
from typing import Tuple

from ..coverage import wrap_python_command

TestsPath = pathlib.Path(__file__).resolve().parents[2]
RepoRoot = TestsPath.parent


@dataclasses.dataclass(frozen=True)
class PlatformSpec:
    architecture: str
    byteorder: str


@dataclasses.dataclass(frozen=True)
class StringSource:
    register: str | None = None
    stack_pointer_register: str | None = None
    stack_offset: int = 0
    pointer_size: int = 8
    byteorder: str = "little"


_EMULATOR_NAMES = {
    "unicorn": "UnicornEmulator",
    "angr": "AngrEmulator",
    "panda": "PandaEmulator",
    "pcode": "GhidraEmulator",
    "ghidra": "GhidraEmulator",
}


def normalise_engine(engine: str) -> str:
    return "pcode" if engine == "ghidra" else engine


def split_variant(variant: str) -> Tuple[str, str]:
    arch, dot, engine = variant.partition(".")
    return arch, normalise_engine(engine or "unicorn")


def make_platform(smallworld, spec: PlatformSpec):
    return smallworld.platforms.Platform(
        smallworld.platforms.Architecture[spec.architecture],
        smallworld.platforms.Byteorder[spec.byteorder],
    )


def make_emulator(smallworld, platform, engine: str):
    return getattr(smallworld.emulators, _EMULATOR_NAMES[normalise_engine(engine)])(
        platform
    )


def set_register(cpu, name: str, value: int) -> None:
    getattr(cpu, name).set(value)


def load_raw_code(smallworld, family: str, arch: str, *, address: int = 0x1000):
    path = TestsPath / family / f"{family}.{arch}.bin"
    return smallworld.state.memory.code.Executable.from_filepath(
        path.as_posix(), address=address
    )


def load_elf_code(
    smallworld,
    family: str,
    arch: str,
    platform=None,
    *,
    address: int | None = None,
    use_platform: bool = True,
):
    path = TestsPath / family / f"{family}.{arch}.elf"
    load_kwargs = {}
    if use_platform:
        load_kwargs["platform"] = platform
    if address is not None:
        load_kwargs["address"] = address
    with open(path, "rb") as elf:
        return smallworld.state.memory.code.Executable.from_elf(elf, **load_kwargs)


def load_pe_code(
    smallworld,
    family: str,
    arch: str,
    platform,
    *,
    address: int | None = None,
):
    path = TestsPath / family / f"{family}.{arch}.pe"
    load_kwargs = {"platform": platform}
    if address is not None:
        load_kwargs["address"] = address
    with open(path, "rb") as pe:
        return smallworld.state.memory.code.Executable.from_pe(pe, **load_kwargs)


def load_elf_library(
    smallworld,
    family: str,
    arch: str,
    platform,
    *,
    address: int | None = None,
    use_platform: bool = True,
):
    path = TestsPath / family / f"{family}.{arch}.so"
    load_kwargs = {}
    if use_platform:
        load_kwargs["platform"] = platform
    if address is not None:
        load_kwargs["address"] = address
    with open(path, "rb") as elf:
        return smallworld.state.memory.code.Executable.from_elf(elf, **load_kwargs)


def load_pe_library(
    smallworld,
    family: str,
    arch: str,
    platform,
    *,
    address: int | None = None,
):
    path = TestsPath / family / f"{family}.{arch}.dll"
    load_kwargs = {"platform": platform}
    if address is not None:
        load_kwargs["address"] = address
    with open(path, "rb") as pe:
        return smallworld.state.memory.code.Executable.from_pe(pe, **load_kwargs)


def add_code_bounds(machine, *codes) -> None:
    for code in codes:
        for start, end in code.bounds:
            machine.add_bound(start, end)


def push_cli_argv(stack, argument: str, *, pointer_size: int) -> tuple[int, int]:
    data = argument.encode("utf-8") + b"\0"
    data += b"\0" * (16 - (len(data) % 16))

    stack.push_bytes(data, None)
    string_address = stack.get_pointer()

    stack.push_integer(0, pointer_size, None)
    stack.push_integer(string_address, pointer_size, None)
    stack.push_integer(0x10101010, pointer_size, None)

    argv = stack.get_pointer()
    stack.push_integer(argv, pointer_size, None)
    stack.push_integer(2, pointer_size, None)
    return string_address, argv


def read_pointer(emulator, address: int, *, pointer_size: int, byteorder: str) -> int:
    return int.from_bytes(emulator.read_memory(address, pointer_size), byteorder)


def read_c_string(emulator, address: int) -> bytes:
    value = b""
    byte = emulator.read_memory_content(address, 1)
    while byte != b"\x00":
        value += byte
        address += 1
        byte = emulator.read_memory_content(address, 1)
    return value


def resolve_string_pointer(emulator, source: StringSource) -> int:
    if source.register is not None:
        return emulator.read_register(source.register)
    if source.stack_pointer_register is None:
        raise ValueError("string source must read from a register or stack slot")
    stack_pointer = emulator.read_register(source.stack_pointer_register)
    return read_pointer(
        emulator,
        stack_pointer + source.stack_offset,
        pointer_size=source.pointer_size,
        byteorder=source.byteorder,
    )


def make_puts_model(smallworld, *, platform, address: int, source: StringSource):
    platform_value = platform
    abi_value = smallworld.platforms.ABI.NONE

    class PutsModel(smallworld.state.models.Model):
        name = "puts"
        platform = platform_value
        abi = abi_value

        def model(self, emulator: smallworld.emulators.Emulator) -> None:
            pointer = resolve_string_pointer(emulator, source)
            print(read_c_string(emulator, pointer))

    return PutsModel(address)


def make_gets_model(smallworld, *, platform, address: int, destination: StringSource):
    platform_value = platform
    abi_value = smallworld.platforms.ABI.NONE

    class GetsModel(smallworld.state.models.Model):
        name = "gets"
        platform = platform_value
        abi = abi_value

        def model(self, emulator: smallworld.emulators.Emulator) -> None:
            pointer = resolve_string_pointer(emulator, destination)
            data = input().encode("utf-8") + b"\0"
            try:
                emulator.write_memory_content(pointer, data)
            except Exception as error:  # noqa: BLE001
                raise smallworld.exceptions.AnalysisError(
                    f"Failed writing {len(data)} bytes to {hex(pointer)}"
                ) from error

    return GetsModel(address)


def make_noop_model(smallworld, *, name: str, platform, address: int):
    name_value = name
    platform_value = platform
    abi_value = smallworld.platforms.ABI.NONE

    class NoopModel(smallworld.state.models.Model):
        name = name_value
        platform = platform_value
        abi = abi_value

        def model(self, emulator: smallworld.emulators.Emulator) -> None:
            return None

    return NoopModel(address)


def resolve_ppc64_function_descriptor(code, symbol: str) -> int:
    descriptor = code.get_symbol_value(symbol) - code.address
    for offset, value in code.items():
        size = value.get_size()
        if offset <= descriptor < offset + size:
            inner = descriptor - offset
            return int.from_bytes(value.get_content()[inner : inner + 8], "big")
    raise ValueError(f"Failed parsing Function Descriptor for {symbol}")


def maybe_enable_linear(smallworld, emulator, engine: str) -> None:
    if normalise_engine(engine) == "angr" and isinstance(
        emulator, smallworld.emulators.AngrEmulator
    ):
        emulator.enable_linear()


def run_case_subprocess(scenario: str, variant: str, *args: str) -> None:
    # A few PANDA cases rerun isolated subtests this way so one emulator run
    # cannot leave process-global state behind for the next assertion.
    command = wrap_python_command(
        [
            sys.executable,
            (TestsPath / "run_case.py").as_posix(),
            scenario,
            variant,
            *args,
        ]
    )
    completed = subprocess.run(command, cwd=TestsPath, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)
