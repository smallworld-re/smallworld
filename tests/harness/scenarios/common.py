from __future__ import annotations

import dataclasses
import pathlib
from typing import Tuple


TestsPath = pathlib.Path(__file__).resolve().parents[2]
RepoRoot = TestsPath.parent


@dataclasses.dataclass(frozen=True)
class PlatformSpec:
    architecture: str
    byteorder: str


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
    return getattr(smallworld.emulators, _EMULATOR_NAMES[normalise_engine(engine)])(platform)


def set_register(cpu, name: str, value: int) -> None:
    getattr(cpu, name).set(value)


def load_raw_code(smallworld, family: str, arch: str, *, address: int = 0x1000):
    path = TestsPath / family / f"{family}.{arch}.bin"
    return smallworld.state.memory.code.Executable.from_filepath(path.as_posix(), address=address)


def load_elf_code(
    smallworld,
    family: str,
    arch: str,
    platform,
    *,
    address: int | None = None,
):
    path = TestsPath / family / f"{family}.{arch}.elf"
    load_kwargs = {"platform": platform}
    if address is not None:
        load_kwargs["address"] = address
    with open(path, "rb") as elf:
        return smallworld.state.memory.code.Executable.from_elf(elf, **load_kwargs)


def maybe_enable_linear(smallworld, emulator, engine: str) -> None:
    if normalise_engine(engine) == "angr" and isinstance(emulator, smallworld.emulators.AngrEmulator):
        emulator.enable_linear()
