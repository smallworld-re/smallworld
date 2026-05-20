from __future__ import annotations

import logging
from typing import Sequence

from .spec import ScenarioInfo, just_run, VariantInfo
from .common import PlatformSpec, TestsPath, make_emulator, make_platform, split_variant

_ARCH_SPECS = {
    "aarch64": PlatformSpec("AARCH64", "LITTLE"),
    "amd64": PlatformSpec("X86_64", "LITTLE"),
    "armel": PlatformSpec("ARM_V6M", "LITTLE"),
    "armhf": PlatformSpec("ARM_V7A", "LITTLE"),
    "i386": PlatformSpec("X86_32", "LITTLE"),
    "mips": PlatformSpec("MIPS32", "BIG"),
    "mips64": PlatformSpec("MIPS64", "BIG"),
    "mips64el": PlatformSpec("MIPS64", "LITTLE"),
    "mipsel": PlatformSpec("MIPS32", "LITTLE"),
    "ppc": PlatformSpec("POWERPC32", "BIG"),
    "riscv64": PlatformSpec("RISCV64", "LITTLE"),
}

_NO_FIXED_LOAD_ADDRESS = {"armel", "mips", "mips64", "mips64el", "mipsel", "ppc"}
_NEEDS_T9 = {"mips", "mips64", "mips64el", "mipsel"}
_EXPECTED_ERRORS = {
    "read": ("Invalid access at", " of size 1"),
    "write": ("Invalid access at ", " of size 1"),
    "uaf": ("Invalid Free at ", None),
    "double_free": ("Invalid Free at ", None),
}


SCENARIO_PREFIXES = (
    ("checked_heap.double_free", "checked_heap.double_free"),
    ("checked_heap.read", "checked_heap.read"),
    ("checked_heap.uaf", "checked_heap.uaf"),
    ("checked_heap.write", "checked_heap.write"),
)

NATIVE_PARITY = True


def _checked_heap_variants() -> Sequence[VariantInfo]:
    out: list[VariantInfo] = []
    for arch in sorted(_ARCH_SPECS):
        for engine in ("unicorn", "angr", "panda", "pcode"):
            if not _supports_engine(arch, engine):
                continue
            variant = arch if engine == "unicorn" else f"{arch}.{engine}"
            out.append((variant, None, {}))
    return out


SCENARIO_INFOS = tuple(
    ScenarioInfo(
        prefix=f"checked_heap.{family}",
        scenario=f"checked_heap.{family}",
        tags=("scenario", "checked_heap"),
        variants_source=_checked_heap_variants,
        run_factory=just_run(),
        weight=2,
    )
    for family in ("double_free", "read", "uaf", "write")
)


def _supports_engine(arch: str, engine: str) -> bool:
    if arch == "riscv64":
        return engine in {"unicorn", "angr", "pcode"}
    return engine in {"unicorn", "angr", "panda", "pcode"}


def can_run(scenario: str, variant: str) -> bool:
    if not scenario.startswith("checked_heap."):
        return False
    family = scenario.split(".", 1)[1]
    if family not in _EXPECTED_ERRORS:
        return False
    arch, engine = split_variant(variant)
    return arch in _ARCH_SPECS and _supports_engine(arch, engine)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if args:
        raise SystemExit(f"{scenario} does not take extra arguments: {' '.join(args)}")

    import smallworld

    family = scenario.split(".", 1)[1]
    arch, engine = split_variant(variant)
    spec = _ARCH_SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    filename = TestsPath / "checked_heap" / family / f"{family}.{arch}.elf"
    with open(filename, "rb") as elf:
        load_kwargs = {"platform": platform}
        if arch not in _NO_FIXED_LOAD_ADDRESS:
            load_kwargs["address"] = 0x400000
        code = smallworld.state.memory.code.Executable.from_elf(elf, **load_kwargs)
        machine.add(code)

    entrypoint = code.get_symbol_value("main")
    cpu.pc.set(entrypoint)
    if arch in _NEEDS_T9 and hasattr(cpu, "t9"):
        cpu.t9.set(entrypoint)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
    machine.add(stack)
    stack.push_integer(0xFFFFFFFF, 8, "fake return address")
    cpu.sp.set(stack.get_pointer())

    heap = smallworld.state.memory.heap.CheckedBumpAllocator(0x200000, 0x1000, 16)
    machine.add(heap)

    malloc_model = smallworld.state.models.Model.lookup(
        "malloc", platform, smallworld.platforms.ABI.SYSTEMV, 0x10004
    )
    malloc_model.heap = heap
    malloc_model.allow_imprecise = True
    machine.add(malloc_model)
    code.update_symbol_value("malloc", malloc_model._address)

    free_model = smallworld.state.models.Model.lookup(
        "free", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
    )
    free_model.heap = heap
    free_model.allow_imprecise = True
    machine.add(free_model)
    code.update_symbol_value("free", free_model._address)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(0)
    expected_prefix, expected_suffix = _EXPECTED_ERRORS[family]
    try:
        machine.emulate(emulator)
        raise RuntimeError("Did not exit as expected")
    except ValueError as error:
        message = str(error)
        if not message.startswith(expected_prefix):
            raise
        if expected_suffix is not None and not message.endswith(expected_suffix):
            raise
    return 0
