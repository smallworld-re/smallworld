from __future__ import annotations

from typing import Any, Mapping, Sequence

from .common import ARCH_REGISTERS, build_specs
from .raw_binary import RawBinarySpec, StackSpec, run_integer_case, supports_variant
from .spec import ScenarioInfo, assert_outputs, from_arch_table

NATIVE_PARITY = True

_ARCHS = (
    "aarch64",
    "amd64",
    "armel",
    "armhf",
    "i386",
    "la64",
    "m68k",
    "mips",
    "mipsel",
    "mips64",
    "mips64el",
    "ppc",
    "ppc64",
    "riscv64",
    "sh2a",
    "sh4",
    "sh4el",
    "tricore",
    "xtensa",
)


def _stack(arch: str, **overrides: Any) -> StackSpec:
    info = ARCH_REGISTERS[arch]
    kwargs: dict[str, Any] = {
        "pointer_register": info.stack_pointer_register,
        "fake_return_size": info.pointer_size,
    }
    kwargs.update(overrides)
    return StackSpec(**kwargs)


# Every arch except xtensa needs a fake return address pushed; i386 also passes
# its argument on the stack instead of in a register, and tricore enters past
# its prologue with no fake return because the test binary uses the link reg.
_STACKS = {
    "aarch64": _stack("aarch64"),
    "amd64": _stack("amd64"),
    "armel": _stack("armel"),
    "armhf": _stack("armhf"),
    "i386": _stack("i386", argument_size=4, pointer_adjust=4),
    "la64": _stack("la64"),
    "m68k": _stack("m68k"),
    "mips": _stack("mips"),
    "mipsel": _stack("mipsel"),
    "mips64": _stack("mips64"),
    "mips64el": _stack("mips64el"),
    "ppc": _stack("ppc"),
    "ppc64": _stack("ppc64"),
    "riscv64": _stack("riscv64"),
    # SuperH leaves the return address in pr rather than on the stack, so like
    # tricore it needs no synthetic return slot; the sh binaries still touch the
    # stack (sts.l pr,@-r15), so sp itself must be valid.
    "sh2a": _stack("sh2a", fake_return_size=None),
    "sh4": _stack("sh4", fake_return_size=None),
    "sh4el": _stack("sh4el", fake_return_size=None),
    "tricore": _stack("tricore", fake_return_size=None),
}

_PER_ARCH: dict[str, dict[str, Any]] = {
    arch: {"stack": stack} for arch, stack in _STACKS.items()
}
_PER_ARCH["i386"]["arg_register"] = None
_PER_ARCH["tricore"]["entry_offset"] = 0x14

_ARM_ENGINES = ("unicorn", "angr", "panda", "pcode", "styx")
# PowerPC also runs on Styx: "styx" selects the PPC405 core, "styx-mpc860" the MPC860.
_PPC_ENGINES = _ARM_ENGINES + ("styx-mpc860",)

_SPECS = build_specs(
    RawBinarySpec,
    _ARCHS,
    engines={"armel": _ARM_ENGINES, "armhf": _ARM_ENGINES, "ppc": _PPC_ENGINES},
    per_arch=_PER_ARCH,
)

SCENARIO_PREFIXES = (("call", "call"),)


def _call_expectations(
    variant: str, kwargs: Mapping[str, Any]
) -> tuple[tuple[tuple[str, ...], str], ...]:
    signext = bool(kwargs.get("signext", False))
    outputs = (
        (0, 0xFFFFFFFFFFFFFFF9 if signext else 0xFFFFFFF9),
        (101, 0x321),
        (65536, 0x21),
    )
    return tuple(((str(n),), f"{r:#x}") for n, r in outputs)


# Ghidra's SuperH4 sleigh never writes pr on bsr - the ghidra and angr backends
# read it back as 0 or unconstrained, where SH-2A's sleigh correctly yields the
# address after the delay slot - so bsr-based call-and-return does not work on
# SH-4 through either pcode-derived backend.  PANDA does not share that sleigh:
# it runs on real QEMU, whose bsr does set pr.
#
# The defect is specific to bsr.  :bsrf and :jsr both assign PR = inst_next,
# and sleigh counts the delay slot as part of the instruction, so that is the
# architectural inst_start + 4 - measured on all three engines, sh2a and sh4
# alike, with a jsr whose delay slot increments a register.  The `hooking`
# scenario uses jsr @Rn and therefore needs no SH-4 skips at all.  This
# scenario keeps bsr on purpose, so the defect stays pinned until it is fixed
# upstream; the skips below can be deleted when it is.
_SH4_SLEIGH_PR = "Ghidra SuperH4 sleigh does not write pr on bsr"
_SH4_CALL_SKIPS = {
    f"{arch}.{engine}": reason
    for arch in ("sh4", "sh4el")
    for engine, reason in (
        ("angr", _SH4_SLEIGH_PR),
        ("pcode", _SH4_SLEIGH_PR),
    )
}


SCENARIO_INFO = ScenarioInfo(
    prefix="call",
    scenario="call",
    tags=("scenario", "call"),
    variants_source=from_arch_table(
        _SPECS,
        skip_reasons={"ppc64": "Unexpected trap", **_SH4_CALL_SKIPS},
        arch_kwargs={
            arch: {"signext": True}
            for arch in ("la64", "mips64", "mips64el", "ppc64", "riscv64")
        },
    ),
    run_factory=assert_outputs(_call_expectations),
)


def can_run(scenario: str, variant: str) -> bool:
    return scenario == "call" and supports_variant(variant, _SPECS)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    return run_integer_case("call", variant, args, _SPECS)
