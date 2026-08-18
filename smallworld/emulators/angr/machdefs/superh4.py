import typing

import angr
import pypcode

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh4 import (
    SH4_FLOAT_ARGUMENT_REGISTERS,
    SH4_INTEGER_ARGUMENT_REGISTERS,
    SH4_PROGRAM_COUNTER_REGISTER,
    SH4_REGISTER_ALIASES,
    SH4_RETURN_ADDRESS_REGISTER,
    SH4_RETURN_VALUE_REGISTER,
    SH4_STATUS_REGISTER,
)
from .machdef import GhidraMachineDef

# The Linux/SH syscall convention and the IRSB-rewriting helpers are shared with
# SH-2A and live in `superh.py`, which `machdefs/__init__.py` already imports
# first.  Both SuperH generations spell `trapa` identically and use the same
# kernel ABI; only the sleigh *modelling* of the instruction differs, so only the
# way the trap is located in the lifted block differs here.  See the long comment
# at the top of `superh.py` for the mechanism, the register assignment and its
# provenance, the cross-backend interrupt-vs-syscall split, and the deliberate
# lack of any check on the trap immediate.
from .superh import (
    SUPERH_INSN_SIZE,
    SUPERH_TRAP_USEROP,
    SimCCSuperHLinuxSyscall,
    covers_one_instruction,
    lift_for_rewrite,
    pcode_arch,
    rewrite_as_syscall,
)

SH4_BE_PCODE_LANGUAGE = "SuperH4:BE:32:default"
SH4_EL_PCODE_LANGUAGE = "SuperH4:LE:32:default"


class SuperH4MachineDef(GhidraMachineDef):
    """Shared SH-4/SH-4A definition.

    Has no ``byteorder`` or ``pcode_language``, so ``find_subclass`` never
    selects it; the concrete subclasses below do.
    """

    arch = Architecture.SUPERH_SH4

    # As on SH-2A: sleigh lifts a branch together with its delay slot.
    supports_single_step = True

    # `archinfo.ArchPcode` lowercases every sleigh register name, so even though
    # SuperH4's spec spells the banked, control and system registers in uppercase
    # (R0_BANK, GBR, PC, MACH, FPSCR, ...) this map is lowercase throughout -
    # unlike the Ghidra machdef, which talks to sleigh directly and must preserve
    # the original case.
    _registers: typing.Dict[str, str] = {
        # *** General-Purpose Registers ***
        **{f"r{i}": f"r{i}" for i in range(0, 16)},
        # ArchPcode synthesizes `sp` and `ip`, but not `fp`/`ra`/`lr`.
        **SH4_REGISTER_ALIASES,
        # *** Banked Registers ***
        **{f"r{i}_bank": f"r{i}_bank" for i in range(0, 8)},
        # *** Control Registers ***
        SH4_PROGRAM_COUNTER_REGISTER: SH4_PROGRAM_COUNTER_REGISTER,
        SH4_STATUS_REGISTER: SH4_STATUS_REGISTER,
        "pr": "pr",
        "gbr": "gbr",
        "vbr": "vbr",
        "ssr": "ssr",
        "spc": "spc",
        "sgr": "sgr",
        "dbr": "dbr",
        "mach": "mach",
        "macl": "macl",
        # *** Floating-Point Registers ***
        **{f"dr{i}": f"dr{i}" for i in range(0, 16, 2)},
        **{f"fr{i}": f"fr{i}" for i in range(0, 16)},
        **{f"xd{i}": f"xd{i}" for i in range(0, 16, 2)},
        **{f"xf{i}": f"xf{i}" for i in range(0, 16)},
        "fpscr": "fpscr",
        "fpul": "fpul",
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        """Surface `trapa` as a syscall.

        `SuperH4.sinc`'s `:trapa` is just `TrapAlways(imm)`, so the trap is a
        CALLOTHER and can be located exactly, without going near the
        disassembly.  Without this, SH-4 `trapa` raised
        EmulationError("CALLOTHER emulation not currently supported") - so unlike
        the SH-2A path this rewrite discards no modelled machine state, because
        the sleigh spec models none.

        The userop is identified by *name*, resolved from the sleigh translator
        at lift time via `Varnode.getUserDefinedOpName()`, rather than by the
        index (0xa in Ghidra 12.1.2, being the 11th `define pcodeop` in the
        spec).  Indices are assigned in declaration order, so a Ghidra or pypcode
        bump that adds or reorders a `define pcodeop` would silently retarget a
        hardcoded index at some unrelated userop.  Matching on the name cannot
        drift that way.
        """
        irsb = lift_for_rewrite(state, kwargs)

        imark_index = None
        for i, op in enumerate(irsb._ops):
            if op.opcode == pypcode.OpCode.IMARK:
                imark_index = i
                continue
            if op.opcode != pypcode.OpCode.CALLOTHER:
                continue
            if op.inputs[0].getUserDefinedOpName() != SUPERH_TRAP_USEROP:
                continue
            if imark_index is None:
                # Cannot happen - the lifter emits an IMARK before every
                # instruction's ops - but the rewrite depends on it, so don't
                # guess if it ever does.
                break
            if not covers_one_instruction(irsb._ops[imark_index]):
                # `trapa` in a delay slot; see `covers_one_instruction`.
                break
            # Retain everything up to and including this instruction's IMARK,
            # i.e. drop only the trap's own ops; see `rewrite_as_syscall`.
            trap_addr = irsb._ops[imark_index].inputs[0].offset
            rewrite_as_syscall(irsb, imark_index + 1, trap_addr + SUPERH_INSN_SIZE)
            break

        kwargs["irsb"] = irsb
        return super().successors(state, **kwargs)


class SuperH4BEMachineDef(SuperH4MachineDef):
    byteorder = Byteorder.BIG
    pcode_language = SH4_BE_PCODE_LANGUAGE


class SuperH4ELMachineDef(SuperH4MachineDef):
    byteorder = Byteorder.LITTLE
    pcode_language = SH4_EL_PCODE_LANGUAGE

    # `SuperH4.sinc`'s little-endian block swaps the names of each `fr` pair, so
    # that DRn = FRn:FRn+1 (FRn the upper half) holds in both endiannesses; it
    # does *not* do the same for the alternate bank.  Measured on
    # `SuperH4:LE:32:default`: xd0 is at register-space offset 0x240 size 8,
    # xf0 at 0x240 size 4 and xf1 at 0x244 - so in a little-endian register
    # space sleigh's xf0 is the *low* half of xd0 and xf1 the upper one, the
    # reverse of the architectural layout `platforms.defs.superh4` models.
    # Undo the transposition here rather than leaving every xf read and write
    # on little-endian SH-4 silently pointed at the wrong half; the `fr` pair
    # needs no such fixup because sleigh already swapped it.
    _registers = {
        **SuperH4MachineDef._registers,
        **{f"xf{i}": f"xf{i + 1}" for i in range(0, 16, 2)},
        **{f"xf{i + 1}": f"xf{i}" for i in range(0, 16, 2)},
    }


class SimCCSuperH4(angr.calling_conventions.SimCC):
    """SH-4 calling convention, per ``SuperH4_{be,le}.cspec``.

    SH-4 passes twice as many floating-point arguments as SH-2A (fr4-fr11), and
    additionally names dr4/dr6/dr8/dr10 for double-precision arguments. SimCC has
    no separate double-argument list, so only the single-precision registers are
    declared; the doubles overlay the same register file.
    """

    ARG_REGS = list(SH4_INTEGER_ARGUMENT_REGISTERS)
    FP_ARG_REGS = list(SH4_FLOAT_ARGUMENT_REGISTERS)
    # Spelled explicitly for the same reason as on SH-2A: the cspec lists the
    # float return fr0 ahead of r0, so `arch.ret_offset` is the wrong register.
    RETURN_VAL = angr.calling_conventions.SimRegArg(SH4_RETURN_VALUE_REGISTER, 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg(SH4_RETURN_ADDRESS_REGISTER, 4)


class SimCCSuperH4BE(SimCCSuperH4):
    ARCH = pcode_arch(SH4_BE_PCODE_LANGUAGE)  # type: ignore


class SimCCSuperH4EL(SimCCSuperH4):
    ARCH = pcode_arch(SH4_EL_PCODE_LANGUAGE)  # type: ignore


class SimCCSuperH4BELinuxSyscall(SimCCSuperHLinuxSyscall):
    ARCH = pcode_arch(SH4_BE_PCODE_LANGUAGE)  # type: ignore


class SimCCSuperH4ELLinuxSyscall(SimCCSuperHLinuxSyscall):
    ARCH = pcode_arch(SH4_EL_PCODE_LANGUAGE)  # type: ignore


angr.calling_conventions.register_default_cc(SH4_BE_PCODE_LANGUAGE, SimCCSuperH4BE)
angr.calling_conventions.register_default_cc(SH4_EL_PCODE_LANGUAGE, SimCCSuperH4EL)
angr.calling_conventions.register_syscall_cc(
    SH4_BE_PCODE_LANGUAGE, "default", SimCCSuperH4BELinuxSyscall
)
angr.calling_conventions.register_syscall_cc(
    SH4_EL_PCODE_LANGUAGE, "default", SimCCSuperH4ELLinuxSyscall
)
