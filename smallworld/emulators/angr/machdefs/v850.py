import enum
import typing

import angr
import archinfo
import claripy
import pypcode

from ....exceptions import EmulationError
from ....platforms import Architecture, Byteorder
from ....platforms.defs.v850 import (
    V850_ARGUMENT_REGISTERS,
    V850_GENERAL_REGISTERS,
    V850_NAMED_REGISTERS,
    V850_PROGRAM_COUNTER_REGISTER,
    V850_RETURN_ADDRESS_REGISTER,
    V850_RETURN_VALUE_REGISTER,
    V850_SYSTEM_REGISTERS,
)
from .machdef import GhidraMachineDef

V850_PCODE_LANGUAGE = "V850:LE:32:default"

# PSW's overflow flag, PSW[2,1] in the sleigh.
_PSW_OV = 1 << 2


class V850UserOp(enum.IntEnum):
    """The p-code user operations Ghidra's V850 language lifts to."""

    SATURATE = 0
    DISABLE_IRQ = 1
    ENABLE_IRQ = 2
    HALT = 3
    SYNCHRONIZE = 4


def _end_block_after(irsb, i, jumpkind: str) -> int:
    """End the block after the instruction containing op i.

    Returns the address of the next instruction.
    """
    start = i
    while irsb._ops[start].opcode != pypcode.OpCode.IMARK:
        start -= 1
    imark = irsb._ops[start].inputs[0]
    next_addr = imark.offset + imark.size

    end = i + 1
    while end < len(irsb._ops) and irsb._ops[end].opcode != pypcode.OpCode.IMARK:
        end += 1

    irsb._ops = irsb._ops[0:end]
    irsb.next = next_addr
    irsb._size = next_addr - irsb.addr
    irsb._instruction_addresses = [
        a for a in irsb._instruction_addresses if a < next_addr
    ]
    irsb.jumpkind = jumpkind
    return next_addr


def _rewrite_v850_userops(irsb) -> typing.Optional[str]:
    """Replace the user operations in irsb with what they do.

    Returns the name of the register a saturating instruction must clamp, if
    the block now ends with one.
    """
    i = 0
    while i < len(irsb._ops):
        op = irsb._ops[i]
        if op.opcode != pypcode.OpCode.CALLOTHER:
            i += 1
            continue

        opnum = op.inputs[0].offset
        if opnum in (
            V850UserOp.DISABLE_IRQ,
            V850UserOp.ENABLE_IRQ,
            V850UserOp.SYNCHRONIZE,
        ):
            # di and ei have already set PSW.ID, and there is nothing to
            # synchronize with.
            irsb._ops.pop(i)
        elif opnum == V850UserOp.HALT:
            # halt waits for an interrupt, which never comes; stop here.
            irsb._ops.pop(i)
            _end_block_after(irsb, i - 1, "Ijk_Exit")
            return None
        elif opnum == V850UserOp.SATURATE:
            # The instruction has written its wrapped result and set PSW.OV;
            # clamp the result once the block has run. Ending the block here
            # leaves that as the last thing the block does.
            register = op.inputs[1].getRegisterName().lower()
            irsb._ops.pop(i)
            _end_block_after(irsb, i - 1, "Ijk_Boring")
            return register
        else:
            raise EmulationError(f"Undefined user op {hex(opnum)}")

    return None


def _saturate(state: angr.SimState, register: str) -> None:
    value = typing.cast(claripy.ast.bv.BV, getattr(state.regs, register))
    psw = typing.cast(claripy.ast.bv.BV, state.regs.psw)
    overflow = (psw & _PSW_OV) != 0
    clamped = claripy.If(
        value.SLT(0),
        claripy.BVV(0x7FFFFFFF, 32),
        claripy.BVV(0x80000000, 32),
    )
    setattr(state.regs, register, claripy.If(overflow, clamped, value))


class V850MachineDef(GhidraMachineDef):
    arch = Architecture.V850
    byteorder = Byteorder.LITTLE
    pcode_language = V850_PCODE_LANGUAGE

    # angr names p-code registers as Ghidra does, in lower case.
    _registers = {
        **{name: name for name in V850_GENERAL_REGISTERS},
        **{number: name for name, number in V850_NAMED_REGISTERS.items()},
        V850_PROGRAM_COUNTER_REGISTER: V850_PROGRAM_COUNTER_REGISTER,
        **{name: name for name in V850_SYSTEM_REGISTERS},
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        assert hasattr(state.scratch, "exit_points")

        if "extra_stop_points" in kwargs:
            exit_points = state.scratch.exit_points | set(kwargs["extra_stop_points"])
            del kwargs["extra_stop_points"]
        else:
            exit_points = state.scratch.exit_points

        if "irsb" in kwargs and kwargs["irsb"] is not None:
            irsb = kwargs["irsb"]
        else:
            kwargs["opt_level"] = 0
            irsb = state.block(extra_stop_points=exit_points, **kwargs).vex

        saturate = _rewrite_v850_userops(irsb)

        kwargs["irsb"] = irsb
        successors = super().successors(state, **kwargs)
        if saturate is not None:
            for successor in successors.all_successors:
                _saturate(successor, saturate)
        return successors


class SimCCV850(angr.calling_conventions.SimCC):
    """GCC's V850 calling convention.

    The first four word arguments go in r6 to r9, results come back in r10
    (and r11), and the return address is in lp.
    """

    ARG_REGS = list(V850_ARGUMENT_REGISTERS)
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg(V850_RETURN_VALUE_REGISTER, 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg(V850_RETURN_ADDRESS_REGISTER, 4)
    ARCH = archinfo.ArchPcode(V850_PCODE_LANGUAGE)  # type: ignore


angr.calling_conventions.register_default_cc(V850_PCODE_LANGUAGE, SimCCV850)
