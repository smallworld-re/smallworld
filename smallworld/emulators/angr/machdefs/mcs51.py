import enum
import typing

import angr
import claripy
from angr.errors import AngrError

from ....platforms import Architecture, Byteorder
from ....platforms.defs.mcs51 import MCS51_ADDRESS_SPACES
from .machdef import GhidraMachineDef

# The 8051 keeps code, external RAM, internal RAM, SFRs and Ghidra's bit space
# in separate address spaces, and angr's p-code engine only knows one, named
# "ram" or "mem".  The engine below moves every access in one of the 8051's
# spaces to that space's place in SmallWorld's flat map, the same map the
# Ghidra backend uses (smallworld.platforms.defs.mcs51).
_SPACE_BASES = {name: base for name, base, _ in MCS51_ADDRESS_SPACES}

# The flat map runs past 64 KiB, so angr's addresses must be wider than the
# 8051's 16-bit pointers.
_FLAT_BITS = 32


class _UpdatedEnumMeta(enum.EnumMeta):
    def __contains__(cls, obj):
        if isinstance(obj, int):
            return obj in cls._value2member_map_
        return super().__contains__(obj)


def handle_nop(engine, op):
    # This op does nothing
    pass


def handle_decimal_adjust(engine, op):
    # DA A: adjust the accumulator after a BCD addition.  The op returns only
    # the new accumulator; the carry it may set lives in PSW.
    acc = engine._get_value(op.inputs[1]).zero_extend(1)
    psw = engine.state.regs.psw
    carry = psw[7] == 1
    aux_carry = psw[6] == 1

    adjust_low = claripy.Or(claripy.ULT(9, acc & 0xF), aux_carry)
    acc = claripy.If(adjust_low, acc + 0x06, acc)
    carry = claripy.Or(carry, claripy.And(adjust_low, claripy.UGT(acc, 0xFF)))

    adjust_high = claripy.Or(claripy.ULT(9, (acc >> 4) & 0xF), carry)
    acc = claripy.If(adjust_high, acc + 0x60, acc)
    carry = claripy.Or(carry, claripy.And(adjust_high, claripy.UGT(acc, 0xFF)))

    engine.state.regs.psw = claripy.If(carry, psw | 0x80, psw)
    engine._set_value(op.output, acc[7:0])


class MCS51UserOp(enum.IntEnum, metaclass=_UpdatedEnumMeta):
    def __new__(
        cls, val: int, name: str = "", handler: typing.Any = None, desc: str = ""
    ):
        obj = int.__new__(cls, val)
        obj._value_ = val
        obj.short_name = name
        obj.handler = handler
        obj.description = desc
        return obj

    def __init__(
        self, val: int, name: str = "", handler: typing.Any = None, desc: str = ""
    ):
        self._value_: int = val
        self.short_name: str = name
        self.handler: typing.Any = handler
        self.description: str = desc

    def __repr__(self):
        return f"{hex(self.value)}: {self.short_name} - {self.description}"

    # Numbered in declaration order; see the Ghidra backend's MCS51UserOp.
    DECIMAL_ADJUST = 0x00, "decimal_adjust", handle_decimal_adjust, "Decimal Adjust"
    NOP = 0x01, "nop", handle_nop, "No Operation"


class MCS51EnginePcode(angr.engines.UberEnginePcode):
    """angr's p-code engine, with the 8051's address spaces on a flat map."""

    def _flat_address(self, space_name: str, offset):
        base = _SPACE_BASES[space_name]
        if isinstance(offset, int):
            return base + offset
        return offset.zero_extend(_FLAT_BITS - offset.size()) + base

    def _set_value(self, varnode, value) -> None:
        if varnode.space.name in _SPACE_BASES:
            value = self._adjust_value_size(varnode.size * 8, value)
            self.state.memory.store(
                self._flat_address(varnode.space.name, varnode.offset),
                value,
                endness=self.project.arch.memory_endness,
            )
            return
        super()._set_value(varnode, value)

    def _get_value(self, varnode):
        if varnode.space.name in _SPACE_BASES:
            return self.state.memory.load(
                self._flat_address(varnode.space.name, varnode.offset),
                size=varnode.size,
                endness=self.project.arch.memory_endness,
            )
        return super()._get_value(varnode)

    def _execute_load(self) -> None:
        op = self._current_op
        assert op is not None
        space = op.inputs[0].getSpaceFromConst()
        if space.name not in _SPACE_BASES:
            return super()._execute_load()
        offset = self._get_value(op.inputs[1])
        out = op.output
        assert out is not None
        res = self.state.memory.load(
            self._flat_address(space.name, offset),
            out.size,
            endness=self.project.arch.memory_endness,
        )
        self._set_value(out, res)

    def _execute_store(self) -> None:
        op = self._current_op
        assert op is not None
        space = op.inputs[0].getSpaceFromConst()
        if space.name not in _SPACE_BASES:
            return super()._execute_store()
        offset = self._get_value(op.inputs[1])
        data = self._get_value(op.inputs[2])
        self.state.memory.store(
            self._flat_address(space.name, offset),
            data,
            endness=self.project.arch.memory_endness,
        )

    def _execute_callother(self) -> None:
        op = self._current_op
        assert op is not None
        opnum = op.inputs[0].offset
        if opnum not in MCS51UserOp:
            raise AngrError(f"Undefined user op {hex(opnum)}")
        MCS51UserOp(opnum).handler(self, op)


class MCS51MachineDef(GhidraMachineDef):
    arch = Architecture.MCS51
    byteorder = Byteorder.BIG
    pcode_language = "8051:BE:16:default"
    angr_engine = MCS51EnginePcode

    _registers = {
        "pc": "pc",
        "sp": "sp",
        "acc": "acc",
        "a": "acc",
        "b": "b",
        "psw": "psw",
        "dptr": "dptr",
        "dph": "dph",
        "dpl": "dpl",
        "r0": "r0",
        "r1": "r1",
        "r2": "r2",
        "r3": "r3",
        "r4": "r4",
        "r5": "r5",
        "r6": "r6",
        "r7": "r7",
    }

    def __init__(self):
        super().__init__()
        # angr sizes memory addresses by the architecture's bit width, which
        # the 8051's 16-bit pointers would make too narrow for the flat map.
        self._angr_arch.bits = _FLAT_BITS


__all__ = ["MCS51MachineDef"]
