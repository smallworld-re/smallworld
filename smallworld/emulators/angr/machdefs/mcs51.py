import enum
import typing

import angr
import claripy
import pypcode
from angr.errors import AngrError

from ....exceptions import EmulationError
from ....platforms import Architecture, Byteorder
from ....platforms.defs.mcs51 import (
    MCS51_ADDRESS_SPACES,
    MCS51_IDATA_BASE,
    MCS51_PSW_BANK_SELECT,
    MCS51_PSW_BANK_SHIFT,
    MCS51_REGISTER_BANKS_SIZE,
    mcs51_return_address,
)
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


# Ops that hand the state to a successor, or copy it for one.
_EXIT_OPS = {
    pypcode.OpCode.BRANCH,
    pypcode.OpCode.CBRANCH,
    pypcode.OpCode.BRANCHIND,
    pypcode.OpCode.CALL,
    pypcode.OpCode.CALLIND,
    pypcode.OpCode.RETURN,
}

# Where a path's last register bank sync is kept: (bank, R0-R7).
_SYNCED_BANK = "mcs51_register_bank"


class MCS51EnginePcode(angr.engines.UberEnginePcode):
    """angr's p-code engine, with the 8051's address spaces on a flat map.

    It also keeps two kinds of state current that Ghidra's 8051 language
    leaves out: the parity flag, which the hardware derives from the
    accumulator on every cycle, and R0-R7 as the register bank PSW selects in
    internal RAM.
    """

    # The instruction whose start the last register bank sync was for.
    _synced_insn: typing.Optional[int] = None

    def _sync_register_bank(self) -> None:
        """Keep R0-R7 in step with the register bank PSW selects.

        On the 8051, R0-R7 are eight bytes of internal RAM, in one of four
        banks that PSW's RS bits select; compiled code reaches them through
        those addresses too (`push ar7`).  Ghidra's language makes them
        standalone registers, so this syncs the two at every instruction
        boundary: a register that changed since the last sync (by an
        instruction, a hook or a model) is written to its bank, then R0-R7 are
        reloaded from the bank PSW now selects.  At a path's first sync the
        registers win, so a caller's R0-R7 land in the selected bank.

        Banks are only modeled when internal RAM 0x00-0x1F is mapped;
        otherwise R0-R7 are plain registers.  The internal RAM accesses here
        skip angr's inspection, so they do not trigger memory hooks.
        """
        state = self.state
        memory_map = getattr(state.scratch, "memory_map", None)
        if memory_map is None or memory_map.get_missing_ranges(
            (MCS51_IDATA_BASE, MCS51_IDATA_BASE + MCS51_REGISTER_BANKS_SIZE)
        ):
            return

        psw = typing.cast(claripy.ast.bv.BV, state.regs.psw)
        banks = state.solver.eval_upto(
            (psw & MCS51_PSW_BANK_SELECT) >> MCS51_PSW_BANK_SHIFT, 2
        )
        if len(banks) != 1:
            raise EmulationError("The 8051 register bank select bits are symbolic")
        bank = banks[0]

        registers = [getattr(state.regs, f"r{n}") for n in range(8)]
        globals_map = typing.cast(typing.MutableMapping[str, typing.Any], state.globals)
        synced = globals_map.get(_SYNCED_BANK)
        if synced is None:
            changed_bank, changed = bank, list(range(8))
        else:
            changed_bank, old = synced
            changed = [n for n in range(8) if not registers[n].identical(old[n])]
        for n in changed:
            state.memory.store(
                MCS51_IDATA_BASE + changed_bank * 8 + n,
                registers[n],
                inspect=False,
                disable_actions=True,
            )

        values = [
            state.memory.load(
                MCS51_IDATA_BASE + bank * 8 + n, 1, inspect=False, disable_actions=True
            )
            for n in range(8)
        ]
        for n in range(8):
            setattr(state.regs, f"r{n}", values[n])
        globals_map[_SYNCED_BANK] = (bank, tuple(values))

    def _execute_current_op(self) -> None:
        # Sync at each instruction boundary, and before an op that passes the
        # state on, so every successor sees the instruction's writes.
        op = self._current_op
        assert op is not None
        if self.state.scratch.ins_addr != self._synced_insn:
            self._synced_insn = self.state.scratch.ins_addr
            self._sync_register_bank()
        elif op.opcode in _EXIT_OPS:
            self._sync_register_bank()
        super()._execute_current_op()

    def _update_parity(self) -> None:
        acc = typing.cast(claripy.ast.bv.BV, self.state.regs.acc)
        parity = acc[0]
        for bit in range(1, 8):
            parity = parity ^ acc[bit]
        psw = typing.cast(claripy.ast.bv.BV, self.state.regs.psw)
        # Concatenate rather than mask and OR: claripy simplifies a later
        # extract of PSW's other bits (the carry, say) through a Concat, so a
        # symbolic accumulator leaves them concrete.
        self.state.regs.psw = claripy.Concat(psw[7:1], parity)

    def _writes_acc_or_psw(self, varnode) -> bool:
        # ACC, which the flag is computed from, and PSW, which holds it.
        if varnode.space.name != "register":
            return False
        registers = self.project.arch.registers
        start, end = varnode.offset, varnode.offset + varnode.size
        return any(start <= registers[name][0] < end for name in ("acc", "psw"))

    def handle_pcode_block(self, irsb) -> None:
        # Recompute parity on entry, in case the state was set up with a stale
        # flag; _set_value keeps it current from there.
        self._update_parity()
        self._synced_insn = None
        super().handle_pcode_block(irsb)
        # The block's fall-through successor is this same state.
        self._sync_register_bank()

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
        if self._writes_acc_or_psw(varnode):
            self._update_parity()

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

    def function_return_address(self, emulator: typing.Any) -> typing.Optional[int]:
        # The return address is in internal RAM, which no angr calling
        # convention can describe: the stack grows up, and SP is an offset
        # into a space angr does not know.
        return mcs51_return_address(emulator, pop=True)

    def __init__(self):
        super().__init__()
        # angr sizes memory addresses by the architecture's bit width, which
        # the 8051's 16-bit pointers would make too narrow for the flat map.
        self._angr_arch.bits = _FLAT_BITS


__all__ = ["MCS51MachineDef"]
