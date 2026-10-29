import enum
import typing

import angr
import claripy
import pypcode
from angr.errors import AngrError
from angr.utils.constants import DEFAULT_STATEMENT

from ....exceptions import EmulationError
from ....platforms import Architecture, Byteorder
from ....platforms.defs.mcs51 import (
    MCS51_ADDRESS_SPACES,
    MCS51_IDATA_BASE,
    MCS51_INTERRUPT_SFRS,
    MCS51_OPCODE_RETI,
    MCS51_PSW_BANK_SELECT,
    MCS51_PSW_BANK_SHIFT,
    MCS51_REGISTER_BANKS_SIZE,
    MCS51_SFR_BASE,
    MCS51_SFR_IE,
    MCS51_SFR_IP,
    MCS51_SFR_SCON,
    MCS51_SFR_T2CON,
    MCS51_SFR_TCON,
    MCS51InterruptState,
    mcs51_return_address,
    mcs51_service_interrupts,
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

# Where a path's interrupt state is kept: an MCS51InterruptState, whether an
# interrupt was just taken, and whether the next block must be one
# instruction long.
_INTERRUPTS = "mcs51_interrupts"
_JUST_TAKEN = "mcs51_interrupt_taken"
_ONE_INSTRUCTION = "mcs51_one_instruction"

# SFRs whose writes can make an interrupt takeable: the request flags, IE and
# IP.  A write to IE or IP also holds interrupts for one instruction.
_INTERRUPT_SFRS = {
    MCS51_SFR_TCON,
    MCS51_SFR_SCON,
    MCS51_SFR_IE,
    MCS51_SFR_IP,
    MCS51_SFR_T2CON,
}
_HOLDING_SFRS = {MCS51_SFR_IE, MCS51_SFR_IP}


def _writes_sfrs(ops, sfrs) -> bool:
    for op in ops:
        out = op.output
        if out is not None and out.space.name == "SFR":
            if any(out.offset <= sfr < out.offset + out.size for sfr in sfrs):
                return True
    return False


def _instructions(irsb) -> typing.List[typing.Tuple[int, typing.List[typing.Any]]]:
    """Split a block's p-code by instruction: (address, ops) for each."""
    instructions: typing.List[typing.Tuple[int, typing.List[typing.Any]]] = []
    for op in irsb._ops:
        if op.opcode == pypcode.OpCode.IMARK:
            instructions.append((op.inputs[0].offset, []))
        elif instructions:
            instructions[-1][1].append(op)
    return instructions


class MCS51EnginePcode(angr.engines.UberEnginePcode):
    """angr's p-code engine, with the 8051's address spaces on a flat map.

    It also keeps two kinds of state current that Ghidra's 8051 language
    leaves out: the parity flag, which the hardware derives from the
    accumulator on every cycle, and R0-R7 as the register bank PSW selects in
    internal RAM.  And it takes interrupts, between blocks it ends wherever
    an instruction could make one takeable.
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

    def _interrupts_modeled(self) -> bool:
        memory_map = getattr(self.state.scratch, "memory_map", None)
        start, end = MCS51_INTERRUPT_SFRS
        return memory_map is not None and not memory_map.get_missing_ranges(
            (MCS51_SFR_BASE + start, MCS51_SFR_BASE + end)
        )

    def _concrete_byte(self, address: int, what: str) -> int:
        value = self.state.memory.load(address, 1, inspect=False, disable_actions=True)
        values = self.state.solver.eval_upto(value, 2)
        if len(values) != 1:
            raise EmulationError(f"The 8051's {what} is symbolic")
        return values[0]

    def _take_interrupt(self, irsb) -> bool:
        """Take an interrupt before this block, if the 8051 would take one.

        process_successors ends a block after any instruction that writes an
        interrupt SFR, so none of the instructions before a block's last
        changes whether an interrupt is takeable, and this check at the start
        of each block is as good as one at every instruction boundary.
        Taking an interrupt replaces the block with a call to the vector.
        """
        state = self.state
        globals_map = typing.cast(typing.MutableMapping[str, typing.Any], state.globals)

        def read_sfr(address: int) -> int:
            return self._concrete_byte(MCS51_SFR_BASE + address, f"SFR {address:#x}")

        last, last_ops = _instructions(irsb)[-1]
        interrupts, source = mcs51_service_interrupts(
            globals_map.get(_INTERRUPTS, MCS51InterruptState()),
            irsb.addr,
            read_sfr,
            lambda address: self._concrete_byte(address, f"code at {address:#x}"),
            last=last,
            # Straight after an interrupt is taken, its vector's first
            # instruction runs before the next check, as on the Ghidra
            # backend.
            take=not globals_map.get(_JUST_TAKEN, False),
        )
        globals_map[_INTERRUPTS] = interrupts
        globals_map[_JUST_TAKEN] = source is not None
        if source is None:
            # After RETI or a write to IE or IP, one more instruction runs
            # before the next interrupt, so the next block is that one.
            assert interrupts.previous is not None
            globals_map[_ONE_INSTRUCTION] = interrupts.previous[
                0
            ] == MCS51_OPCODE_RETI or _writes_sfrs(last_ops, _HOLDING_SFRS)
            return False
        globals_map[_ONE_INSTRUCTION] = False

        # Call the handler as LCALL would: push PC low byte first.
        sp = state.solver.eval_one(typing.cast(claripy.ast.bv.BV, state.regs.sp))
        for byte in irsb.addr.to_bytes(2, "little"):
            sp = (sp + 1) & 0xFF
            state.memory.store(
                MCS51_IDATA_BASE + sp, claripy.BVV(byte, 8), disable_actions=True
            )
        state.regs.sp = claripy.BVV(sp, 8)
        if source.cleared:
            flags = read_sfr(source.flag_sfr) & ~source.cleared
            state.memory.store(
                MCS51_SFR_BASE + source.flag_sfr,
                claripy.BVV(flags, 8),
                disable_actions=True,
            )
        assert self.successors is not None
        self.successors.add_successor(
            state,
            source.vector,
            claripy.true(),
            "Ijk_Boring",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=irsb.addr,
        )
        return True

    def _instructions_before_interrupts_change(self, addr: int, **kwargs) -> int:
        """How many instructions a block at addr may run.

        The block ends after the first instruction that writes TCON, SCON,
        IE, IP or T2CON, the only state other than RETI that decides whether
        an interrupt is takeable.  8051 instructions name the SFRs they write
        in their encoding - indirect addressing reaches internal RAM, not
        SFRs - so lifting the block shows every such write.  RETI ends a
        block anyway, as every return does.
        """
        irsb = self.lift_pcode(
            addr=addr,
            state=self.state,
            insn_bytes=kwargs.get("insn_bytes"),
            size=kwargs.get("size"),
            num_inst=kwargs.get("num_inst"),
            extra_stop_points=kwargs.get("extra_stop_points"),
        )
        instructions = _instructions(irsb)
        for count, (_, ops) in enumerate(instructions, start=1):
            if _writes_sfrs(ops, _INTERRUPT_SFRS):
                return count
        return len(instructions)

    def process_successors(self, successors, *args, **kwargs):
        addr = successors.addr
        if (
            isinstance(addr, int)
            and not self.project.is_hooked(addr)
            and self._interrupts_modeled()
        ):
            globals_map = typing.cast(
                typing.Mapping[str, typing.Any], self.state.globals
            )
            if globals_map.get(_ONE_INSTRUCTION, False):
                kwargs["num_inst"] = 1
            else:
                kwargs["num_inst"] = self._instructions_before_interrupts_change(
                    addr, **kwargs
                )
        return super().process_successors(successors, *args, **kwargs)

    def handle_pcode_block(self, irsb) -> None:
        if self._interrupts_modeled() and self._take_interrupt(irsb):
            return
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
