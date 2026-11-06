import enum
import typing

import angr
import claripy
import pypcode
from angr.errors import AngrError
from angr.utils.constants import DEFAULT_STATEMENT

from ....exceptions import ConfigurationError, EmulationError
from ....platforms import Architecture, Byteorder
from ....platforms.defs.mcs51 import (
    MCS51_ADDRESS_SPACES,
    MCS51_IDATA_BASE,
    MCS51_OPCODE_RETI,
    MCS51_PSW_BANK_SELECT,
    MCS51_PSW_BANK_SHIFT,
    MCS51_REGISTER_BANKS_SIZE,
    MCS51_SFR_BASE,
    MCS51_SFR_P2,
    MCS51FlashProgramming,
    MCS51Interrupt,
    MCS51InterruptSource,
    MCS51InterruptState,
    MCS51SFRPaging,
    mcs51_flash_owns_store,
    mcs51_flash_store,
    mcs51_interrupt_control_sfrs,
    mcs51_interrupt_sfrs,
    mcs51_pop_sfr_page,
    mcs51_push_sfr_page,
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

# The extensions holding the device's interrupt sources, when they are not the
# 8052's, its SFR paging, when it pages its SFRs, and how it writes its own
# flash, when SmallWorld knows.
_INTERRUPT_SOURCES = "mcs51_interrupt_sources"
_SFR_PAGING = "mcs51_sfr_paging"
_FLASH = "mcs51_flash"


def _writes_sfrs(ops, sfrs) -> bool:
    """Whether an instruction's ops may write one of some SFRs.

    The SFRs are addresses in SmallWorld's SFR space, with a page above the
    SFR where it matters.  An instruction stores to an SFR at an address it
    computes, the SFR or'd with its page, so this goes by the SFR alone: a
    write to it on any page counts.  A store whose SFR it cannot tell counts
    too.
    """
    wanted = {sfr & 0xFF for sfr in sfrs}
    defined: typing.Dict[typing.Tuple[str, int], typing.Any] = {}
    for op in ops:
        if (
            op.opcode == pypcode.OpCode.STORE
            and op.inputs[0].getSpaceFromConst().name == "PSFR"
        ):
            address = op.inputs[1]
            definition = defined.get((address.space.name, address.offset))
            constants = []
            if definition is not None and definition.opcode == pypcode.OpCode.INT_OR:
                constants = [v for v in definition.inputs if v.space.name == "const"]
            if len(constants) != 1 or constants[0].offset & 0xFF in wanted:
                return True
        out = op.output
        if out is not None:
            defined[(out.space.name, out.offset)] = op
            if out.space.name == "PSFR" and any(
                out.offset <= sfr < out.offset + out.size for sfr in sfrs
            ):
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

    # Within a block: the register bank selected and R0-R7 at the last sync,
    # or None when banks are not modeled.
    _bank: int = 0
    _bank_values: typing.Optional[typing.List[typing.Any]] = None

    # What the instruction executing has written, for the bank sync and the
    # parity flag to act on when it ends: R0-R7 by number, internal RAM 0x00-
    # 0x1F by offset (or anywhere there, for a symbolic address), PSW, and
    # ACC or PSW, which the parity flag depends on.
    # handle_pcode_block resets these as each block starts.
    _written_registers: typing.Set[int]
    _written_bank_memory: typing.Set[int]
    _wrote_bank_memory_somewhere: bool = False
    _wrote_psw: bool = False
    _parity_stale: bool = False

    # Whether the instruction executing may have written SFRPAGE, on a device
    # that pages its SFRs, so that sfr_page must be brought in step with it;
    # and the SFR that pages MOVX @Ri, so that xpage must be.
    _wrote_sfrpage: bool = False
    _wrote_xpage: bool = False

    def _register_offset(self, name: str) -> int:
        return self.project.arch.registers[name][0]

    def _load_register(self, name: str) -> claripy.ast.bv.BV:
        return typing.cast(
            claripy.ast.bv.BV,
            self.state.registers.load(
                self._register_offset(name), 1, inspect=False, disable_actions=True
            ),
        )

    def _store_register(self, name: str, value) -> None:
        self.state.registers.store(
            self._register_offset(name), value, inspect=False, disable_actions=True
        )

    def _selected_bank(self) -> int:
        psw = self._load_register("psw")
        if not psw.symbolic:
            return (psw.concrete_value & MCS51_PSW_BANK_SELECT) >> MCS51_PSW_BANK_SHIFT
        banks = self.state.solver.eval_upto(
            (psw & MCS51_PSW_BANK_SELECT) >> MCS51_PSW_BANK_SHIFT, 2
        )
        if len(banks) != 1:
            raise EmulationError("The 8051 register bank select bits are symbolic")
        return banks[0]

    def _load_bank(self, bank: int) -> typing.List[typing.Any]:
        data = self.state.memory.load(
            MCS51_IDATA_BASE + bank * 8, 8, inspect=False, disable_actions=True
        )
        return [data.get_byte(n) for n in range(8)]

    def _sync_register_bank(self) -> None:
        """Bring R0-R7 in step with the register bank PSW selects.

        On the 8051, R0-R7 are eight bytes of internal RAM, in one of four
        banks that PSW's RS bits select; compiled code reaches them through
        those addresses too (`push ar7`).  Ghidra's language makes them
        standalone registers, so the engine syncs the two: a register that
        changed since the last sync (by an instruction, a hook or a model) is
        written to its bank, then R0-R7 are reloaded from the bank PSW now
        selects.  At a path's first sync the registers win, so a caller's
        R0-R7 land in the selected bank.

        This full sync runs as each block starts, since hooks and models can
        change state between blocks; within a block,
        :meth:`_finish_instruction` syncs only what each instruction wrote.

        Banks are only modeled when internal RAM 0x00-0x1F is mapped;
        otherwise R0-R7 are plain registers.  The internal RAM accesses here
        skip angr's inspection, so they do not trigger memory hooks.
        """
        state = self.state
        memory_map = getattr(state.scratch, "memory_map", None)
        if memory_map is None or memory_map.get_missing_ranges(
            (MCS51_IDATA_BASE, MCS51_IDATA_BASE + MCS51_REGISTER_BANKS_SIZE)
        ):
            self._bank_values = None
            return

        bank = self._selected_bank()
        registers = [self._load_register(f"r{n}") for n in range(8)]
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

        values = self._load_bank(bank)
        for n in range(8):
            if not values[n].identical(registers[n]):
                self._store_register(f"r{n}", values[n])
        self._bank = bank
        self._bank_values = values
        globals_map[_SYNCED_BANK] = (bank, tuple(values))

    def _finish_instruction(self) -> None:
        """Sync what the instruction just executed wrote.

        The same as a full :meth:`_sync_register_bank`, but limited to what
        changed: R0-R7 that were written go to the bank they belong to, and
        R0-R7 whose bytes were written, or all of them when PSW switched
        banks, are reloaded.  Then the parity flag is recomputed if ACC or PSW
        was written.
        """
        if self._bank_values is not None and (
            self._written_registers
            or self._written_bank_memory
            or self._wrote_bank_memory_somewhere
            or self._wrote_psw
        ):
            state = self.state
            values = self._bank_values
            for n in self._written_registers:
                values[n] = self._load_register(f"r{n}")
                state.memory.store(
                    MCS51_IDATA_BASE + self._bank * 8 + n,
                    values[n],
                    inspect=False,
                    disable_actions=True,
                )
            bank = self._selected_bank() if self._wrote_psw else self._bank
            if bank != self._bank or self._wrote_bank_memory_somewhere:
                reload = set(range(8))
            else:
                reload = {
                    offset - bank * 8
                    for offset in self._written_bank_memory
                    if bank * 8 <= offset < bank * 8 + 8
                } - self._written_registers
            if reload:
                loaded = self._load_bank(bank)
                for n in reload:
                    if not loaded[n].identical(values[n]):
                        self._store_register(f"r{n}", loaded[n])
                        values[n] = loaded[n]
            self._bank = bank
            globals_map = typing.cast(
                typing.MutableMapping[str, typing.Any], state.globals
            )
            globals_map[_SYNCED_BANK] = (bank, tuple(values))
        self._written_registers = set()
        self._written_bank_memory = set()
        self._wrote_bank_memory_somewhere = False
        self._wrote_psw = False
        if self._parity_stale:
            self._update_parity()
        if self._wrote_sfrpage:
            self._wrote_sfrpage = False
            paging = self._sfr_paging()
            if paging is not None:
                self._sync_sfr_page(paging)
        if self._wrote_xpage:
            self._wrote_xpage = False
            self._sync_xpage()

    def _execute_current_op(self) -> None:
        # Sync at each instruction boundary, and before an op that passes the
        # state on, so every successor sees the instruction's writes.
        op = self._current_op
        assert op is not None
        if self.state.scratch.ins_addr != self._synced_insn:
            self._synced_insn = self.state.scratch.ins_addr
            self._finish_instruction()
        elif op.opcode in _EXIT_OPS:
            self._finish_instruction()
        super()._execute_current_op()

    def _update_parity(self) -> None:
        self._parity_stale = False
        acc = self._load_register("acc")
        psw = self._load_register("psw")
        if not acc.symbolic and not psw.symbolic:
            bit = bin(acc.concrete_value).count("1") & 1
            if psw.concrete_value & 1 != bit:
                self._store_register(
                    "psw", claripy.BVV((psw.concrete_value & 0xFE) | bit, 8)
                )
            return
        parity = acc[0]
        for bit in range(1, 8):
            parity = parity ^ acc[bit]
        # Concatenate rather than mask and OR: claripy simplifies a later
        # extract of PSW's other bits (the carry, say) through a Concat, so a
        # symbolic accumulator leaves them concrete.
        self._store_register("psw", claripy.Concat(psw[7:1], parity))

    def _note_register_write(self, varnode) -> None:
        start, end = varnode.offset, varnode.offset + varnode.size
        registers = self.project.arch.registers
        for n in range(8):
            if start <= registers[f"r{n}"][0] < end:
                self._written_registers.add(n)
        if start <= registers["psw"][0] < end:
            self._wrote_psw = True
            self._parity_stale = True
        if start <= registers["acc"][0] < end:
            self._parity_stale = True

    def _flash_store(self, address, data) -> bool:
        """Perform a store the device's flash programming owns, if it is one.

        A store to FLKEY, or a MOVX write while PSCTL's PSWE is set; see
        :class:`MCS51FlashProgramming`.  Flash programming is only modeled
        when PSCTL and FLKEY are mapped, and for stores to concrete
        addresses; one to flash must store a concrete byte.
        """
        extensions = getattr(self.state.scratch, "extensions", {})
        flash = extensions.get(_FLASH)
        memory_map = getattr(self.state.scratch, "memory_map", None)
        if flash is None or memory_map is None or data.size() != 8:
            return False
        if not all(
            memory_map.contains_value(MCS51_SFR_BASE + sfr)
            for sfr in (flash.psctl, flash.flkey)
        ):
            return False

        def read_memory(start: int, size: int) -> bytes:
            return bytes(
                self._concrete_byte(a, f"byte at {a:#x}")
                for a in range(start, start + size)
            )

        def write_memory(start: int, content: bytes) -> None:
            self.state.memory.store(
                start, claripy.BVV(content), inspect=False, disable_actions=True
            )

        addresses = self.state.solver.eval_upto(address, 2)
        if len(addresses) != 1 or not mcs51_flash_owns_store(
            flash, addresses[0], read_memory
        ):
            return False
        values = self.state.solver.eval_upto(data, 2)
        if len(values) != 1:
            raise EmulationError("A byte written to 8051 flash is symbolic")
        mcs51_flash_store(flash, addresses[0], values[0], read_memory, write_memory)
        return True

    def _note_sfr_write(self, address) -> None:
        def may_be(target: int) -> bool:
            if isinstance(address, int):
                return address == target
            return address.symbolic or address.concrete_value == target

        if may_be(self._xpage_address()):
            self._wrote_xpage = True
        extensions = getattr(self.state.scratch, "extensions", {})
        paging = extensions.get(_SFR_PAGING)
        if paging is not None and may_be(MCS51_SFR_BASE + paging.sfrpage):
            self._wrote_sfrpage = True

    def _note_internal_ram_write(self, offset, size: int) -> None:
        if isinstance(offset, int):
            start = offset
        elif not offset.symbolic:
            start = offset.concrete_value
        else:
            self._wrote_bank_memory_somewhere = True
            return
        for address in range(start, start + size):
            if address < MCS51_REGISTER_BANKS_SIZE:
                self._written_bank_memory.add(address)

    def _sfr_paging(self) -> typing.Optional[MCS51SFRPaging]:
        """The device's SFR paging, if it pages its SFRs and they are mapped.

        Paging is only modeled when SFRPAGE, the page stack and the SFR that
        enables it are mapped.
        """
        extensions = getattr(self.state.scratch, "extensions", {})
        paging = extensions.get(_SFR_PAGING)
        memory_map = getattr(self.state.scratch, "memory_map", None)
        if paging is None or memory_map is None:
            return None
        sfrs = (paging.sfrpage, paging.sfrnext, paging.sfrlast, paging.stack_enable[0])
        if not all(memory_map.contains_value(MCS51_SFR_BASE + sfr) for sfr in sfrs):
            return None
        return paging

    def _xpage_address(self) -> int:
        # The flat address of the SFR that pages MOVX @Ri.
        sfr = self.state.solver.eval_upto(self._load_register("xpage_sfr"), 2)
        if len(sfr) != 1:
            raise EmulationError("The 8051's xpage_sfr is symbolic")
        return MCS51_SFR_BASE + sfr[0]

    def _sync_xpage(self) -> None:
        """Keep xpage in step with the SFR that pages MOVX @Ri.

        MOVX @Ri takes its page from xpage, so as not to read an SFR the
        harness may not have mapped; it is that SFR's value, or 0 where it is
        not mapped.
        """
        address = self._xpage_address()
        memory_map = getattr(self.state.scratch, "memory_map", None)
        if memory_map is not None and memory_map.contains_value(address):
            page = self.state.memory.load(
                address, 1, inspect=False, disable_actions=True
            )
        else:
            page = claripy.BVV(0, 8)
        self._store_register("xpage", page)

    def _sync_sfr_page(self, paging: MCS51SFRPaging) -> None:
        # sfr_page mirrors SFRPAGE, from which instructions take the page of
        # the paged SFRs they reach.
        self._store_register(
            "sfr_page",
            self.state.memory.load(
                MCS51_SFR_BASE + paging.sfrpage, 1, inspect=False, disable_actions=True
            ),
        )

    def _interrupt_sources(self) -> typing.Type[MCS51InterruptSource]:
        extensions = getattr(self.state.scratch, "extensions", {})
        return extensions.get(_INTERRUPT_SOURCES, MCS51Interrupt)

    def _interrupts_modeled(self) -> bool:
        memory_map = getattr(self.state.scratch, "memory_map", None)
        return memory_map is not None and all(
            memory_map.contains_value(MCS51_SFR_BASE + sfr)
            for sfr in mcs51_interrupt_sfrs(self._interrupt_sources())
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

        def write_sfr(address: int, value: int) -> None:
            state.memory.store(
                MCS51_SFR_BASE + address, claripy.BVV(value, 8), disable_actions=True
            )

        # RETI, as the last block's last instruction, pops the SFR page stack
        # of a device that pages its SFRs.
        paging = self._sfr_paging()
        previous = globals_map.get(_INTERRUPTS, MCS51InterruptState()).previous
        if (
            paging is not None
            and previous is not None
            and previous[0] == MCS51_OPCODE_RETI
            and not globals_map.get(_JUST_TAKEN, False)
            and mcs51_pop_sfr_page(paging, read_sfr, write_sfr)
        ):
            self._sync_sfr_page(paging)

        sources = self._interrupt_sources()
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
            sources=sources,
        )
        globals_map[_INTERRUPTS] = interrupts
        globals_map[_JUST_TAKEN] = source is not None
        if source is None:
            # After RETI or a write to IE, IP or another SFR that enables
            # interrupts or sets their priorities, one more instruction runs
            # before the next interrupt, so the next block is that one.
            assert interrupts.previous is not None
            globals_map[_ONE_INSTRUCTION] = interrupts.previous[
                0
            ] == MCS51_OPCODE_RETI or _writes_sfrs(
                last_ops, mcs51_interrupt_control_sfrs(sources)
            )
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
        # The interrupt's page is that of its request flags.
        if paging is not None and mcs51_push_sfr_page(
            paging, read_sfr, write_sfr, source.flag_sfr >> 8
        ):
            self._sync_sfr_page(paging)
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

        The block ends after the first instruction that writes one of the
        device's interrupt SFRs (see :func:`mcs51_interrupt_sfrs`) - on the
        8052, TCON, SCON, IE, IP or T2CON - the only state other than RETI
        that decides whether an interrupt is takeable.  8051 instructions name the SFRs they write
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
        sfrs = mcs51_interrupt_sfrs(self._interrupt_sources())
        for count, (_, ops) in enumerate(instructions, start=1):
            if _writes_sfrs(ops, sfrs):
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
        # Hooks, models and the harness can change state between blocks, so
        # recompute the parity flag and sync the register bank in full here;
        # within the block, _finish_instruction keeps them current.
        self._written_registers = set()
        self._written_bank_memory = set()
        self._wrote_bank_memory_somewhere = False
        self._wrote_psw = False
        self._wrote_sfrpage = False
        self._wrote_xpage = False
        self._update_parity()
        self._sync_register_bank()
        self._sync_xpage()
        paging = self._sfr_paging()
        if paging is not None:
            self._sync_sfr_page(paging)
        self._synced_insn = irsb.addr
        super().handle_pcode_block(irsb)
        # The block's fall-through successor is this same state.
        self._finish_instruction()

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
            if varnode.space.name == "INTMEM":
                self._note_internal_ram_write(varnode.offset, varnode.size)
            elif varnode.space.name == "PSFR":
                self._note_sfr_write(
                    self._flat_address(varnode.space.name, varnode.offset)
                )
            return
        super()._set_value(varnode, value)
        if varnode.space.name == "register":
            self._note_register_write(varnode)

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
        address = self._flat_address(space.name, offset)
        if space.name in ("EXTMEM", "PSFR") and self._flash_store(address, data):
            return
        self.state.memory.store(
            address,
            data,
            endness=self.project.arch.memory_endness,
        )
        if space.name == "INTMEM":
            self._note_internal_ram_write(offset, op.inputs[2].size)
        elif space.name == "PSFR":
            self._note_sfr_write(address)

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
        "xpage_sfr": "xpage_sfr",
        "xpage": "xpage",
        "sfr_page": "sfr_page",
        "sfr_paged_lo": "sfr_paged_lo",
        "sfr_paged_hi": "sfr_paged_hi",
        "r0": "r0",
        "r1": "r1",
        "r2": "r2",
        "r3": "r3",
        "r4": "r4",
        "r5": "r5",
        "r6": "r6",
        "r7": "r7",
    }

    def initialize_state(self, emulator: typing.Any) -> None:
        # As the Ghidra machine definition.
        emulator.write_register("xpage_sfr", MCS51_SFR_P2)
        for register in ("xpage", "sfr_page", "sfr_paged_lo", "sfr_paged_hi"):
            emulator.write_register(register, 0)

    def set_flash_programming(
        self, emulator: typing.Any, flash: MCS51FlashProgramming
    ) -> None:
        """Write flash as a device that writes its own does.

        Kept with each path's state, as the interrupt sources are.

        Arguments:
            emulator: The emulator.
            flash: The device's flash programming.

        Raises:
            ConfigurationError: If the emulator already has a device's.
        """
        try:
            emulator.add_extension(_FLASH, flash)
        except KeyError:
            raise ConfigurationError(
                "the 8051 device's flash programming is already set"
            )

    def set_sfr_paging(self, emulator: typing.Any, paging: MCS51SFRPaging) -> None:
        """Page SFRs as a device that pages them does.

        The paging is kept with each path's state, as the interrupt sources
        are.

        Arguments:
            emulator: The emulator.
            paging: The device's SFR paging.

        Raises:
            ConfigurationError: If the emulator already has a device's paging.
        """
        try:
            emulator.add_extension(_SFR_PAGING, paging)
        except KeyError:
            raise ConfigurationError("the 8051 device's SFR paging is already set")
        lo, hi = paging.paged_masks()
        emulator.write_register("sfr_paged_lo", lo)
        emulator.write_register("sfr_paged_hi", hi)

    def set_interrupt_sources(
        self, emulator: typing.Any, sources: typing.Type[MCS51InterruptSource]
    ) -> None:
        """Take the interrupts of a device other than the 8052.

        The sources are kept with each path's state, which is where the
        engine looks for them.

        Arguments:
            emulator: The emulator.
            sources: The device's interrupt sources.

        Raises:
            ConfigurationError: If the emulator already has a device's
                sources.
        """
        try:
            emulator.add_extension(_INTERRUPT_SOURCES, sources)
        except KeyError:
            raise ConfigurationError("the 8051 device's interrupts are already set")

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
