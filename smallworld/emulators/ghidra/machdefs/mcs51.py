import typing

from .... import utils
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
    MCS51_SFR_P2,
    MCS51InterruptState,
    mcs51_interrupt_to_take,
    mcs51_psw_with_parity,
    mcs51_service_interrupts,
)
from .machdef import GhidraMachineDef, GhidraUserOp


def handle_nop(emulator, op):
    # This op does nothing
    pass


def handle_decimal_adjust(emulator, op):
    # DA A: adjust the accumulator after a BCD addition.  The op returns only
    # the new accumulator; the carry it may set lives in PSW.
    acc = emulator._read_varnode(op.getInputs()[1])
    psw = emulator.read_register("psw")
    carry = bool(psw & 0x80)
    if (acc & 0x0F) > 9 or psw & 0x40:
        acc += 0x06
        carry = carry or acc > 0xFF
    if ((acc >> 4) & 0x0F) > 9 or carry:
        acc += 0x60
        carry = carry or acc > 0xFF
    emulator.write_register("psw", (psw | 0x80) if carry else psw)
    emulator._write_varnode(op.getOutput(), acc)


class MCS51UserOp(GhidraUserOp):
    # Numbered in declaration order.  Ghidra builds the 8051 with
    # BIT_OPS = "BIT_ADDRS", which declares only these two; the bit-access
    # ops (get, set, set_bit_value, clr) exist only under "PCODEOPS".
    DECIMAL_ADJUST = 0x00, "decimal_adjust", handle_decimal_adjust, "Decimal Adjust"
    NOP = 0x01, "nop", handle_nop, "No Operation"


class MCS51MachineDef(GhidraMachineDef):
    arch = Architecture.MCS51
    byteorder = Byteorder.BIG

    address_spaces = MCS51_ADDRESS_SPACES
    userops = MCS51UserOp

    def __init__(self):
        super().__init__()
        # The bank PSW selected, and R0-R7, at the last register bank sync;
        # None until the first.
        self._synced_bank: typing.Optional[typing.Tuple[int, typing.List[int]]] = None
        # Interrupts in service, and the instruction executing.
        self._interrupts = MCS51InterruptState()
        # Whether, at the last full interrupt check, no interrupt could have
        # been taken even without a hold; and whether an interrupt SFR has
        # been written since.  While both hold, only RETI changes anything.
        self._interrupts_quiet = False
        self._interrupt_sfrs_written = True
        # The memory map the mapping checks below last saw, and their results.
        self._mapped_for: typing.Optional[typing.Tuple[typing.Tuple[int, int], ...]] = (
            None
        )
        self._banks_mapped = False
        self._interrupt_sfrs_mapped = False
        # Register offsets in Ghidra's register space, by name.
        self._register_offsets: typing.Dict[str, int] = {}

    def _register_offset(self, name: str) -> int:
        offset = self._register_offsets.get(name)
        if offset is None:
            offset = self.pcode_reg(name).getAddress().getOffset()
            self._register_offsets[name] = offset
        return offset

    def _check_mapping(self, emulator) -> None:
        regions = tuple(emulator.get_memory_map())
        if regions == self._mapped_for:
            return
        mapped = utils.RangeCollection()
        for region in regions:
            mapped.add_range(region)
        start, end = MCS51_INTERRUPT_SFRS
        self._banks_mapped = not mapped.get_missing_ranges(
            (MCS51_IDATA_BASE, MCS51_IDATA_BASE + MCS51_REGISTER_BANKS_SIZE)
        )
        self._interrupt_sfrs_mapped = not mapped.get_missing_ranges(
            (MCS51_SFR_BASE + start, MCS51_SFR_BASE + end)
        )
        self._mapped_for = regions

    def initialize_state(self, emulator) -> None:
        # MOVX @Ri pages through P2, as on Intel's 8051, unless the harness
        # names another SFR.
        emulator.write_register("xpage_sfr", MCS51_SFR_P2)

    def before_instruction(self, emulator) -> None:
        """Take an interrupt, if the 8051 would take one now.

        Interrupts are only modeled when the SFRs that control them are
        mapped; see :func:`mcs51_service_interrupts`.  When nothing could
        have changed since the last check - no interrupt was takeable, no
        interrupt SFR has been written, and the last instruction was not
        RETI - only the instruction about to run is recorded.
        """
        self._check_mapping(emulator)
        if not self._interrupt_sfrs_mapped:
            return

        pc = emulator.read_register("pc")
        previous = self._interrupts.previous
        if (
            self._interrupts_quiet
            and not self._interrupt_sfrs_written
            and previous is not None
            and previous[0] != MCS51_OPCODE_RETI
        ):
            opcode = emulator.read_memory(pc, 1)[0]
            self._interrupts = MCS51InterruptState(
                self._interrupts.in_service, (opcode, previous[1], previous[2])
            )
            return
        self._interrupt_sfrs_written = False

        def read_sfr(address: int) -> int:
            return emulator.read_memory(MCS51_SFR_BASE + address, 1)[0]

        self._interrupts, source = mcs51_service_interrupts(
            self._interrupts,
            pc,
            read_sfr,
            lambda address: emulator.read_memory(address, 1)[0],
        )
        if source is None:
            self._interrupts_quiet = (
                mcs51_interrupt_to_take(read_sfr, self._interrupts.in_service) is None
            )
            return
        self._interrupts_quiet = False
        # Call the handler as LCALL would: push PC low byte first.
        sp = emulator.read_register("sp")
        for byte in pc.to_bytes(2, "little"):
            sp = (sp + 1) & 0xFF
            emulator.write_memory(MCS51_IDATA_BASE + sp, bytes([byte]))
        emulator.write_register("sp", sp)
        emulator.write_register("pc", source.vector)
        if source.cleared:
            flags = read_sfr(source.flag_sfr) & ~source.cleared
            emulator.write_memory(MCS51_SFR_BASE + source.flag_sfr, bytes([flags]))

    def update_derived_state(self, emulator, writes=None) -> None:
        """Keep R0-R7 in step with their register bank, and parity with ACC.

        On the 8051, R0-R7 are eight bytes of internal RAM, in one of four
        banks that PSW's RS bits select; compiled code reaches them through
        those addresses too (`push ar7`).  Ghidra's language makes them
        standalone registers, so this syncs the two: R0-R7 that were written
        go to the bank they belong to, then R0-R7 whose bytes were written,
        or all of them when PSW selected another bank, are reloaded.  At the
        first sync the registers win, so a caller's R0-R7 land in the
        selected bank.  Banks are only modeled when internal RAM 0x00-0x1F is
        mapped; otherwise R0-R7 are plain registers.

        Ghidra's language never computes the parity flag either, so it is
        recomputed after ACC or PSW is written.

        Only what ``writes`` shows changed is acted on; with no record, as on
        the first call, everything is.
        """
        self._check_mapping(emulator)
        psw_offset = self._register_offset("psw")
        if writes is None:
            self._interrupt_sfrs_written = True
            wrote_psw = wrote_acc = True
            registers = set(range(8))
            bank_memory = set(range(MCS51_REGISTER_BANKS_SIZE))
        else:
            start, end = MCS51_INTERRUPT_SFRS
            if writes.wrote_memory(MCS51_SFR_BASE + start, MCS51_SFR_BASE + end):
                self._interrupt_sfrs_written = True
            wrote_psw = writes.wrote_register(psw_offset)
            wrote_acc = writes.wrote_register(self._register_offset("acc"))
            registers = {
                n
                for n in range(8)
                if writes.wrote_register(self._register_offset(f"r{n}"))
            }
            bank_memory = {
                address - MCS51_IDATA_BASE
                for address in writes.wrote_memory(
                    MCS51_IDATA_BASE, MCS51_IDATA_BASE + MCS51_REGISTER_BANKS_SIZE
                )
            }

        if self._banks_mapped and (registers or bank_memory or wrote_psw):
            self._sync_register_bank(emulator, registers, bank_memory, wrote_psw)

        if wrote_acc or wrote_psw:
            psw = emulator.read_register("psw")
            new_psw = mcs51_psw_with_parity(psw, emulator.read_register("acc"))
            if new_psw != psw:
                emulator.write_register("psw", new_psw)

    def _sync_register_bank(
        self,
        emulator,
        registers: typing.Set[int],
        bank_memory: typing.Set[int],
        wrote_psw: bool,
    ) -> None:
        if self._synced_bank is None:
            # The first sync: the registers win.
            bank = (emulator.read_register("psw") & MCS51_PSW_BANK_SELECT) >> (
                MCS51_PSW_BANK_SHIFT
            )
            values = [emulator.read_register(f"r{n}") for n in range(8)]
            emulator.write_memory(MCS51_IDATA_BASE + bank * 8, bytes(values))
            self._synced_bank = (bank, values)
            return

        old_bank, values = self._synced_bank
        for n in registers:
            values[n] = emulator.read_register(f"r{n}")
            emulator.write_memory(
                MCS51_IDATA_BASE + old_bank * 8 + n, bytes([values[n]])
            )
        bank = old_bank
        if wrote_psw:
            bank = (emulator.read_register("psw") & MCS51_PSW_BANK_SELECT) >> (
                MCS51_PSW_BANK_SHIFT
            )
        if bank != old_bank:
            reload = set(range(8))
        else:
            reload = {
                offset - bank * 8
                for offset in bank_memory
                if bank * 8 <= offset < bank * 8 + 8
            } - registers
        if reload:
            loaded = emulator.read_memory(MCS51_IDATA_BASE + bank * 8, 8)
            for n in reload:
                if loaded[n] != values[n]:
                    emulator.write_register(f"r{n}", loaded[n])
                    values[n] = loaded[n]
        self._synced_bank = (bank, values)

    _registers = {
        "pc": "PC",
        "sp": "SP",
        "acc": "ACC",
        "a": "ACC",
        "b": "B",
        "psw": "PSW",
        "dptr": "DPTR",
        "dph": "DPH",
        "dpl": "DPL",
        "xpage_sfr": "XPAGE_SFR",
        "r0": "R0",
        "r1": "R1",
        "r2": "R2",
        "r3": "R3",
        "r4": "R4",
        "r5": "R5",
        "r6": "R6",
        "r7": "R7",
    }
