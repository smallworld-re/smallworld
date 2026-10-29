import typing

from .... import utils
from ....platforms import Architecture, Byteorder
from ....platforms.defs.mcs51 import (
    MCS51_ADDRESS_SPACES,
    MCS51_IDATA_BASE,
    MCS51_INTERRUPT_SFRS,
    MCS51_PSW_BANK_SELECT,
    MCS51_PSW_BANK_SHIFT,
    MCS51_REGISTER_BANKS_SIZE,
    MCS51_SFR_BASE,
    MCS51InterruptState,
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

    def before_instruction(self, emulator) -> None:
        """Take an interrupt, if the 8051 would take one now.

        Interrupts are only modeled when the SFRs that control them are
        mapped; see :func:`mcs51_service_interrupts`.
        """
        mapped = utils.RangeCollection()
        for region in emulator.get_memory_map():
            mapped.add_range(region)
        start, end = MCS51_INTERRUPT_SFRS
        if mapped.get_missing_ranges((MCS51_SFR_BASE + start, MCS51_SFR_BASE + end)):
            return

        def read_sfr(address: int) -> int:
            return emulator.read_memory(MCS51_SFR_BASE + address, 1)[0]

        pc = emulator.read_register("pc")
        self._interrupts, source = mcs51_service_interrupts(
            self._interrupts,
            pc,
            read_sfr,
            lambda address: emulator.read_memory(address, 1)[0],
        )
        if source is None:
            return
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

    def update_derived_state(self, emulator) -> None:
        self._sync_register_bank(emulator)
        # Ghidra's 8051 language never computes the parity flag.
        psw = emulator.read_register("psw")
        new_psw = mcs51_psw_with_parity(psw, emulator.read_register("acc"))
        if new_psw != psw:
            emulator.write_register("psw", new_psw)

    def _sync_register_bank(self, emulator) -> None:
        """Keep R0-R7 in step with the register bank PSW selects.

        On the 8051, R0-R7 are eight bytes of internal RAM, in one of four
        banks that PSW's RS bits select; compiled code reaches them through
        those addresses too (`push ar7`).  Ghidra's language makes them
        standalone registers, so this syncs the two around every instruction:
        a register that changed since the last sync (by an instruction, a hook
        or a model) is written to its bank, then R0-R7 are reloaded from the
        bank PSW now selects.  At the first sync the registers win, so a
        caller's R0-R7 land in the selected bank.

        Banks are only modeled when internal RAM 0x00-0x1F is mapped;
        otherwise R0-R7 are plain registers.
        """
        mapped = utils.RangeCollection()
        for region in emulator.get_memory_map():
            mapped.add_range(region)
        if mapped.get_missing_ranges(
            (MCS51_IDATA_BASE, MCS51_IDATA_BASE + MCS51_REGISTER_BANKS_SIZE)
        ):
            return

        registers = [emulator.read_register(f"r{n}") for n in range(8)]
        if self._synced_bank is None:
            changed_bank, changed = None, list(range(8))
        else:
            changed_bank, old = self._synced_bank
            changed = [n for n in range(8) if registers[n] != old[n]]
        bank = (emulator.read_register("psw") & MCS51_PSW_BANK_SELECT) >> (
            MCS51_PSW_BANK_SHIFT
        )
        if changed_bank is None:
            changed_bank = bank
        for n in changed:
            emulator.write_memory(
                MCS51_IDATA_BASE + changed_bank * 8 + n, bytes([registers[n]])
            )

        values = list(emulator.read_memory(MCS51_IDATA_BASE + bank * 8, 8))
        for n in range(8):
            if values[n] != registers[n]:
                emulator.write_register(f"r{n}", values[n])
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
        "r0": "R0",
        "r1": "R1",
        "r2": "R2",
        "r3": "R3",
        "r4": "R4",
        "r5": "R5",
        "r6": "R6",
        "r7": "R7",
    }
