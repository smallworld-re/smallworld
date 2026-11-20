import logging
import typing

from .... import utils
from ....platforms import Architecture, Byteorder
from ....platforms.defs.mcs51 import (
    MCS51_ADDRESS_SPACES,
    MCS51_IDATA_BASE,
    MCS51_OPCODE_RETI,
    MCS51_PSW_AUX_CARRY,
    MCS51_PSW_BANK_SELECT,
    MCS51_PSW_BANK_SHIFT,
    MCS51_PSW_CARRY,
    MCS51_REGISTER_BANKS_SIZE,
    MCS51_SFR_BASE,
    MCS51FlashProgramming,
    MCS51Interrupt,
    MCS51InterruptSource,
    MCS51InterruptState,
    MCS51SFRPaging,
    mcs51_decimal_adjust,
    mcs51_flash_owns_store,
    mcs51_flash_store,
    mcs51_initialize_state,
    mcs51_interrupt_sfrs,
    mcs51_interrupt_to_take,
    mcs51_pop_sfr_page,
    mcs51_psw_with_parity,
    mcs51_service_interrupts,
    mcs51_sfr_stack_view,
    mcs51_take_interrupt,
    mcs51_unmapped_paging_message,
)
from .machdef import GhidraMachineDef, Userop

logger = logging.getLogger(__name__)


def _decimal_adjust(emulator, mnemonic, args) -> int:
    # DA A: adjust the accumulator after a BCD addition.  The op returns only
    # the new accumulator; the carry it may set lives in PSW.
    (acc,) = args
    psw = emulator.read_register("psw")
    acc, carry = mcs51_decimal_adjust(
        acc,
        bool(psw & MCS51_PSW_CARRY),
        bool(psw & MCS51_PSW_AUX_CARRY),
    )
    emulator.write_register("psw", (psw | MCS51_PSW_CARRY) if carry else psw)
    return acc & 0xFF


class MCS51MachineDef(GhidraMachineDef):
    arch = Architecture.MCS51
    byteorder = Byteorder.BIG

    address_spaces = MCS51_ADDRESS_SPACES
    # Ghidra builds the 8051 with BIT_OPS = "BIT_ADDRS", which declares only
    # these two userops; the bit-access ops (get, set, set_bit_value, clr)
    # exist only under "PCODEOPS".
    nop_userops = frozenset({"nop"})
    userops: typing.Mapping[str, Userop] = {"decimal_adjust": _decimal_adjust}

    def __init__(self):
        super().__init__()
        # The bank PSW selected, and R0-R7, at the last register bank sync;
        # None until the first.
        self._synced_bank: typing.Optional[typing.Tuple[int, typing.List[int]]] = None
        # The device's interrupt sources, the SFRs that decide whether they
        # are taken, and the interrupts in service and the instruction
        # executing.
        self._interrupt_sources: typing.Type[MCS51InterruptSource] = MCS51Interrupt
        self._interrupt_sfrs = mcs51_interrupt_sfrs(MCS51Interrupt)
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
        # The device's SFR paging, if it pages its SFRs, and whether the SFRs
        # it depends on are mapped.
        self._sfr_paging: typing.Optional[MCS51SFRPaging] = None
        self._sfr_paging_mapped = False
        # The SFRs paging depends on that are not mapped, and whether that has
        # been warned of.
        self._sfr_paging_unmapped: typing.Tuple[int, ...] = ()
        self._sfr_paging_warned = False
        # How the device writes its own flash, if SmallWorld knows, and
        # whether the SFRs that control it are mapped.
        self._flash: typing.Optional[MCS51FlashProgramming] = None
        self._flash_mapped = False
        # The SFR xpage_sfr names, and the memory map, when xpage was last
        # brought in step with it.
        self._xpage_sfr: typing.Optional[int] = None
        self._xpage_synced_for: typing.Optional[
            typing.Tuple[typing.Tuple[int, int], ...]
        ] = None
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
        self._banks_mapped = not mapped.get_missing_ranges(
            (MCS51_IDATA_BASE, MCS51_IDATA_BASE + MCS51_REGISTER_BANKS_SIZE)
        )
        self._interrupt_sfrs_mapped = all(
            mapped.contains_value(MCS51_SFR_BASE + sfr) for sfr in self._interrupt_sfrs
        )
        paging = self._sfr_paging
        self._sfr_paging_unmapped = (
            ()
            if paging is None
            else tuple(
                sfr
                for sfr in paging.sfrs()
                if not mapped.contains_value(MCS51_SFR_BASE + sfr)
            )
        )
        self._sfr_paging_mapped = paging is not None and not self._sfr_paging_unmapped
        flash = self._flash
        self._flash_mapped = flash is not None and all(
            mapped.contains_value(MCS51_SFR_BASE + sfr)
            for sfr in (flash.psctl, flash.flkey)
        )
        self._mapped_for = regions

    def initialize_state(self, emulator) -> None:
        mcs51_initialize_state(emulator)

    def set_sfr_paging(self, emulator, paging: MCS51SFRPaging) -> None:
        """Page SFRs as a device that pages them does.

        Arguments:
            emulator: The emulator.
            paging: The device's SFR paging.
        """
        self._sfr_paging = paging
        self._mapped_for = None
        # Page 0's, as sfr_page starts; the masks follow it from then on.
        lo, hi = paging.paged_masks()
        emulator.write_register("sfr_paged_lo", lo)
        emulator.write_register("sfr_paged_hi", hi)

    def set_flash_programming(self, emulator, flash: MCS51FlashProgramming) -> None:
        """Write flash as a device that writes its own does.

        Arguments:
            emulator: The emulator.
            flash: The device's flash programming.
        """
        self._flash = flash
        self._mapped_for = None

    def redirect_store(self, emulator, address: int, data: bytes) -> bool:
        """Perform a store the device's flash programming owns.

        A store to FLKEY, or a MOVX write while PSCTL's PSWE is set; see
        :class:`MCS51FlashProgramming`.  Flash programming is only modeled
        when PSCTL and FLKEY are mapped.
        """
        flash = self._flash
        if flash is None or len(data) != 1:
            return False
        self._check_mapping(emulator)
        if not self._flash_mapped or not mcs51_flash_owns_store(
            flash, address, emulator.read_memory
        ):
            return False
        mcs51_flash_store(
            flash, address, data[0], emulator.read_memory, emulator.write_memory
        )
        return True

    def _sync_sfr_page(self, emulator, stack: bool = False) -> None:
        # sfr_page mirrors SFRPAGE, from which instructions take the page of
        # the paged SFRs they reach, and on a device with SFRs on some pages
        # but not all, sfr_paged_lo and sfr_paged_hi say which are paged on
        # it.  The view of the page stack, on a device with one, shows
        # SFRPAGE or a level below it, so is synced when SFRPAGE changes, and
        # when the caller says the stack, or the level shown, may have.
        paging = self._sfr_paging
        assert paging is not None
        page = emulator.read_memory(MCS51_SFR_BASE + paging.sfrpage, 1)[0]
        if page != emulator.read_register("sfr_page"):
            emulator.write_register("sfr_page", page)
            if paging.also_shared:
                lo, hi = paging.paged_masks(page)
                emulator.write_register("sfr_paged_lo", lo)
                emulator.write_register("sfr_paged_hi", hi)
            stack = True
        if stack:
            view = mcs51_sfr_stack_view(
                paging,
                lambda address: emulator.read_memory(MCS51_SFR_BASE + address, 1)[0],
            )
            if view is not None:
                address, value = view
                emulator.write_memory(MCS51_SFR_BASE + address, bytes([value]))

    def set_interrupt_sources(
        self, emulator, sources: typing.Type[MCS51InterruptSource]
    ) -> None:
        """Take the interrupts of a device other than the 8052.

        Arguments:
            emulator: The emulator.
            sources: The device's interrupt sources.
        """
        self._interrupt_sources = sources
        self._interrupt_sfrs = mcs51_interrupt_sfrs(sources)
        self._interrupts_quiet = False
        self._interrupt_sfrs_written = True
        self._mapped_for = None

    def before_instruction(self, emulator) -> None:
        """Take an interrupt, if the 8051 would take one now.

        Interrupts are only modeled when the SFRs that control them are
        mapped; see :func:`mcs51_service_interrupts`.  When nothing could
        have changed since the last check - no interrupt was takeable, no
        interrupt SFR has been written, and the last instruction was not
        RETI - only the instruction about to run is recorded.

        On a device that pages its SFRs, ``sfr_page`` is first brought in
        step with SFRPAGE, whatever wrote it, and taking an interrupt
        and RETI push and pop the SFR page stack; see
        :class:`MCS51SFRPaging`.  Paging is only modeled when the SFRs it
        depends on are mapped (see :meth:`MCS51SFRPaging.sfrs`); a warning
        is logged, once, when they are not.
        """
        self._check_mapping(emulator)
        if self._sfr_paging_mapped:
            self._sync_sfr_page(emulator)
        elif self._sfr_paging_unmapped and not self._sfr_paging_warned:
            self._sfr_paging_warned = True
            logger.warning(mcs51_unmapped_paging_message(self._sfr_paging_unmapped))
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
                self._interrupts.in_service, (opcode, previous[1])
            )
            return
        self._interrupt_sfrs_written = False

        def read_sfr(address: int) -> int:
            return emulator.read_memory(MCS51_SFR_BASE + address, 1)[0]

        def write_sfr(address: int, value: int) -> None:
            emulator.write_memory(MCS51_SFR_BASE + address, bytes([value]))

        paging = self._sfr_paging if self._sfr_paging_mapped else None
        if (
            paging is not None
            and previous is not None
            and previous[0] == MCS51_OPCODE_RETI
            and mcs51_pop_sfr_page(paging, read_sfr, write_sfr)
        ):
            self._sync_sfr_page(emulator, stack=True)

        self._interrupts, source = mcs51_service_interrupts(
            self._interrupts,
            pc,
            read_sfr,
            lambda address: emulator.read_memory(address, 1)[0],
            sources=self._interrupt_sources,
        )
        if source is None:
            self._interrupts_quiet = (
                mcs51_interrupt_to_take(
                    read_sfr, self._interrupts.in_service, self._interrupt_sources
                )
                is None
            )
            return
        self._interrupts_quiet = False
        sp, paged = mcs51_take_interrupt(
            source,
            pc,
            emulator.read_register("sp"),
            lambda offset, value: emulator.write_memory(
                MCS51_IDATA_BASE + offset, bytes([value])
            ),
            read_sfr,
            write_sfr,
            paging,
        )
        emulator.write_register("sp", sp)
        emulator.write_register("pc", source.vector)
        if paged:
            self._sync_sfr_page(emulator, stack=True)

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
        recomputed after ACC or PSW is written; ``xpage``, from which MOVX
        @Ri takes its page, is kept in step with the SFR that holds it; and
        on a device that pages its SFRs, ``sfr_page`` with SFRPAGE.

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
            written = writes.wrote_memory(MCS51_SFR_BASE, MCS51_SFR_BASE + 0x10000)
            if any(
                address - MCS51_SFR_BASE in self._interrupt_sfrs for address in written
            ):
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

        self._sync_xpage(emulator, writes)

        if self._sfr_paging_mapped:
            paging = self._sfr_paging
            assert paging is not None
            sfrpage = MCS51_SFR_BASE + paging.sfrpage
            select = (
                None
                if paging.stack_view is None
                else MCS51_SFR_BASE + paging.stack_view[0]
            )
            stack = writes is None or (
                select is not None and bool(writes.wrote_memory(select, select + 1))
            )
            if (
                stack
                or writes.wrote_memory(sfrpage, sfrpage + 1)
                or writes.wrote_register(self._register_offset("sfr_page"))
            ):
                self._sync_sfr_page(emulator, stack=stack)

        if wrote_acc or wrote_psw:
            psw = emulator.read_register("psw")
            new_psw = mcs51_psw_with_parity(psw, emulator.read_register("acc"))
            if new_psw != psw:
                emulator.write_register("psw", new_psw)

    def _sync_xpage(self, emulator, writes) -> None:
        """Keep xpage in step with the SFR that pages MOVX @Ri.

        MOVX @Ri takes its page from xpage, so as not to read an SFR the
        harness may not have mapped; it is that SFR's value, or 0 where it is
        not mapped.  Only a write to xpage_sfr, to the SFR or to xpage
        itself, or a change to the memory map, can change it.
        """
        stale = self._xpage_synced_for is not self._mapped_for or (
            writes is not None and writes.wrote_register(self._register_offset("xpage"))
        )
        if (
            writes is None
            or self._xpage_sfr is None
            or writes.wrote_register(self._register_offset("xpage_sfr"))
        ):
            self._xpage_sfr = emulator.read_register("xpage_sfr")
            stale = True
        assert self._xpage_sfr is not None
        address = MCS51_SFR_BASE + self._xpage_sfr
        if not stale and not writes.wrote_memory(address, address + 1):
            return
        self._xpage_synced_for = self._mapped_for
        page = (
            emulator.read_memory(address, 1)[0]
            if emulator.is_memory_mapped(address, 1)
            else 0
        )
        if page != emulator.read_register("xpage"):
            emulator.write_register("xpage", page)

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
        "xpage": "XPAGE",
        "sfr_page": "SFR_PAGE",
        "sfr_paged_lo": "SFR_PAGED_LO",
        "sfr_paged_hi": "SFR_PAGED_HI",
        "r0": "R0",
        "r1": "R1",
        "r2": "R2",
        "r3": "R3",
        "r4": "R4",
        "r5": "R5",
        "r6": "R6",
        "r7": "R7",
    }
