import logging
import typing

from ... import emulators, exceptions, platforms
from ...platforms.defs.mcs51 import (
    MCS51Interrupt,
    mcs51_interrupts,
    mcs51_sfr_paging,
    mcs51_xpage_sfr,
)
from .. import state
from . import cpu

logger = logging.getLogger(__name__)


class MCS51(cpu.CPU):
    """CPU state for the Intel MCS-51 (8051).

    R0-R7 are the working registers of the current bank.  On real hardware
    they live in internal RAM at 0x00-0x1F, in the bank PSW's RS bits select.
    When internal RAM 0x00-0x1F is mapped, the emulators keep these registers
    and that bank in step, and these values are written into the selected
    bank when emulation starts; otherwise they are registers of their own.

    ``xpage_sfr`` is not a register of the hardware but a property of the
    device: the address of the SFR that supplies the high byte of MOVX @Ri's
    address.  The emulators set it to P2's (0xA0), as on Intel's 8051; set it
    to EMI0CN's to emulate a Silicon Labs CIP-51 device, or add an
    :class:`MCS51Device` to the machine, which sets it for you.

    ``sfr_page``, ``sfr_paged_lo`` and ``sfr_paged_hi`` are not the
    hardware's either: they page SFRs on a device that pages them (see
    :class:`~smallworld.platforms.defs.mcs51.MCS51SFRPaging`).  An
    :class:`MCS51Device` sets them; leave them alone.
    """

    platform = platforms.Platform(platforms.Architecture.MCS51, platforms.Byteorder.BIG)

    def __init__(self):
        super().__init__()
        self.pc = state.Register("pc", 2)
        self.add(self.pc)
        # SP is an 8-bit index into internal RAM.
        self.sp = state.Register("sp", 1)
        self.add(self.sp)
        self.acc = state.Register("acc", 1)
        self.add(self.acc)
        self.a = state.RegisterAlias("a", self.acc, 1, 0)
        self.add(self.a)
        self.b = state.Register("b", 1)
        self.add(self.b)
        self.psw = state.Register("psw", 1)
        self.add(self.psw)
        self.dptr = state.Register("dptr", 2)
        self.add(self.dptr)
        self.dph = state.RegisterAlias("dph", self.dptr, 1, 1)
        self.add(self.dph)
        self.dpl = state.RegisterAlias("dpl", self.dptr, 1, 0)
        self.add(self.dpl)
        self.xpage_sfr = state.Register("xpage_sfr", 1)
        self.add(self.xpage_sfr)
        self.sfr_page = state.Register("sfr_page", 1)
        self.add(self.sfr_page)
        self.sfr_paged_lo = state.Register("sfr_paged_lo", 8)
        self.add(self.sfr_paged_lo)
        self.sfr_paged_hi = state.Register("sfr_paged_hi", 8)
        self.add(self.sfr_paged_hi)
        for i in range(0, 8):
            reg = state.Register(f"r{i}", 1)
            setattr(self, f"r{i}", reg)
            self.add(reg)


class MCS51Device(state.Stateful):
    """An 8051 device that differs from Intel's 8051 in ways SmallWorld models.

    Add one to a machine, beside the CPU, to emulate the device: it sets the
    CPU's ``xpage_sfr`` to the SFR that pages the device's MOVX @Ri (see
    :func:`~smallworld.platforms.defs.mcs51.mcs51_xpage_sfr`), and makes
    the emulator take the device's interrupts (see
    :func:`~smallworld.platforms.defs.mcs51.mcs51_interrupts`) instead of
    the 8052's.  Do not set the CPU's ``xpage_sfr`` as well: which would win
    is undefined.

    For a device whose interrupts SmallWorld has no table of, the emulator
    takes the 8052's, which most devices have among theirs; ``interrupts``
    says which it takes, and a warning is logged.

    A device that pages its SFRs, as Silicon Labs' larger devices do, has
    them paged too (see
    :func:`~smallworld.platforms.defs.mcs51.mcs51_sfr_paging`); its pages
    are in the SFR space, above page 0.  For one whose paging SmallWorld has
    no table of, SFRs are not paged, and a warning is logged.
    ``sfr_paging`` says which.

    Only the Ghidra and angr emulators can emulate a device.

    Arguments:
        device: The device's part number, such as ``C8051F330``; case and
            suffixes, such as a package code, are ignored.

    Raises:
        ValueError: If SmallWorld does not know the device's paging SFR.
    """

    def __init__(self, device: str):
        self.device = device
        self.xpage_sfr = mcs51_xpage_sfr(device)
        try:
            self.interrupts = mcs51_interrupts(device)
        except ValueError:
            logger.warning(
                f"no table of the interrupts of 8051 device {device}; "
                "taking the 8052's"
            )
            self.interrupts = MCS51Interrupt
        try:
            self.sfr_paging = mcs51_sfr_paging(device)
        except ValueError as e:
            logger.warning(f"{e}; its SFRs are not paged")
            self.sfr_paging = None

    def extract(self, emulator: emulators.Emulator) -> None:
        # Nothing about the device changes as it runs.
        pass

    def apply(self, emulator: emulators.Emulator) -> None:
        machdef: typing.Any = getattr(emulator, "machdef", None)
        set_interrupt_sources = getattr(machdef, "set_interrupt_sources", None)
        if set_interrupt_sources is None:
            raise exceptions.ConfigurationError(
                f"{type(emulator).__name__} cannot emulate 8051 devices"
            )
        emulator.write_register("xpage_sfr", self.xpage_sfr)
        set_interrupt_sources(emulator, self.interrupts)
        if self.sfr_paging is not None:
            machdef.set_sfr_paging(emulator, self.sfr_paging)
