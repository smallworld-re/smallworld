import dataclasses
import enum
import re
import typing

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef


class MCS51(PlatformDef):
    """Platform definition for the Intel MCS-51 (8051) family.

    The 8051 is a Harvard machine with several overlapping address spaces:
    64 KiB of code, 64 KiB of external data (XDATA), 256 bytes of internal
    RAM, and the special function registers (SFRs) and bit-addressable memory
    layered over parts of internal RAM.  SmallWorld lays these out side by
    side in one flat address map (see :data:`MCS51_ADDRESS_SPACES`), so
    ``address_size`` is the CPU's pointer width, not the width of that map.
    """

    architecture = Architecture.MCS51
    byteorder = Byteorder.BIG
    ghidra_language_id = "8051:BE:16:default"
    address_size = 2

    # Not supported by capstone
    capstone_arch = -1
    capstone_mode = -1

    conditional_branch_mnemonics = {
        "jc",
        "jnc",
        "jz",
        "jnz",
        "jb",
        "jnb",
        "jbc",
        "cjne",
        "djnz",
    }
    compare_mnemonics = {"cjne"}
    compare_branch_mnemonics = {"cjne", "djnz", "jz", "jnz", "jb", "jnb", "jbc"}
    status_register = "psw"

    pc_register = "pc"
    sp_register = "sp"

    # R0-R7 are the working registers of the current register bank.
    general_purpose_registers = [f"r{i}" for i in range(0, 8)]

    @property
    def registers(self) -> typing.Dict[str, RegisterDef]:
        return self._registers

    def __init__(self):
        self._registers: typing.Dict[str, RegisterDef] = {
            "pc": RegisterDef(name="pc", size=2),
            # SP is an 8-bit index into internal RAM.
            "sp": RegisterDef(name="sp", size=1),
            "acc": RegisterDef(name="acc", size=1),
            "a": RegisterAliasDef(name="a", parent="acc", size=1, offset=0),
            "b": RegisterDef(name="b", size=1),
            "psw": RegisterDef(name="psw", size=1),
            "dptr": RegisterDef(name="dptr", size=2),
            "dph": RegisterAliasDef(name="dph", parent="dptr", size=1, offset=1),
            "dpl": RegisterAliasDef(name="dpl", parent="dptr", size=1, offset=0),
            # Not registers of the hardware: the SFR that pages MOVX @Ri (see
            # MCS51_SFR_P2), and SFR paging (see MCS51SFRPaging).
            "xpage_sfr": RegisterDef(name="xpage_sfr", size=1),
            "sfr_page": RegisterDef(name="sfr_page", size=1),
            "sfr_paged_lo": RegisterDef(name="sfr_paged_lo", size=8),
            "sfr_paged_hi": RegisterDef(name="sfr_paged_hi", size=8),
        }
        for i in range(0, 8):
            self._registers[f"r{i}"] = RegisterDef(name=f"r{i}", size=1)


#: SmallWorld's flat layout of the 8051's address spaces, as
#: (Ghidra space name, flat base address, size).  CODE sits at 0 so that code
#: addresses, exit points and the program counter all agree; the data spaces
#: sit above 64 KiB, where no code address can reach them.
#:
#: SFRs are in PSFR, SmallWorld's SFR space, which has a page for each value
#: of a Silicon Labs device's SFRPAGE: SFR ``sfr`` on page ``page`` is at
#: ``MCS51_SFR_BASE + (page << 8) + sfr``.  SFRs that are not paged, as none
#: are on most devices, are on page 0.
MCS51_ADDRESS_SPACES: typing.Tuple[typing.Tuple[str, int, int], ...] = (
    ("CODE", 0x00000, 0x10000),
    ("EXTMEM", 0x10000, 0x10000),
    ("INTMEM", 0x20000, 0x100),
    ("PSFR", 0x20100, 0x10000),
    ("BITS", 0x30100, 0x100),
)

#: Flat base addresses, by space, for scripts and tests.
MCS51_CODE_BASE = 0x00000
MCS51_XDATA_BASE = 0x10000
MCS51_IDATA_BASE = 0x20000
MCS51_SFR_BASE = 0x20100
MCS51_BITS_BASE = 0x30100


def mcs51_return_address(emulator: typing.Any, pop: bool = False) -> int:
    """Read the return address an 8051 call left on the stack.

    LCALL and ACALL push the return address low byte first onto a stack that
    grows up through internal RAM, so SP points at its high byte.  SP is an
    offset into internal RAM, not a flat address.

    Arguments:
        emulator: The emulator to read from.
        pop: Whether to also pop the return address, as RET does.

    Returns:
        The return address.
    """
    sp = emulator.read_register("sp")
    ret = int.from_bytes(emulator.read_memory(MCS51_IDATA_BASE + sp - 1, 2), "little")
    if pop:
        emulator.write_register("sp", (sp - 2) & 0xFF)
    return ret


#: R0-R7 are a bank of eight bytes in internal RAM; PSW's RS1 and RS0 bits
#: select one of four banks, at internal RAM 0x00, 0x08, 0x10 and 0x18.
MCS51_PSW_BANK_SELECT = 0x18
MCS51_PSW_BANK_SHIFT = 3
MCS51_REGISTER_BANKS_SIZE = 0x20

#: PSW's parity flag, P: set when the accumulator holds an odd number of ones.
#: The hardware recomputes it from ACC on every cycle, so it is read-only.
MCS51_PSW_PARITY = 0x01


def mcs51_psw_with_parity(psw: int, acc: int) -> int:
    """PSW with its parity flag recomputed from the accumulator."""
    return (psw & ~MCS51_PSW_PARITY) | (bin(acc & 0xFF).count("1") & 1)


#: P2, the SFR that supplies the high byte of MOVX @Ri's address on Intel's
#: 8051, and the default of the ``xpage_sfr`` register, which names that SFR.
#: Silicon Labs' CIP-51 devices page MOVX @Ri through their EMI0CN instead:
#: set ``xpage_sfr`` to its address (SDCC's device headers declare it as
#: ``_XPAGE``) to emulate one.
MCS51_SFR_P2 = 0xA0

#: The SFR that pages MOVX @Ri, by device family, for :func:`mcs51_xpage_sfr`:
#: (pattern of part numbers, SFR address).  Taken from the ``_XPAGE``
#: declarations in SDCC 4.6's device headers.
_MCS51_XPAGE_SFRS: typing.Tuple[typing.Tuple[str, int], ...] = (
    # Silicon Labs CIP-51: EMI0CN.
    (r"C8051F0[0-2]\d", 0xAF),
    (r"C8051F2\d\d", 0xAF),
    (r"C8051F0[46]\d", 0xA2),
    (r"C8051F1[23]\d", 0xA2),
    (r"C8051F3[1-6]\d", 0xAA),
    (r"C8051F41\d", 0xAA),
    (r"C8051F9[23]\d", 0xAA),
    (r"C8051T6[13]\d", 0xAA),
    # Axsem: XPAGE.
    (r"AX8052", 0xD9),
    # Chipcon and Texas Instruments: MPAGE.
    (r"CC(1110|2430|251[01]|253\d)", 0x93),
    (r"MSC12\d\d", 0x92),
    # Infineon: XADDRH, which shares its address with SFRs on other SFR
    # pages; SmallWorld does not model SFR pages.
    (r"XC866", 0xB3),
)


def mcs51_xpage_sfr(device: str) -> int:
    """The SFR that pages MOVX @Ri on an 8051 device, for ``xpage_sfr``.

    Many 8051 derivatives page MOVX @Ri through an SFR of their own instead
    of P2 - Silicon Labs' CIP-51 devices through EMI0CN, for one.  To
    emulate one, set the CPU's ``xpage_sfr`` register to this::

        cpu.xpage_sfr.set(mcs51_xpage_sfr("C8051F330"))

    A program built with SDCC records the same address in its linker map, as
    ``__XPAGE``; see :attr:`~smallworld.state.memory.ihex.IHexExecutable.xpage_sfr`.

    Arguments:
        device: The device's part number, such as ``C8051F330``, ``CC2530``
            or ``XC866``; case and suffixes, such as a package code, are
            ignored.

    Returns:
        The address of the SFR in the SFR space.

    Raises:
        ValueError: If the device is not one SmallWorld knows.  Intel's 8051
            and the many derivatives that keep its P2 paging are not listed:
            leave ``xpage_sfr`` unset for those.
    """
    for pattern, sfr in _MCS51_XPAGE_SFRS:
        if re.match(pattern, device, re.IGNORECASE):
            return sfr
    raise ValueError(
        f"unknown 8051 device {device}: set xpage_sfr to the address of the SFR "
        "that pages MOVX @Ri, which SDCC's device header declares as _XPAGE"
    )


def mcs51_pdata_page(emulator: typing.Any) -> int:
    """The page of XDATA that MOVX @Ri reaches now: pdata.

    It is the value of the SFR the ``xpage_sfr`` register names - P2 on
    Intel's 8051, EMI0CN on Silicon Labs' CIP-51 devices.

    Arguments:
        emulator: The emulator to read from.

    Returns:
        The page, the high byte of the XDATA address.
    """
    sfr = emulator.read_register("xpage_sfr")
    return emulator.read_memory(MCS51_SFR_BASE + sfr, 1)[0]


@dataclasses.dataclass(frozen=True)
class MCS51SFRPaging:
    """How an 8051 device pages its SFRs, as Silicon Labs' larger devices do.

    The SFRPAGE SFR selects the page through which the CPU reaches most
    SFRs, so that one address holds a different SFR on each page; the SFRs in
    ``shared`` are the same on every page.  SmallWorld keeps each page's SFRs
    in its own 256 bytes of SFR space (see :data:`MCS51_ADDRESS_SPACES`), and
    the shared ones on page 0.

    The device also keeps a stack of pages: taking an interrupt pushes
    SFRPAGE onto SFRNEXT, and SFRNEXT onto SFRLAST, and selects the
    interrupt's page, the page of its request flags; RETI pops it.  It does
    so only while the bits ``stack_enable`` names are set.

    Addresses are SFR addresses, with the page above them where it matters:
    ``0xF96`` is SFR 0x96 on page 0xF.
    """

    sfrpage: int
    """SFRPAGE's address."""

    sfrnext: int
    """SFRNEXT's address."""

    sfrlast: int
    """SFRLAST's address."""

    stack_enable: typing.Tuple[int, int]
    """The SFR, and the mask of its bits, that enable the page stack."""

    shared: typing.FrozenSet[int]
    """The SFRs that are on every page."""

    def paged_masks(self) -> typing.Tuple[int, int]:
        """The ``sfr_paged_lo`` and ``sfr_paged_hi`` registers' values.

        Bit n of the first is set when SFR 0x80 + n is paged; bit n of the
        second, when SFR 0xC0 + n is.
        """
        lo = sum(1 << n for n in range(0x40) if 0x80 + n not in self.shared)
        hi = sum(1 << n for n in range(0x40) if 0xC0 + n not in self.shared)
        return lo, hi


#: The C8051F04x's SFR paging, from SDCC 4.6's C8051F040.h, which lists these
#: SFRs under "All Pages" and every other SFR under a page of its own; its
#: C8051F060.h lists the same for the C8051F06x.  The headers do not say which
#: bit of SFRPGCN enables the page stack; SmallWorld takes it to be bit 0,
#: SFRPGEN.
MCS51_C8051F04X_SFR_PAGING = MCS51SFRPaging(
    sfrpage=0x84,
    sfrnext=0x85,
    sfrlast=0x86,
    stack_enable=(0xF96, 0x01),
    shared=frozenset(
        {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x90, 0xA0, 0xA8}
        | {0xB0, 0xB8, 0xD0, 0xE0, 0xE6, 0xE7, 0xF0, 0xF6, 0xF7, 0xFF}
    ),
)

#: The C8051F12x's and F13x's SFR paging: the C8051F04x's, with PSBANK, the
#: flash bank select, on every page too, as SDCC 4.6's C8051F120.h lists it.
MCS51_C8051F12X_SFR_PAGING = dataclasses.replace(
    MCS51_C8051F04X_SFR_PAGING,
    shared=MCS51_C8051F04X_SFR_PAGING.shared | {0xB1},
)

#: The C8051F36x's SFR paging, from SDCC 4.6's C8051F360.h, which lists these
#: SFRs under "All Pages" and every other SFR on page 0 or 0x0F.  SFRPAGE is
#: at 0xA7, and SFR0CN, on page 0x0F, controls the page stack.  SmallWorld
#: takes the stack to work as the C8051F04x's does, enabled by SFR0CN's bit
#: 0; the header says neither.
MCS51_C8051F36X_SFR_PAGING = MCS51SFRPaging(
    sfrpage=0xA7,
    sfrnext=0x85,
    sfrlast=0x86,
    stack_enable=(0xFE5, 0x01),
    shared=frozenset(
        {0x80, 0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B}
        | {0x8C, 0x8D, 0x8E, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97}
        | {0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2}
        | {0xA3, 0xA7, 0xA8, 0xAA, 0xB0, 0xB5, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC}
        | {0xBD, 0xBE, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC8, 0xCA}
        | {0xCB, 0xCC, 0xCD, 0xD0, 0xD1, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD}
        | {0xDE, 0xDF, 0xE0, 0xE4, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC}
        | {0xED, 0xEE, 0xEF, 0xF0, 0xF5, 0xF6, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC}
        | {0xFD, 0xFE, 0xFF}
    ),
)

#: SFR paging, by device family, for :func:`mcs51_sfr_paging`: (pattern of
#: part numbers, paging).
_MCS51_SFR_PAGING: typing.Tuple[typing.Tuple[str, MCS51SFRPaging], ...] = (
    (r"C8051F0[46]\d", MCS51_C8051F04X_SFR_PAGING),
    (r"C8051F1[23]\d", MCS51_C8051F12X_SFR_PAGING),
    (r"C8051F36\d", MCS51_C8051F36X_SFR_PAGING),
)

#: Devices that page their SFRs in ways SmallWorld has no table of.
_MCS51_SFR_PAGING_UNKNOWN = (r"C8051F9[23]\d",)


def mcs51_sfr_paging(device: str) -> typing.Optional[MCS51SFRPaging]:
    """How an 8051 device pages its SFRs.

    Arguments:
        device: The device's part number, such as ``C8051F040``; case and
            suffixes, such as a package code, are ignored.

    Returns:
        The device's SFR paging, or None if it does not page its SFRs.

    Raises:
        ValueError: If the device pages its SFRs, but SmallWorld has no table
            of how.
    """
    for pattern, paging in _MCS51_SFR_PAGING:
        if re.match(pattern, device, re.IGNORECASE):
            return paging
    for pattern in _MCS51_SFR_PAGING_UNKNOWN:
        if re.match(pattern, device, re.IGNORECASE):
            raise ValueError(
                f"8051 device {device} pages its SFRs, which SmallWorld has no "
                "table of"
            )
    return None


def mcs51_push_sfr_page(
    paging: MCS51SFRPaging,
    read_sfr: typing.Callable[[int], int],
    write_sfr: typing.Callable[[int, int], None],
    page: int,
) -> bool:
    """Push the SFR page stack, as taking an interrupt does.

    Arguments:
        paging: The device's SFR paging.
        read_sfr: Reads an SFR, by its address (with its page above it).
        write_sfr: Writes an SFR, by its address and value.
        page: The interrupt's page.

    Returns:
        Whether the stack is enabled, and so was pushed.
    """
    sfr, mask = paging.stack_enable
    if not read_sfr(sfr) & mask:
        return False
    write_sfr(paging.sfrlast, read_sfr(paging.sfrnext))
    write_sfr(paging.sfrnext, read_sfr(paging.sfrpage))
    write_sfr(paging.sfrpage, page)
    return True


def mcs51_pop_sfr_page(
    paging: MCS51SFRPaging,
    read_sfr: typing.Callable[[int], int],
    write_sfr: typing.Callable[[int, int], None],
) -> bool:
    """Pop the SFR page stack, as RETI does.

    Arguments:
        paging: The device's SFR paging.
        read_sfr: Reads an SFR, by its address (with its page above it).
        write_sfr: Writes an SFR, by its address and value.

    Returns:
        Whether the stack is enabled, and so was popped.
    """
    sfr, mask = paging.stack_enable
    if not read_sfr(sfr) & mask:
        return False
    write_sfr(paging.sfrpage, read_sfr(paging.sfrnext))
    write_sfr(paging.sfrnext, read_sfr(paging.sfrlast))
    return True


@dataclasses.dataclass(frozen=True)
class MCS51FlashProgramming:
    """How a Silicon Labs device writes its own flash.

    With PSCTL's PSWE bit set, MOVX writes go to flash - code memory - rather
    than XDATA: a write clears the bits of the flash byte that are clear in
    the byte written, since only erasing sets them, and with PSEE set too,
    erases the whole page holding the byte, setting it to 0xFF.  MOVX reads
    still read XDATA; a program reads flash with MOVC.

    Each write or erase must be unlocked first, by writing 0xA5 then 0xF1 to
    FLKEY; the lock closes again after it.  Writing anything else to FLKEY,
    or writing or erasing flash while it is locked, disables writes and
    erases until reset.  Reading FLKEY reads the lock's state, one of the
    ``MCS51_FLKEY_*`` values.

    Addresses are SFR addresses, with the page above them where it matters.
    """

    psctl: int
    """PSCTL's address."""

    flkey: int
    """FLKEY's address."""

    page_size: int
    """The size of a flash page, which an erase sets to 0xFF."""


#: PSCTL's bits: PSWE, which sends MOVX writes to flash, and PSEE, which makes
#: them erase.
MCS51_PSCTL_PSWE = 0x01
MCS51_PSCTL_PSEE = 0x02

#: The states of the flash lock, as FLKEY reads: locked, with the first key
#: written, unlocked, and disabled until reset.
MCS51_FLKEY_LOCKED = 0
MCS51_FLKEY_FIRST_KEY = 1
MCS51_FLKEY_UNLOCKED = 2
MCS51_FLKEY_DISABLED = 3

#: The C8051F33x's flash programming, from its data sheet, revision 1.7:
#: section 11 and the PSCTL and FLKEY definitions.
MCS51_C8051F33X_FLASH = MCS51FlashProgramming(psctl=0x8F, flkey=0xB7, page_size=512)

#: Flash programming, by device family, for :func:`mcs51_flash_programming`:
#: (pattern of part numbers, flash programming).
_MCS51_FLASH: typing.Tuple[typing.Tuple[str, MCS51FlashProgramming], ...] = (
    (r"C8051F33[0-5]", MCS51_C8051F33X_FLASH),
)


def mcs51_flash_programming(device: str) -> typing.Optional[MCS51FlashProgramming]:
    """How an 8051 device writes its own flash.

    Arguments:
        device: The device's part number, such as ``C8051F330``; case and
            suffixes, such as a package code, are ignored.

    Returns:
        The device's flash programming, or None if SmallWorld has no table
        of it.
    """
    for pattern, flash in _MCS51_FLASH:
        if re.match(pattern, device, re.IGNORECASE):
            return flash
    return None


def mcs51_flash_owns_store(
    flash: MCS51FlashProgramming,
    address: int,
    read_memory: typing.Callable[[int, int], bytes],
) -> bool:
    """Whether a store is the flash's to perform: see :func:`mcs51_flash_store`.

    Arguments:
        flash: The device's flash programming.
        address: The flat address stored to.
        read_memory: Reads memory, by flat address and size.
    """
    if address == MCS51_SFR_BASE + flash.flkey:
        return True
    return MCS51_XDATA_BASE <= address < MCS51_XDATA_BASE + 0x10000 and bool(
        read_memory(MCS51_SFR_BASE + flash.psctl, 1)[0] & MCS51_PSCTL_PSWE
    )


def mcs51_flash_store(
    flash: MCS51FlashProgramming,
    address: int,
    value: int,
    read_memory: typing.Callable[[int, int], bytes],
    write_memory: typing.Callable[[int, bytes], None],
) -> None:
    """Perform a store the flash owns, as the device does.

    A store to FLKEY advances the lock, and leaves FLKEY reading its state.
    A MOVX write, while PSWE is set, writes or erases flash if the lock is
    open, and closes it, or else disables writes and erases until reset.

    Arguments:
        flash: The device's flash programming.
        address: The flat address stored to, one
            :func:`mcs51_flash_owns_store` says the flash owns.
        value: The byte stored.
        read_memory: Reads memory, by flat address and size.
        write_memory: Writes memory, by flat address and content.
    """
    flkey = MCS51_SFR_BASE + flash.flkey
    lock = read_memory(flkey, 1)[0] & 0x03
    if address == flkey:
        if lock == MCS51_FLKEY_LOCKED and value == 0xA5:
            lock = MCS51_FLKEY_FIRST_KEY
        elif lock == MCS51_FLKEY_FIRST_KEY and value == 0xF1:
            lock = MCS51_FLKEY_UNLOCKED
        else:
            lock = MCS51_FLKEY_DISABLED
        write_memory(flkey, bytes([lock]))
        return
    if lock != MCS51_FLKEY_UNLOCKED:
        write_memory(flkey, bytes([MCS51_FLKEY_DISABLED]))
        return
    offset = address - MCS51_XDATA_BASE
    if read_memory(MCS51_SFR_BASE + flash.psctl, 1)[0] & MCS51_PSCTL_PSEE:
        page = offset - offset % flash.page_size
        write_memory(MCS51_CODE_BASE + page, bytes([0xFF]) * flash.page_size)
    else:
        old = read_memory(MCS51_CODE_BASE + offset, 1)[0]
        write_memory(MCS51_CODE_BASE + offset, bytes([old & value]))
    write_memory(flkey, bytes([MCS51_FLKEY_LOCKED]))


#: SFRs that control interrupts.
MCS51_SFR_TCON = 0x88
MCS51_SFR_SCON = 0x98
MCS51_SFR_IE = 0xA8
MCS51_SFR_IP = 0xB8
MCS51_SFR_T2CON = 0xC8

#: SFRs of Silicon Labs' CIP-51 devices that control interrupts.
MCS51_SFR_EIE1 = 0xE6
MCS51_SFR_EIP1 = 0xF6

#: IE's global enable bit, EA.
MCS51_IE_EA = 0x80

#: RETI's opcode.  Ghidra's 8051 language makes RETI a plain return, so
#: SmallWorld recognizes it by its opcode to end an interrupt's service.
MCS51_OPCODE_RETI = 0x32


class MCS51InterruptSource(enum.Enum):
    """Base for the interrupt sources of an 8051 device.

    Each subclass lists one device's sources, in the order the CPU polls them
    within a priority level.  Each source is a vector; the SFR holding its
    request flags, the mask of those flags (``pending_flags``), and the flag
    :func:`mcs51_raise_interrupt` sets; the mask of its enable bit; the flags
    the CPU clears when it vectors to the handler; the SFRs that hold its
    enable bit and its priority bit, at the same position, by default IE and
    IP; and its gates.

    A gate is a mask of request flags, an SFR and a mask of bits in it: those
    flags request the interrupt only while one of those bits is set, as a
    timer's low-byte overflow flag does only while its own enable bit is.
    """

    def __init__(
        self,
        vector: int,
        flag_sfr: int,
        flags: int,
        request: int,
        enable: int,
        cleared: int,
        enable_sfr: int = MCS51_SFR_IE,
        priority_sfr: int = MCS51_SFR_IP,
        gates: typing.Tuple[typing.Tuple[int, int, int], ...] = (),
    ):
        self.vector = vector
        self.flag_sfr = flag_sfr
        self.pending_flags = flags
        self.request = request
        self.enable = enable
        self.cleared = cleared
        self.enable_sfr = enable_sfr
        self.priority_sfr = priority_sfr
        self.gates = gates

    def pending(self, read_sfr: typing.Callable[[int], int]) -> bool:
        """Whether the source requests its interrupt.

        Arguments:
            read_sfr: Reads an SFR, by its address (0x80-0xFF).
        """
        requested = read_sfr(self.flag_sfr) & self.pending_flags
        for gated, sfr, mask in self.gates:
            if requested & gated and not read_sfr(sfr) & mask:
                requested &= ~gated
        return bool(requested)


class MCS51Interrupt(MCS51InterruptSource):
    """The 8052's interrupt sources.

    The external interrupts' flags are cleared on vectoring whether they are
    edge- or level-triggered: SmallWorld has no pins, so a level-triggered
    request does not stay asserted as a held-down pin would.
    """

    EXTERNAL0 = (0x03, MCS51_SFR_TCON, 0x02, 0x02, 0x01, 0x02)
    TIMER0 = (0x0B, MCS51_SFR_TCON, 0x20, 0x20, 0x02, 0x20)
    EXTERNAL1 = (0x13, MCS51_SFR_TCON, 0x08, 0x08, 0x04, 0x08)
    TIMER1 = (0x1B, MCS51_SFR_TCON, 0x80, 0x80, 0x08, 0x80)
    SERIAL = (0x23, MCS51_SFR_SCON, 0x03, 0x01, 0x10, 0x00)
    TIMER2 = (0x2B, MCS51_SFR_T2CON, 0xC0, 0x80, 0x20, 0x00)


# The C8051F33x's peripheral SFRs that hold request flags or gate them.
_F33X_TMR3CN = 0x91
_F33X_CPT0CN = 0x9B
_F33X_CPT0MD = 0x9D
_F33X_SMB0CN = 0xC0
_F33X_PCA0CN = 0xD8
_F33X_PCA0MD = 0xD9
_F33X_PCA0CPM0 = 0xDA
_F33X_ADC0CN = 0xE8
_F33X_SPI0CN = 0xF8
_EIE1 = MCS51_SFR_EIE1
_EIP1 = MCS51_SFR_EIP1


class C8051F33xInterrupt(MCS51InterruptSource):
    """The interrupt sources of Silicon Labs' C8051F330-F335.

    From the C8051F33x data sheet, revision 1.7: Table 9.4, the IE, IP, EIE1
    and EIP1 definitions, and the peripherals' flag and enable bits.  The
    first five are the 8052's, UART0 included; Timer 2's low-byte flag,
    TF2L, requests only while TF2LEN is set.  Vectors 0x43 and 0x6B are
    reserved.  As with the 8052, the external interrupts' flags are cleared
    on vectoring even when level-triggered.
    """

    EXTERNAL0 = MCS51Interrupt.EXTERNAL0.value
    TIMER0 = MCS51Interrupt.TIMER0.value
    EXTERNAL1 = MCS51Interrupt.EXTERNAL1.value
    TIMER1 = MCS51Interrupt.TIMER1.value
    UART0 = MCS51Interrupt.SERIAL.value
    # TF2H and TF2L in TMR2CN, at T2CON's address; TF2L gated by TF2LEN.
    TIMER2 = (
        0x2B,
        MCS51_SFR_T2CON,
        0xC0,
        0x80,
        0x20,
        0x00,
        MCS51_SFR_IE,
        MCS51_SFR_IP,
        ((0x40, MCS51_SFR_T2CON, 0x20),),
    )
    # SPIF, WCOL, MODF and RXOVRN.
    SPI0 = (0x33, _F33X_SPI0CN, 0xF0, 0x80, 0x40, 0x00)
    # SI.
    SMBUS0 = (0x3B, _F33X_SMB0CN, 0x01, 0x01, 0x01, 0x00, _EIE1, _EIP1)
    # AD0WINT.
    ADC0_WINDOW = (0x4B, _F33X_ADC0CN, 0x08, 0x08, 0x04, 0x00, _EIE1, _EIP1)
    # AD0INT.
    ADC0_CONVERSION = (0x53, _F33X_ADC0CN, 0x20, 0x20, 0x08, 0x00, _EIE1, _EIP1)
    # CF, gated by PCA0MD's ECF, and CCF0-CCF2, each gated by its module's
    # ECCFn in PCA0CPMn.
    PCA0 = (
        0x5B,
        _F33X_PCA0CN,
        0x87,
        0x80,
        0x10,
        0x00,
        _EIE1,
        _EIP1,
        (
            (0x80, _F33X_PCA0MD, 0x01),
            (0x01, _F33X_PCA0CPM0, 0x01),
            (0x02, _F33X_PCA0CPM0 + 1, 0x01),
            (0x04, _F33X_PCA0CPM0 + 2, 0x01),
        ),
    )
    # CP0FIF and CP0RIF, gated by CPT0MD's CP0FIE and CP0RIE.
    COMPARATOR0 = (
        0x63,
        _F33X_CPT0CN,
        0x30,
        0x20,
        0x20,
        0x00,
        _EIE1,
        _EIP1,
        ((0x10, _F33X_CPT0MD, 0x10), (0x20, _F33X_CPT0MD, 0x20)),
    )
    # TF3H and TF3L; TF3L gated by TF3LEN.
    TIMER3 = (
        0x73,
        _F33X_TMR3CN,
        0xC0,
        0x80,
        0x80,
        0x00,
        _EIE1,
        _EIP1,
        ((0x40, _F33X_TMR3CN, 0x20),),
    )


#: The interrupt sources, by device family, for :func:`mcs51_interrupts`:
#: (pattern of part numbers, sources).
_MCS51_INTERRUPTS: typing.Tuple[
    typing.Tuple[str, typing.Type[MCS51InterruptSource]], ...
] = ((r"C8051F33[0-5]", C8051F33xInterrupt),)


def mcs51_interrupts(device: str) -> typing.Type[MCS51InterruptSource]:
    """The interrupt sources of an 8051 device.

    Arguments:
        device: The device's part number, such as ``C8051F330``; case and
            suffixes, such as a package code, are ignored.

    Returns:
        The device's sources, an :class:`MCS51InterruptSource` subclass.

    Raises:
        ValueError: If SmallWorld has no table of the device's sources.
    """
    for pattern, sources in _MCS51_INTERRUPTS:
        if re.match(pattern, device, re.IGNORECASE):
            return sources
    raise ValueError(f"no table of the interrupt sources of 8051 device {device}")


def mcs51_interrupt_to_take(
    read_sfr: typing.Callable[[int], int],
    in_service: typing.Sequence[int],
    sources: typing.Type[MCS51InterruptSource] = MCS51Interrupt,
) -> typing.Optional[typing.Tuple[MCS51InterruptSource, int]]:
    """Choose the interrupt the 8051 takes now, if any.

    An interrupt is taken when interrupts are enabled (IE's EA bit), its own
    enable bit is set, it is pending (see :meth:`MCS51InterruptSource.pending`),
    and its priority beats every interrupt in service.  Of those, the higher
    priority wins, then the first in polling order.

    Arguments:
        read_sfr: Reads an SFR, by its address (0x80-0xFF).
        in_service: The priority levels of the interrupts in service: 0 for
            low, 1 for high.
        sources: The device's interrupt sources; by default, the 8052's.

    Returns:
        The interrupt and its priority level, or None.
    """
    if not read_sfr(MCS51_SFR_IE) & MCS51_IE_EA:
        return None
    current = max(in_service, default=-1)
    chosen: typing.Optional[typing.Tuple[MCS51InterruptSource, int]] = None
    for source in sources:
        if not read_sfr(source.enable_sfr) & source.enable or not source.pending(
            read_sfr
        ):
            continue
        level = 1 if read_sfr(source.priority_sfr) & source.enable else 0
        if level > current and (chosen is None or level > chosen[1]):
            chosen = (source, level)
    return chosen


def mcs51_raise_interrupt(emulator: typing.Any, source: MCS51InterruptSource) -> None:
    """Request an 8051 interrupt, as the hardware that raises it would.

    Sets the source's request flag in its SFR: on the 8052, IE0, TF0, IE1 or
    TF1 in TCON, RI in SCON, or TF2 in T2CON.  The CPU takes the interrupt
    at the next instruction boundary, if it is enabled, its gate, if any, is
    open, and its priority allows.

    Arguments:
        emulator: The emulator.
        source: The interrupt to request.
    """
    address = MCS51_SFR_BASE + source.flag_sfr
    value = emulator.read_memory(address, 1)[0]
    emulator.write_memory(address, bytes([value | source.request]))


def mcs51_interrupt_sfrs(
    sources: typing.Type[MCS51InterruptSource],
) -> typing.FrozenSet[int]:
    """The SFRs that decide whether a device's interrupts are taken.

    They are IE, and each source's flag, enable and priority SFRs and the
    SFRs of its gates.  Interrupts are only modeled when they are all
    mapped, and only a write to one of them, or RETI, can make an interrupt
    takeable.

    Arguments:
        sources: The device's interrupt sources.
    """
    sfrs = {MCS51_SFR_IE}
    for source in sources:
        sfrs |= {source.flag_sfr, source.enable_sfr, source.priority_sfr}
        sfrs |= {sfr for _, sfr, _ in source.gates}
    return frozenset(sfrs)


def mcs51_interrupt_control_sfrs(
    sources: typing.Type[MCS51InterruptSource],
) -> typing.FrozenSet[int]:
    """The SFRs that enable a device's interrupts and set their priorities.

    As IE and IP on Intel's 8051, a write to one holds interrupts for one
    instruction.  Silicon Labs' data sheets do not say whether their
    extended enable and priority SFRs do; SmallWorld assumes they do.

    Arguments:
        sources: The device's interrupt sources.
    """
    sfrs = {MCS51_SFR_IE, MCS51_SFR_IP}
    for source in sources:
        sfrs |= {source.enable_sfr, source.priority_sfr}
    return frozenset(sfrs)


@dataclasses.dataclass(frozen=True)
class MCS51InterruptState:
    """What an 8051 tracks about interrupts that no register shows."""

    in_service: typing.Tuple[int, ...] = ()
    """The priority levels of the interrupts in service, oldest first."""

    previous: typing.Optional[typing.Tuple[int, typing.Tuple[int, ...]]] = None
    """The opcode of the instruction now executing, and the values of the
    SFRs that enable interrupts and set their priorities before it, in
    address order (see :func:`mcs51_interrupt_control_sfrs`)."""


def mcs51_service_interrupts(
    state: MCS51InterruptState,
    pc: int,
    read_sfr: typing.Callable[[int], int],
    read_code: typing.Callable[[int], int],
    last: typing.Optional[int] = None,
    take: bool = True,
    sources: typing.Type[MCS51InterruptSource] = MCS51Interrupt,
) -> typing.Tuple[MCS51InterruptState, typing.Optional[MCS51InterruptSource]]:
    """Decide, between two instructions, whether the 8051 takes an interrupt.

    Called at every instruction boundary.  The instruction just executed
    ends an interrupt's service if it was RETI; then, as on hardware, no
    interrupt is taken if it was RETI or wrote IE or IP - or, on a CIP-51,
    another SFR that enables interrupts or sets their priorities - so at
    least one more instruction runs first.  Otherwise the CPU takes the interrupt
    :func:`mcs51_interrupt_to_take` chooses.

    Taking it is the caller's job: push PC as LCALL would, jump to the
    vector, and clear the source's ``cleared`` flags.

    A caller that runs several instructions before the next boundary - a
    block, all but whose last instruction leave interrupts alone - says
    where the last one is.

    Arguments:
        state: The state from the previous boundary.
        pc: The address of the next instruction.
        read_sfr: Reads an SFR, by its address (0x80-0xFF).
        read_code: Reads a byte of code memory.
        last: The address of the last instruction to run before the next
            boundary, if not ``pc``.  Ignored when an interrupt is taken.
        take: False to only record the state, taking no interrupt: for a
            boundary straight after one was taken, before its vector's
            first instruction.
        sources: The device's interrupt sources; by default, the 8052's.

    Returns:
        The state for the next boundary, and the interrupt to take, if any.
    """
    controls = tuple(
        read_sfr(sfr) for sfr in sorted(mcs51_interrupt_control_sfrs(sources))
    )
    in_service = state.in_service
    hold = not take
    if take and state.previous is not None:
        opcode, previous_controls = state.previous
        if opcode == MCS51_OPCODE_RETI:
            in_service = in_service[:-1]
            hold = True
        if controls != previous_controls:
            hold = True

    taken = None if hold else mcs51_interrupt_to_take(read_sfr, in_service, sources)
    if taken is not None:
        source, level = taken
        in_service = in_service + (level,)
        last = source.vector
    elif last is None:
        last = pc
    return (
        MCS51InterruptState(in_service, (read_code(last), controls)),
        None if taken is None else taken[0],
    )
