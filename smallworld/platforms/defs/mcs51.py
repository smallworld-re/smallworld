import dataclasses
import enum
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
            # Not a register of the hardware: the SFR that pages MOVX @Ri; see
            # MCS51_SFR_P2.
            "xpage_sfr": RegisterDef(name="xpage_sfr", size=1),
        }
        for i in range(0, 8):
            self._registers[f"r{i}"] = RegisterDef(name=f"r{i}", size=1)


#: SmallWorld's flat layout of the 8051's address spaces, as
#: (Ghidra space name, flat base address, size).  CODE sits at 0 so that code
#: addresses, exit points and the program counter all agree; the data spaces
#: sit above 64 KiB, where no code address can reach them.
MCS51_ADDRESS_SPACES: typing.Tuple[typing.Tuple[str, int, int], ...] = (
    ("CODE", 0x00000, 0x10000),
    ("EXTMEM", 0x10000, 0x10000),
    ("INTMEM", 0x20000, 0x100),
    ("SFR", 0x20100, 0x100),
    ("BITS", 0x20200, 0x100),
)

#: Flat base addresses, by space, for scripts and tests.
MCS51_CODE_BASE = 0x00000
MCS51_XDATA_BASE = 0x10000
MCS51_IDATA_BASE = 0x20000
MCS51_SFR_BASE = 0x20100
MCS51_BITS_BASE = 0x20200


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


#: SFRs that control interrupts.
MCS51_SFR_TCON = 0x88
MCS51_SFR_SCON = 0x98
MCS51_SFR_IE = 0xA8
MCS51_SFR_IP = 0xB8
MCS51_SFR_T2CON = 0xC8

#: IE's global enable bit, EA.
MCS51_IE_EA = 0x80

#: RETI's opcode.  Ghidra's 8051 language makes RETI a plain return, so
#: SmallWorld recognizes it by its opcode to end an interrupt's service.
MCS51_OPCODE_RETI = 0x32


class MCS51Interrupt(enum.Enum):
    """The 8052's interrupt sources.

    Each is a vector, the SFR holding its request flags, the mask of those
    flags, the flag :func:`mcs51_raise_interrupt` sets, the mask of its
    enable bit in IE (and priority bit in IP), and the flags the CPU clears
    when it vectors to the handler.  Declared in the order the CPU polls them
    within a priority level.

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

    def __init__(
        self,
        vector: int,
        flag_sfr: int,
        flags: int,
        request: int,
        enable: int,
        cleared: int,
    ):
        self.vector = vector
        self.flag_sfr = flag_sfr
        self.flags = flags
        self.request = request
        self.enable = enable
        self.cleared = cleared


def mcs51_interrupt_to_take(
    read_sfr: typing.Callable[[int], int], in_service: typing.Sequence[int]
) -> typing.Optional[typing.Tuple[MCS51Interrupt, int]]:
    """Choose the interrupt the 8051 takes now, if any.

    An interrupt is taken when interrupts are enabled (IE's EA bit), its own
    enable bit in IE and a request flag are set, and its priority in IP beats
    every interrupt in service.  Of those, the higher priority wins, then the
    first in polling order.

    Arguments:
        read_sfr: Reads an SFR, by its address (0x80-0xFF).
        in_service: The priority levels of the interrupts in service: 0 for
            low, 1 for high.

    Returns:
        The interrupt and its priority level, or None.
    """
    ie = read_sfr(MCS51_SFR_IE)
    if not ie & MCS51_IE_EA:
        return None
    ip = read_sfr(MCS51_SFR_IP)
    current = max(in_service, default=-1)
    chosen: typing.Optional[typing.Tuple[MCS51Interrupt, int]] = None
    for source in MCS51Interrupt:
        if not ie & source.enable or not read_sfr(source.flag_sfr) & source.flags:
            continue
        level = 1 if ip & source.enable else 0
        if level > current and (chosen is None or level > chosen[1]):
            chosen = (source, level)
    return chosen


def mcs51_raise_interrupt(emulator: typing.Any, source: MCS51Interrupt) -> None:
    """Request an 8051 interrupt, as the hardware that raises it would.

    Sets the source's request flag in its SFR: IE0, TF0, IE1 or TF1 in TCON,
    RI in SCON, or TF2 in T2CON.  The CPU takes the interrupt at the next
    instruction boundary, if IE enables it and its priority allows.

    Arguments:
        emulator: The emulator.
        source: The interrupt to request.
    """
    address = MCS51_SFR_BASE + source.flag_sfr
    value = emulator.read_memory(address, 1)[0]
    emulator.write_memory(address, bytes([value | source.request]))


#: The SFRs interrupt servicing reads, TCON through T2CON.  Interrupts are
#: only modeled when they are mapped.
MCS51_INTERRUPT_SFRS = (MCS51_SFR_TCON, MCS51_SFR_T2CON + 1)


@dataclasses.dataclass(frozen=True)
class MCS51InterruptState:
    """What an 8051 tracks about interrupts that no register shows."""

    in_service: typing.Tuple[int, ...] = ()
    """The priority levels of the interrupts in service, oldest first."""

    previous: typing.Optional[typing.Tuple[int, int, int]] = None
    """The opcode of the instruction now executing, and IE and IP before it."""


def mcs51_service_interrupts(
    state: MCS51InterruptState,
    pc: int,
    read_sfr: typing.Callable[[int], int],
    read_code: typing.Callable[[int], int],
    last: typing.Optional[int] = None,
    take: bool = True,
) -> typing.Tuple[MCS51InterruptState, typing.Optional[MCS51Interrupt]]:
    """Decide, between two instructions, whether the 8051 takes an interrupt.

    Called at every instruction boundary.  The instruction just executed
    ends an interrupt's service if it was RETI; then, as on hardware, no
    interrupt is taken if it was RETI or wrote IE or IP, so at least one more
    instruction runs first.  Otherwise the CPU takes the interrupt
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

    Returns:
        The state for the next boundary, and the interrupt to take, if any.
    """
    ie = read_sfr(MCS51_SFR_IE)
    ip = read_sfr(MCS51_SFR_IP)
    in_service = state.in_service
    hold = not take
    if take and state.previous is not None:
        opcode, previous_ie, previous_ip = state.previous
        if opcode == MCS51_OPCODE_RETI:
            in_service = in_service[:-1]
            hold = True
        if ie != previous_ie or ip != previous_ip:
            hold = True

    taken = None if hold else mcs51_interrupt_to_take(read_sfr, in_service)
    if taken is not None:
        source, level = taken
        in_service = in_service + (level,)
        last = source.vector
    elif last is None:
        last = pc
    return (
        MCS51InterruptState(in_service, (read_code(last), ie, ip)),
        None if taken is None else taken[0],
    )
