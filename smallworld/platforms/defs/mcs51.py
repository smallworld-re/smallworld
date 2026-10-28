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


#: PSW's parity flag, P: set when the accumulator holds an odd number of ones.
#: The hardware recomputes it from ACC on every cycle, so it is read-only.
MCS51_PSW_PARITY = 0x01


def mcs51_psw_with_parity(psw: int, acc: int) -> int:
    """PSW with its parity flag recomputed from the accumulator."""
    return (psw & ~MCS51_PSW_PARITY) | (bin(acc & 0xFF).count("1") & 1)
