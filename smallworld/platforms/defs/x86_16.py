import capstone

from ..platforms import Architecture, Byteorder
from .i386 import I386
from .platformdef import PlatformDef, RegisterDef


class X86RealMode(PlatformDef):
    """16-bit x86 in real mode.

    The register file is the 80386's, since real-mode code may use the
    32-bit registers through the operand-size prefix.

    ``pc`` is the linear address of the next instruction, ``cs * 16 + ip``.
    Code bounds, exit points, hooks and memory maps are all linear, so this
    is the address the rest of SmallWorld works with. It is a register of
    its own rather than an alias of ``eip``, which holds only the offset
    into the code segment.
    """

    architecture = Architecture.X86_16
    byteorder = Byteorder.LITTLE
    ghidra_language_id = "x86:LE:16:Real Mode"
    status_register = "eflags"

    # Near pointers are 16-bit offsets into a segment.
    address_size = 2

    capstone_arch = capstone.CS_ARCH_X86
    capstone_mode = capstone.CS_MODE_16

    conditional_branch_mnemonics = I386.conditional_branch_mnemonics
    compare_branch_mnemonics = I386.compare_branch_mnemonics
    compare_mnemonics = I386.compare_mnemonics

    pc_register = "pc"
    sp_register = "sp"

    general_purpose_registers = ["ax", "bx", "cx", "dx", "di", "si"]

    registers = {
        **I386.registers,
        "pc": RegisterDef(name="pc", size=4),
    }
