import argparse
import enum
import struct


class Bits(enum.Enum):
    B32 = 1
    B64 = 2


class Byteorder(enum.Enum):
    LITTLE = 1
    BIG = 2


class ABI(enum.Enum):
    SYSTEM_V = 0x00
    HP_UX = 0x01
    NETBSD = 0x02
    LINUX = 0x03


class ISA(enum.Enum):
    NONE = 0x00  # No specific instruction set
    X86 = 0x03  # x86
    X86_64 = 0x3E  # AMD x86-64
    ARM = 0x28  # Arm (up to Armv7/AArch32)
    ARM_64 = 0xB7  # Arm 64-bits (Armv8/AArch64)
    MIPS = 0x08  # MIPS
    MIPSX = 0x33  # Stanford MIPS-X
    PPC = 0x14  # PowerPC
    PPC_64 = 0x15  # PowerPC (64-bit)
    SPARC = 0x02  # SPARC
    SPARC9 = 0x2B  # SPARC Version 9
    IA64 = 0x32  # IA-64


def build(bits: Bits, byteorder: Byteorder, abi: ABI, isa: ISA, entry: int) -> bytes:
    """Generate a minimal ELF of the given parameters.

    Arguments:
        bits: 32 or 64 bit.
        byteorder: Endianness.
        abi: The system ABI.
        isa: Instruction set architecture.
        entry: Entrypoint address.

    Returns:
        The bytes of an ELF file with the given parameters.
    """

    pack = "<" if byteorder is Byteorder.LITTLE else ">"
    CHAR = f"{pack}b"
    WORD = f"{pack}h"
    DWORD = f"{pack}i"
    QWORD = f"{pack}q"

    # Magic.
    elf = b"\x7f\x45\x4c\x46"

    # Mode.
    elf += struct.pack(CHAR, bits.value)

    # Byteorder.
    elf += struct.pack(CHAR, byteorder.value)

    # Version (1 = ELF).
    elf += struct.pack(CHAR, 1)

    # ABI.
    elf += struct.pack(CHAR, abi.value)

    # ABI Version.
    elf += struct.pack(CHAR, 0)

    # Padding (Unused).
    elf += 7 * b"\x00"

    # Type (Executable).
    elf += struct.pack(WORD, 2)

    # ISA.
    elf += struct.pack(WORD, isa.value)

    # Version (1 = ELF).
    elf += struct.pack(DWORD, 1)

    # Entry.
    elf += struct.pack(DWORD if bits is Bits.B32 else QWORD, entry)

    # Program Header Table Offset (fixed based on program bits).
    elf += struct.pack(
        DWORD if bits is Bits.B32 else QWORD, 0x34 if bits is Bits.B32 else 0x40
    )

    # Section Header Table Offset.
    elf += struct.pack(DWORD if bits is Bits.B32 else QWORD, 0)

    # Arch Specific.
    elf += struct.pack(DWORD, 0)

    # Header Size (fixed based on program bits).
    elf += struct.pack(WORD, 52 if bits is Bits.B32 else 64)

    # Header Table Entry Size (fixed based on program bits).
    elf += struct.pack(WORD, 0x20 if bits is Bits.B32 else 0x38)

    # Header Table Entries (1).
    elf += struct.pack(WORD, 1)

    # Section Table Entry Size (fixed based on program bits).
    elf += struct.pack(WORD, 0x28 if bits is Bits.B32 else 0x40)

    # Section Table Entries (0).
    elf += struct.pack(WORD, 0)

    # Section Table Name Index (0).
    elf += struct.pack(WORD, 0)

    # Program Header Type (PT_LOAD).
    elf += struct.pack(DWORD, 1)

    # Segment Permissions on 64 bit (RWX).
    if bits is Bits.B64:
        elf += struct.pack(DWORD, 7)

    # Segment Offset (0).
    elf += struct.pack(DWORD if bits is Bits.B32 else QWORD, 0)

    # Segment Virtual Address.
    elf += struct.pack(DWORD if bits is Bits.B32 else QWORD, entry)

    # Reserved.
    elf += struct.pack(DWORD if bits is Bits.B32 else QWORD, 0)

    # Size of image.
    elf += struct.pack(DWORD if bits is Bits.B32 else QWORD, 0)

    # Size of segment.
    elf += struct.pack(DWORD if bits is Bits.B32 else QWORD, 0x1000)

    # Segment Permissions on 32 bit (RWX).
    if bits is Bits.B32:
        elf += struct.pack(DWORD, 7)

    # Alignment (0 = None).
    elf += struct.pack(DWORD if bits is Bits.B32 else QWORD, 0)

    return elf


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="build a minimal ELF stub for starting a GDB session"
    )

    parser.add_argument("-o", "--output", help="output file (default: stdout)")

    arguments = parser.parse_args()

    elf = build(Bits.B64, Byteorder.LITTLE, ABI.SYSTEM_V, ISA.X86_64, 0x5500000000)
    # elf = build(Bits.B32, Byteorder.LITTLE, ABI.SYSTEM_V, ISA.X86, 0x550000)

    with open(arguments.output, "wb") as f:
        f.write(elf)
