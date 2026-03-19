import struct
import typing
from dataclasses import dataclass, field


@dataclass(frozen=False)
class ElfSymbol:
    """ELF symbol struct

    Lief parses this data, but I can't keep the objects around.

    This adds one field to the typical ELF symbol, baseaddr.
    ELF symbol values are often relative,
    but relative to what is an annoying question:

    - In non-PIC binaries, the value is relative to zero.
    - In linked PIC binaries, the value is relative to the load address
    - In relocatables (.o and .ko), the value is relative to the section's address

    I'll figure out the base address; to get the absolute address,
    just add value to baseaddr.

    This also adds a data structure helper field, relas,
    so I can collect the relas linked to a symbol
    without a separate dict.
    """

    idx: int  # Symbol table index
    dynamic: bool  # Is this in the static or dynamic symbol table?
    name: str  # Symbol name
    type: int  # Symbol type
    bind: int  # Symbol binding
    visibility: int  # Symbol visibility
    shndx: int  # Symbol section index, or reserved flags
    defined: bool  # Is this symbol defined?
    value: int  # Symbol value
    size: int  # Symbol size
    baseaddr: int  # Base address for relative symbol values
    relas: typing.List["ElfRela"] = field(
        default_factory=list
    )  # List of associated relas


rela_patterns = [
    # 32-bit
    [
        # LSB
        [
            # Rel
            "<II",
            # Rela
            "<IIi",
        ],
        # MSB
        [
            # Rel
            ">II",
            # Rela
            ">IIi",
        ],
    ],
    # 64-bit
    [
        # LSB
        [
            # Rel
            "<QQ",
            # Rela
            "<QQq",
        ],
        # MSB
        [
            # Rel
            ">QQ",
            # Rela
            ">QQq",
        ],
    ],
]


@dataclass(frozen=False)
class ElfRela:
    """ELF relocation struct

    Lief parses this data, but I can't keep the objects around.

    NOTE: offset is the absolute address this rela is modifying.
    Normally, it's optionally relative to the load address,
    or to the linked section's address in a .o or .ko.
    I don't want to deal with that.
    """

    is_rela: bool  # Does this relocation have an addend?
    offset: int  # Address of the relocation
    type: int  # Relocation type; platform-dependent
    symbol: ElfSymbol  # Relevant symbol in use
    addend: int  # Extra argument to computation

    @staticmethod
    def from_bytes(
        idx: int,
        is_rela: bool,
        elfclass: int,
        elfdata: int,
        image: bytes,
        offset: int,
        baseaddr: int,
        symtab: typing.List["ElfSymbol"],
    ):
        # Lief has done something weird with their rela parsing.
        #
        # For one, it now mulches the r_info field
        # in order to help them with internal enums.
        # For two, they don't return raw results if they don't
        # internally support a particular platform.
        #
        # Relas are really, really, really simple structs, dammit.
        if elfclass != 1 and elfclass != 2:
            raise ValueError(f"Bad elfclass: {elfclass}")
        if elfdata != 1 and elfdata != 2:
            raise ValueError(f"Bad elfdata: {elfdata}")

        pattern = rela_patterns[elfclass - 1][elfdata - 1][1 if is_rela else 0]

        size = struct.calcsize(pattern)
        offset += idx * size

        res = struct.unpack_from(pattern, image, offset=offset)
        if is_rela:
            r_offset, r_info, r_addend = res
        else:
            r_offset, r_info = res
            r_addend = 0

        if elfclass == 1:
            r_type = r_info & 0xFF
            r_symbol = r_info >> 8
        else:
            r_type = r_info & 0xFFFFFFFF
            r_symbol = r_info >> 32

        if r_symbol < 0 or r_symbol >= len(symtab):
            raise ValueError(
                f"Bad symbol number: {r_symbol} ({len(symtab)} symbols in table)"
            )
        symbol = symtab[r_symbol]

        return ElfRela(
            is_rela=is_rela,
            offset=r_offset + baseaddr,
            type=r_type,
            symbol=symbol,
            addend=r_addend,
        )
