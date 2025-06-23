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


@dataclass(frozen=False)
class ElfRela:
    """ELF relocation struct

    Lief parses this data, but I can't keep the objects around.

    NOTE: offset is the absolute address this rela is modifying.
    Normally, it's optionally relative to the load address,
    or to the linked section's address in a .o or .ko.
    I don't want to deal with that.
    """

    offset: int  # Address of the relocation
    type: int  # Relocation type; platform-dependent
    symbol: ElfSymbol  # Relevant symbol in use
    addend: int  # Extra argument to computation
