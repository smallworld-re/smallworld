import typing
from dataclasses import dataclass


@dataclass(frozen=False)
class PEExport:
    """PE export struct

    Lief parses this data, but I can't keep the objects around.

    An export defines a symbol that can be imported by other images.
    See 'PEImport' for more on that process.

    This is a mashup of a number of PE32+ structs
    (export definitions are actually somewhat complicated
    compared to import definitions).

    Exports can be referenced by name or by ordinal - a numeric key
    specific to the DLL.

    Exports can provide an actual address, or a "forwarder".
    This is the name of another export in another DLL that
    will provide the actual value of the symbol... or possibly forward again.
    """

    dll: str
    ordinal: int
    name: str
    forwarder: typing.Optional[str]
    value: int


@dataclass(frozen=False)
class PEImport:
    """PE import struct

    Lief parses this data, but I can't keep the objects around.

    An import defines that a specific exported symbol
    is required from a specific DLL file.

    They are closer to a relocation entry than a symbol;
    each import defines the export required, and where
    to write the exported value.  There is exactly one
    relocation mechanism, making this a lot easier to parse than ELF.

    This class actually mashes up two PE32+ structures:
    an Import Directory Entry, which defines a DLL that the file needs,
    and an Import Lookup Entry, which defines a specific export it needs.

    Lookup requires two keys, either the DLL name and export name,
    or the DLL and export ordinal - a numeric key specified wihtin the DLL.
    """

    dll: str  # Name of the DLL
    name: typing.Optional[str]  # String name of the export
    ordinal: typing.Optional[int]  # Ordinal of the export
    iat_address: int  # Address of the IAT slot for this import
    forwarder: typing.Optional[str]  # Forwarder export, if provided
    value: typing.Optional[int]  # Value imported
