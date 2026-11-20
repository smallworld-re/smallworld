"""Read the symbols in an ASxxxx linker map.

ASxxxx's linker, and SDCC's fork of it, ``sdld``, write a map file listing
every global under the area that holds it.  The format has no specification;
this reads the layout ``sdld`` 3.x and 4.x write, and refuses files that do not
look like it rather than guess.
"""

import dataclasses
import re
import typing

from ....exceptions import ConfigurationError

_HEADER = re.compile(r"^ASxxxx Linker\b")
_RADIX = re.compile(r"^(Hexadecimal|Octal|Decimal)\s+\[\d+-Bits\]")
_AREA = re.compile(
    r"^(?P<name>\S.*?)\s+(?P<addr>[0-9A-F]+)\s+(?P<size>[0-9A-F]+)\s+="
    r"\s+\d+\.\s+bytes\s+\((?P<attributes>[A-Z,]*)\)\s*$"
)
_SYMBOL = re.compile(
    r"^(?:[A-Z]:)?\s+(?P<value>[0-9A-F]+)\s+(?P<name>\S+)(?:\s+(?P<module>\S+))?\s*$"
)


@dataclasses.dataclass(frozen=True)
class AsxxxxSymbol:
    """A global from an ASxxxx linker map."""

    name: str
    """The symbol's name, as the linker sees it (C names gain a ``_``)."""

    value: int
    """The symbol's value: an address in its area's space, or a constant."""

    area: str
    """The area it is defined in."""

    attributes: typing.FrozenSet[str]
    """The area's attributes, such as ``CODE``, ``XDATA`` or ``ABS``."""

    module: typing.Optional[str]
    """The module that defines it, when the linker says."""


def read_asxxxx_map(text: str) -> typing.Dict[str, AsxxxxSymbol]:
    """Read the globals out of an ASxxxx linker map.

    Arguments:
        text: The map file's contents.

    Returns:
        The globals, by name.  A name listed twice keeps its first entry.

    Raises:
        ConfigurationError: If the text is not a hexadecimal ASxxxx linker map.
    """
    # Each page starts with a form feed, which splitlines() also breaks at.
    lines = text.splitlines()
    first = next((line for line in lines if line.strip()), "")
    if not _HEADER.match(first):
        raise ConfigurationError("Not an ASxxxx linker map")

    symbols: typing.Dict[str, AsxxxxSymbol] = dict()
    area: typing.Optional[typing.Tuple[str, typing.FrozenSet[str]]] = None
    in_symbols = False
    for line in lines:
        radix = _RADIX.match(line)
        if radix:
            if radix.group(1) != "Hexadecimal":
                raise ConfigurationError(
                    f"ASxxxx linker map in {radix.group(1).lower()}; "
                    "only hexadecimal maps are supported"
                )
            continue
        match = _AREA.match(line)
        if match:
            attributes = frozenset(match.group("attributes").split(","))
            area = (match.group("name"), attributes)
            in_symbols = False
            continue
        if line.lstrip().startswith("-----") and area is not None:
            # The rule under the "Value  Global" heading starts the
            # area's symbols; the one under "Area" does not, but no
            # symbol can come before an area line anyway.
            in_symbols = True
            continue
        if not line.strip():
            in_symbols = False
            continue
        if not in_symbols or area is None:
            continue
        match = _SYMBOL.match(line)
        if match:
            name = match.group("name")
            if name not in symbols:
                symbols[name] = AsxxxxSymbol(
                    name=name,
                    value=int(match.group("value"), 16),
                    area=area[0],
                    attributes=area[1],
                    module=match.group("module"),
                )
    return symbols


__all__ = ["AsxxxxSymbol", "read_asxxxx_map"]
