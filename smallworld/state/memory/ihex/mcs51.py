from ....exceptions import ConfigurationError
from ....platforms import Architecture
from ....platforms.defs.mcs51 import (
    MCS51_CODE_BASE,
    MCS51_IDATA_BASE,
    MCS51_XDATA_BASE,
)
from .asxxxx import AsxxxxSymbol
from .layout import IHexLayout


class MCS51IHexLayout(IHexLayout):
    """The 8051's layout of an Intel HEX image and its map's symbols

    A map's symbols land in the flat address space SmallWorld lays the
    8051's memories out in: a symbol in a code area at its code address, one
    in an XDATA area (pdata included) in XDATA, and the rest in internal RAM.
    That goes for an absolute XDATA area too, which holds XDATA variables
    placed with ``__at``; symbols in other absolute areas - constants, such
    as the linker's area starts and lengths, and SFRs and variables placed
    with ``__at`` - keep their values, since the map does not say which
    space they are in.  The image itself must fit the 8051's 64 KiB of code
    space.
    """

    arch = Architecture.MCS51

    def check_extent(self, end: int) -> None:
        # Past the 8051's 64 KiB of code is XDATA in SmallWorld's flat map;
        # banked code, for parts with more flash, has nowhere to go.
        if end > MCS51_XDATA_BASE:
            raise ConfigurationError(
                f"Intel HEX data up to {hex(end)} is past the 8051's code "
                f"space, which ends at {hex(MCS51_XDATA_BASE)}"
            )

    def symbol_address(self, image_address: int, symbol: AsxxxxSymbol) -> int:
        if "XDATA" in symbol.attributes:
            return MCS51_XDATA_BASE + symbol.value
        if "ABS" in symbol.attributes:
            return symbol.value
        if "CODE" in symbol.attributes:
            return image_address + MCS51_CODE_BASE + symbol.value
        return MCS51_IDATA_BASE + symbol.value


__all__ = ["MCS51IHexLayout"]
