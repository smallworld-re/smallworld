import typing

from .... import platforms, utils
from .asxxxx import AsxxxxSymbol


class IHexLayout:
    """Where a platform puts an Intel HEX image and its map's symbols

    Intel HEX holds only bytes and the addresses they go at, and an ASxxxx
    map only symbol values and the areas they are in; how those land in
    SmallWorld's flat address space depends on the platform.  This default
    puts the image where it is loaded, puts each symbol in an absolute area
    at its value and every other symbol at its value moved with the image,
    and limits the image's size not at all.  A platform with more than one
    memory, such as the 8051, defines a subclass.
    """

    arch: typing.Optional[platforms.Architecture] = None
    """The architecture this layout is for; None for the default."""

    def check_extent(self, end: int) -> None:
        """Refuse an image that runs past what the platform can hold.

        Arguments:
            end: The flat address just past the image's last byte.

        Raises:
            ConfigurationError: If the platform has no room for the image.
        """
        pass

    def symbol_address(self, image_address: int, symbol: AsxxxxSymbol) -> int:
        """The flat address of a map symbol.

        Arguments:
            image_address: Where the image's address 0 was loaded.
            symbol: The symbol, as the map describes it.

        Returns:
            The symbol's address, or its value for an absolute symbol.
        """
        if "ABS" in symbol.attributes:
            return symbol.value
        return image_address + symbol.value

    @classmethod
    def for_platform(cls, platform: typing.Optional[platforms.Platform]):
        """The layout for a platform, or the default for None or a platform
        that defines none."""
        if platform is None:
            return cls()
        try:
            return utils.find_subclass(cls, lambda x: x.arch == platform.architecture)
        except ValueError:
            return cls()


__all__ = ["IHexLayout"]
