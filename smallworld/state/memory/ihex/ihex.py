import logging
import typing

from ....exceptions import ConfigurationError
from ....platforms import Platform
from ....utils import RangeCollection
from ...state import BytesValue
from ..code import Executable
from .asxxxx import AsxxxxSymbol, read_asxxxx_map
from .layout import IHexLayout

logger = logging.getLogger(__name__)

# Record types
_DATA = 0x00
_END_OF_FILE = 0x01
_EXTENDED_SEGMENT_ADDRESS = 0x02
_START_SEGMENT_ADDRESS = 0x03
_EXTENDED_LINEAR_ADDRESS = 0x04
_START_LINEAR_ADDRESS = 0x05


def _read_text(file: typing.IO) -> str:
    content = file.read()
    if isinstance(content, bytes):
        try:
            return content.decode("ascii")
        except UnicodeDecodeError as e:
            raise ConfigurationError(f"Not a text file: {e}")
    return content


def _parse_records(text: str) -> typing.Iterator[typing.Tuple[int, int, bytes]]:
    """Yield (line number, record type, data with address) for each record."""
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        if not line.startswith(":"):
            raise ConfigurationError(f"Intel HEX line {number}: no ':' start code")
        try:
            record = bytes.fromhex(line[1:])
        except ValueError:
            raise ConfigurationError(f"Intel HEX line {number}: not hexadecimal")
        if len(record) < 5 or len(record) != record[0] + 5:
            raise ConfigurationError(f"Intel HEX line {number}: wrong length")
        if sum(record) & 0xFF != 0:
            raise ConfigurationError(f"Intel HEX line {number}: bad checksum")
        yield number, record[3], record[1:3] + record[4:-1]


class IHexExecutable(Executable):
    """Executable loaded from an Intel HEX file.

    Intel HEX holds only bytes and the addresses they go at, so the image is
    sparse: each run of contiguous bytes is mapped on its own, and
    :attr:`bounds` covers them all.  The format has no symbols; pass a linker
    map to look them up with :meth:`get_symbol_value`.  Maps from the ASxxxx
    linker, which SDCC uses, are supported.

    Where the image and its symbols land is up to the platform's
    :class:`~smallworld.state.memory.ihex.IHexLayout`.  By default symbols
    keep their values, moved with the image; on the 8051, see
    :class:`~smallworld.state.memory.ihex.MCS51IHexLayout`.

    Arguments:
        file: File-like object containing the Intel HEX records.
        map_file: Optional file-like object containing the linker's map.
        platform: The platform the image is for.  Intel HEX does not say, and
            on some platforms, such as the 8051, symbol addresses depend on it.
        user_base: Where the image's address 0 goes; by default, 0.
    """

    def __init__(
        self,
        file: typing.IO,
        map_file: typing.Optional[typing.IO] = None,
        platform: typing.Optional[Platform] = None,
        user_base: typing.Optional[int] = None,
    ):
        base = 0 if user_base is None else user_base
        super().__init__(base, 0)
        self.platform = platform
        self._layout = IHexLayout.for_platform(platform)
        self.bounds: RangeCollection = RangeCollection()
        self._symbols: typing.Dict[str, AsxxxxSymbol] = dict()

        runs: typing.Dict[int, bytearray] = dict()
        run_start: typing.Optional[int] = None
        upper = 0
        ended = False
        for number, kind, data in _parse_records(_read_text(file)):
            if ended:
                raise ConfigurationError(
                    f"Intel HEX line {number}: record after end of file"
                )
            offset = int.from_bytes(data[:2], "big")
            payload = data[2:]
            if kind == _DATA:
                address = upper + offset
                if (
                    run_start is not None
                    and run_start + len(runs[run_start]) == address
                ):
                    runs[run_start] += payload
                else:
                    run_start = address
                    if address in runs:
                        raise ConfigurationError(
                            f"Intel HEX line {number}: {hex(address)} written twice"
                        )
                    runs[address] = bytearray(payload)
            elif kind == _END_OF_FILE:
                ended = True
            elif kind == _EXTENDED_SEGMENT_ADDRESS and len(payload) == 2:
                upper = int.from_bytes(payload, "big") << 4
            elif kind == _EXTENDED_LINEAR_ADDRESS and len(payload) == 2:
                upper = int.from_bytes(payload, "big") << 16
            elif kind == _START_SEGMENT_ADDRESS and len(payload) == 4:
                segment = int.from_bytes(payload[:2], "big")
                self.entrypoint = (
                    base + (segment << 4) + int.from_bytes(payload[2:], "big")
                )
            elif kind == _START_LINEAR_ADDRESS and len(payload) == 4:
                self.entrypoint = base + int.from_bytes(payload, "big")
            else:
                raise ConfigurationError(
                    f"Intel HEX line {number}: bad record of type {kind}"
                )
        if not ended:
            logger.warning("Intel HEX file has no end-of-file record")

        # Join runs that meet, which records out of address order leave apart.
        ordered: typing.List[typing.Tuple[int, bytearray]] = list()
        for start, content in sorted(runs.items()):
            if ordered:
                last_start, last = ordered[-1]
                if last_start + len(last) > start:
                    raise ConfigurationError(
                        f"Intel HEX data at {hex(start)} overlaps earlier data"
                    )
                if last_start + len(last) == start:
                    last += content
                    continue
            ordered.append((start, content))
        if ordered:
            start, content = ordered[-1]
            self._layout.check_extent(base + start + len(content))
        for start, content in ordered:
            self[start] = BytesValue(bytes(content), None)
            self.bounds.add_range((base + start, base + start + len(content)))
            self.size = max(self.size, start + len(content))

        if map_file is not None:
            self._symbols = read_asxxxx_map(_read_text(map_file))

    def _symbol_address(self, symbol: AsxxxxSymbol) -> int:
        return self._layout.symbol_address(self.address, symbol)

    def get_symbol_value(self, name: str) -> int:
        """Get a symbol's address, from the linker map.

        Arguments:
            name: The symbol's name, as the linker sees it; SDCC prefixes C
                names with ``_``.

        Returns:
            The symbol's address, or value for an absolute symbol.

        Raises:
            ConfigurationError: If no map was loaded, or it has no such symbol.
        """
        if name not in self._symbols:
            if not self._symbols:
                raise ConfigurationError(
                    f"No symbol named {name}: no linker map was loaded"
                )
            raise ConfigurationError(f"No symbol named {name}")
        return self._symbol_address(self._symbols[name])

    def get_map_value(self, name: str) -> typing.Optional[int]:
        """Get a symbol's value as the linker map records it.

        Unlike :meth:`get_symbol_value`, this does not place the symbol in
        the platform's address space: it is the number the linker wrote.
        That suits symbols that are not addresses, such as SDCC's
        ``__XPAGE`` on the 8051, the SFR that pages MOVX @Ri::

            cpu.xpage_sfr.set(code.get_map_value("__XPAGE"))

        Arguments:
            name: The symbol's name, as the linker sees it.

        Returns:
            The symbol's value, or None if no map was loaded or it has no
            such symbol.
        """
        symbol = self._symbols.get(name)
        return None if symbol is None else symbol.value

    def get_symbol_names(self) -> typing.List[str]:
        """List the symbols the linker map defines."""
        return list(self._symbols)


__all__ = ["IHexExecutable"]
