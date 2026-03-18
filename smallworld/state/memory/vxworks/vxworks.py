import logging as lg
import typing

from binaryninja import BinaryView, SectionDescriptorList, load

from ....exceptions import ConfigurationError
from ....platforms import Architecture, Byteorder, Platform, PlatformDef
from ....utils import RangeCollection
from ...state import BytesValue
from ..code import Executable

logger = lg.getLogger(__name__)

ARCH_MAP: typing.Dict[str, Architecture] = {
    # PowerPC
    "vxworks-ppc32": Architecture.POWERPC32,
    "ppc32": Architecture.POWERPC32,
    "vxworks-ppc64": Architecture.POWERPC64,
    "ppc64": Architecture.POWERPC64,
    # ARM 32-bit — Binary Ninja only reports armv7 for VXWorks; no finer
    # distinction is available.  Defaulting to v7m (microcontroller) since
    # VXWorks targets embedded hardware, but could be v7r (real-time)
    "vxworks-armv7": Architecture.ARM_V7M,
    "armv7": Architecture.ARM_V7M,
    # MIPS — VXWorks supports both big- and little-endian MIPS32;
    # endianness is handled separately, so both map to the same Architecture.
    "vxworks-mipsel32": Architecture.MIPS32,
    "mipsel32": Architecture.MIPS32,
    "vxworks-mips32": Architecture.MIPS32,
    "mips32": Architecture.MIPS32,
    # x86
    "vxworks-x86": Architecture.X86_32,
    "x86": Architecture.X86_32,
    "vxworks-x86-64": Architecture.X86_64,
    "x86-64": Architecture.X86_64,
}


class VXWorksImage(Executable):
    """Executable loaded from a VxWorks firmware image.

    Uses Binary Ninja to parse the image, auto-detecting platform, base address,
    section layout, executable bounds, and symbol table. Supports VxWorks 5 and 6
    images that include a symbol table for PowerPC, ARM, MIPS, and x86 targets.

    Arguments:
        file: File-like object containing the raw firmware image.
        platform: Optional platform override; when given the detected platform
                  is verified against it.
        ignore_platform: Skip platform identification and verification entirely.
        user_base: Optional base address override. When *None* the base recorded
                   in the BinaryView is used.
    """

    def __init__(
        self,
        file: typing.BinaryIO,
        platform: typing.Optional[Platform] = None,
        ignore_platform: bool = False,
        user_base: typing.Optional[int] = None,
    ):
        # Initialize with null address and size;
        # we will update these later
        super().__init__(0, 0)

        self.platform = platform
        self.platdef: typing.Optional[PlatformDef] = None
        self.bounds: RangeCollection = RangeCollection()

        self._user_base = user_base
        self._file_base = 0

        self._symbols: typing.List[typing.Any] = list()

        # Read the entire image out of the file
        image = file.read()

        # Create BinaryView from in-memory content
        bv = load(image, update_analysis=False)

        if bv is None:
            raise ConfigurationError("BinaryView could not be created")

        self.entry_point = bv.entry_point

        # Check machine compatibility
        if not ignore_platform:
            hdr_platform = self._platform_for_hdr(bv)
            if self.platform is not None:
                if self.platform != hdr_platform:
                    raise ConfigurationError(
                        "Platform mismatch: "
                        f"specified {self.platform}, but got {hdr_platform} from header"
                    )
            else:
                self.platform = hdr_platform
            self.platdef = PlatformDef.for_platform(hdr_platform)

        # Determine the file base address
        self._determine_base(bv)

        self._map_sections(bv, image)

        self._map_bounds(bv)

        for offset, value in self.items():
            self.size = max(self.size, offset + value.get_size())

        # Extract symbols into dictionary
        self._extract_symbols(bv)

        bv.file.close()

    @staticmethod
    def _platform_for_hdr(bv: BinaryView) -> Platform:
        """Derive an internal :class:`Platform` from the BinaryView metadata.

        Performs an exact lookup of ``bv.platform.name`` against :data:`ARCH_MAP`.
        VxWorks platform names are well-defined and finite, so exact matching is
        preferred over the substring matching used for generic binaries.

        Arguments:
            bv: The Binary Ninja BinaryView to inspect.

        Returns:
            The detected :class:`Platform`.

        Raises:
            ConfigurationError: If the BinaryView has no platform set, or if the
                                 platform name is not present in :data:`ARCH_MAP`.
        """
        if bv.endianness == bv.endianness.BigEndian:
            endianness = Byteorder.BIG
        else:
            endianness = Byteorder.LITTLE

        name = bv.platform.name if bv.platform is not None else None
        if name is None:
            raise ConfigurationError("BinaryView has no platform set")

        arch = ARCH_MAP.get(name)
        if arch is None:
            raise ConfigurationError(f"Unsupported machine type {name!r}")

        return Platform(arch, endianness)

    def _determine_base(self, bv: BinaryView):
        """Set the image base address from the BinaryView or a user override.

        When no user base is provided, the base is taken from ``bv.start``.
        A warning is logged if the detected base is zero, which may indicate
        that Binary Ninja failed to detect a load address.

        Arguments:
            bv: The Binary Ninja BinaryView to inspect.
        """
        if self._user_base is None:
            self._file_base = bv.start
            if self._file_base == 0:
                logger.warning("File entry_point set to 0")
            self.address = self._file_base
        else:
            # User base can override binja base detection
            self.address = self._user_base

    def _map_sections(self, bv: BinaryView, image: bytes):
        """Map every section from the firmware image into *self*.

        Uses :class:`~binaryninja.SectionDescriptorList` to enumerate sections
        and reads their content from the raw *image* bytes. Sections shorter than
        their declared size are zero-padded to fill the remainder (e.g. ``.bss``).

        Arguments:
            bv: The Binary Ninja BinaryView to read section metadata from.
            image: The raw firmware image bytes, used to slice section content.

        Raises:
            ConfigurationError: If a section's data exceeds its declared size,
                                 which would indicate a malformed image.
        """
        # SDL will auto-shift parameters by the base address passed
        sdl = SectionDescriptorList(bv.start)
        for sec in bv.sections.values():
            sdl.append(
                name=sec.name,
                start=sec.start,
                length=sec.length,
                semantics=sec.semantics,
                type=sec.type,
                align=sec.align,
                entry_size=sec.entry_size,
                link=sec.linked_section,
                info_section=sec.info_section,
                info_data=sec.info_data,
                auto_defined=sec.auto_defined,
            )

        for section in sdl:
            sect_start = section["start"]
            sect_end = section["start"] + section["length"]
            sect_addr = section["start"] + self.address  # self.address = file_base
            sect_size = section["length"]

            sect_data = image[sect_start:sect_end]
            if len(sect_data) < sect_size:
                # Section is shorter than what's available in the file;
                # This will get zero-padded.
                pad_size = sect_size - len(sect_data)
                sect_data += b"\0" * pad_size
            if len(sect_data) != sect_size:
                raise ConfigurationError(
                    f"Expected segment of size {sect_size}, but got {len(sect_data)}"
                )

            sect_value = BytesValue(sect_data, None)

            logger.debug(
                f"\x1b[34m{section['name']} section ({hex(sect_addr)}-{hex(sect_addr + sect_size)}) first 8 bytes : {sect_data[:4].hex().lower()} {sect_data[4:8].hex().lower()}\x1b[0m"
            )

            # This seems unintuitive, but SMWO later self adjusts for base address
            self[sect_addr - self.address] = sect_value

    def _map_bounds(self, bv: BinaryView):
        """Populate executable bounds from the BinaryView's segment flags.

        Iterates over all segments in the BinaryView and adds any segment marked
        executable to :attr:`bounds`. These bounds constrain which addresses the
        emulator will treat as valid code.

        Arguments:
            bv: The Binary Ninja BinaryView to read segment metadata from.
        """
        for seg in bv.segments:
            if seg.executable:
                self.bounds.add_range((seg.start, seg.end))

    @staticmethod
    def _get_func_end(bv: BinaryView, address: int) -> typing.Optional[int]:
        """Return the first address past the last instruction of the function at *address*.

        Looks up the function at *address* in the BinaryView and returns
        ``highest_address + 1``. Returns *None* if no function exists at that
        address (e.g. for data symbols or unanalysed regions).

        Arguments:
            bv: The Binary Ninja BinaryView to query.
            address: The entry point address of the function.

        Returns:
            The first address past the function's last instruction, or *None* if
            no function exists at *address*.
        """
        func = bv.get_function_at(address)
        if func is None:
            return None
        return func.highest_address + 1

    def _extract_symbols(self, bv: BinaryView) -> None:
        """Extract all symbols from the BinaryView into :attr:`_symbols`.

        Populates :attr:`_symbols` with a dict for each symbol containing its
        name variants, address, type, binding, and — for function symbols — the
        first address past its last instruction via :meth:`_get_func_end`.

        Arguments:
            bv: The Binary Ninja BinaryView to read symbols from.
        """
        for sym_list in bv.symbols.values():
            for sym in sym_list:
                self._symbols.append(
                    {
                        "name": sym.name,
                        "full_name": sym.full_name,
                        "short_name": sym.short_name,
                        "raw_name": sym.raw_name,
                        "address": sym.address,
                        "func_end": self._get_func_end(bv, sym.address),
                        "type": str(sym.type),  # SymbolType Enum
                        "binding": str(sym.binding),  # SymbolBinding Enum
                        "namespace": sym.namespace.name if sym.namespace else None,
                        "ordinal": sym.ordinal,
                        "auto": sym.auto,
                        "raw_bytes": sym.raw_bytes.hex() if sym.raw_bytes else None,
                        "raw_repr": repr(sym),
                    }
                )

    def get_symbol_value(self, name: str) -> int:
        """Return the address of the first symbol matching *name*.

        Checks ``name``, ``full_name``, and ``short_name`` fields so that
        both mangled and demangled lookups work.

        Arguments:
            name: The symbol name to look up.

        Returns:
            The address of the matching symbol.

        Raises:
            KeyError: If no symbol with that name exists in the image.
        """
        for sym in self._symbols:
            if name in (sym["name"], sym["full_name"], sym["short_name"]):
                return sym["address"]
        raise KeyError(f"Symbol {name!r} not found in database")

    def get_function_end(self, name: str) -> int:
        """Return the first address past the last instruction of the named function.

        Looks up the function by symbol name and returns the address immediately
        following its final instruction, suitable for use as an emulator exit point.
        Checks ``name``, ``full_name``, and ``short_name`` fields so that both
        mangled and demangled lookups should work.

        Arguments:
            name: The symbol name of the function to look up.

        Returns:
            The first address past the function's last instruction.

        Raises:
            KeyError: If no symbol with that name exists in the database, or if the
                    symbol exists but is not a function (e.g. a data label).
        """
        for sym in self._symbols:
            if name in (sym["name"], sym["full_name"], sym["short_name"]):
                end = sym.get("func_end")
                if end is None:
                    raise KeyError(
                        f"Symbol {name!r} is not a function or has no known end"
                    )
                return end
        raise KeyError(f"Symbol {name!r} not found in database")
