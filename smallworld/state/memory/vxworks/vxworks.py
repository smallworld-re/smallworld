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
    """Executable loaded from VXWorks

    Arguments:
        file: File-like object containing the image
        platform: Optional platform; used for header verification
        ignore_platform: Do not try to ID or verify platform from headers
        user_base: Optional user-specified base address
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

    def _platform_for_hdr(self, bv: BinaryView):
        if bv.endianness == bv.endianness.BigEndian:
            endianness = Byteorder.BIG
        else:
            endianness = Byteorder.LITTLE
        if bv.platform.name in ("vxworks-ppc32", "ppc32"):
            return Platform(Architecture.POWERPC32, endianness)
        elif bv.platform.name in ("vxworks-ppc64", "ppc64"):
            return Platform(Architecture.POWERPC64, endianness)
        elif bv.platform.name in ("vxworks-armv7", "armv7"):
            # Binja doesn't tell you which subversion of ARM, only has 7,
            # So we're guessing because it's VXWorks
            # Doesn't seem to distinguish well between subtypes
            # We're guessing it's M for Embedded, but could be R for RTOS
            return Platform(Architecture.ARM_V7M, endianness)
        elif bv.platform.name in (
            "vxworks-mipsel32",
            "mipsel32",
            "vxworks-mips32",
            "mips32",
        ):
            return Platform(Architecture.MIPS32, endianness)
        elif bv.platform.name in ("vxworks-x86", "x86"):
            return Platform(Architecture.X86_32, endianness)
        elif bv.platform.name in ("vxworks-x86-64", "x86-64"):
            return Platform(Architecture.X86_64, endianness)
        else:
            raise ConfigurationError(f"Unsupported machine type {bv.platform.name}")

    def _determine_base(self, bv: BinaryView):
        if self._user_base is None:
            self._file_base = bv.start
            if self._file_base == 0:
                logger.warning("File entry_point set to 0")
            self.address = self._file_base
        else:
            # User base can override binja base detection
            self.address = self._user_base

    def _map_sections(self, bv: BinaryView, image: bytes):
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
        for seg in bv.segments:
            if seg.executable:
                self.bounds.add_range((seg.start, seg.end))

    @staticmethod
    def _get_func_end(bv: BinaryView, address: int) -> typing.Optional[int]:
        func = bv.get_function_at(address)
        if func is None:
            return None
        return func.highest_address + 1

    def _extract_symbols(self, bv: BinaryView) -> None:
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

        Raises:
            KeyError: if no symbol with that name exists in the database.
        """
        for sym in self._symbols:
            if name in (sym["name"], sym["full_name"], sym["short_name"]):
                return sym["address"]
        raise KeyError(f"Symbol {name!r} not found in database")

    def get_function_end(self, name: str) -> int:
        for sym in self._symbols:
            if name in (sym["name"], sym["full_name"], sym["short_name"]):
                end = sym.get("func_end")
                if end is None:
                    raise KeyError(
                        f"Symbol {name!r} is not a function or has no known end"
                    )
                return end
        raise KeyError(f"Symbol {name!r} not found in database")
