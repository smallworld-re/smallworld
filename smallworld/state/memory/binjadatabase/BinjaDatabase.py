import typing

from binaryninja import BinaryView, load

from ....exceptions import ConfigurationError
from ....platforms import Architecture, Byteorder, Platform, PlatformDef
from ....utils import RangeCollection
from ...state import BytesValue
from ..code import Executable

# Mapping from Binary Ninja architecture/platform names to internal Architecture enums.
# Keys are substrings matched against bv.arch.name and bv.platform.name.
_ARCH_MAP: typing.Dict[str, Architecture] = {
    # PowerPC
    "ppc64": Architecture.POWERPC64,
    "powerpc64": Architecture.POWERPC64,
    "ppc32": Architecture.POWERPC32,
    "powerpc32": Architecture.POWERPC32,
    "ppc": Architecture.POWERPC32,  # fallback for generic "ppc"
    # AArch64
    "aarch64": Architecture.AARCH64,
    "arm64": Architecture.AARCH64,
    # ARM 32-bit — Binary Ninja reports "armv7" or "thumb2" but doesn't
    # distinguish v7m/v7r/v7a well.  Default to v7m; callers can override
    # via the ``platform`` parameter if needed.
    "armv7": Architecture.ARM_V7M,
    "thumb2": Architecture.ARM_V7M,
    "armv6": Architecture.ARM_V6M,
    "armv5": Architecture.ARM_V5T,
    "arm": Architecture.ARM_V7M,  # generic fallback
    # MIPS
    "mips64": Architecture.MIPS64,
    "mips32": Architecture.MIPS32,
    "mipsel32": Architecture.MIPS32,
    "mips": Architecture.MIPS32,  # fallback
    # x86
    "x86_64": Architecture.X86_64,
    "x86": Architecture.X86_32,
    # RISC-V
    "riscv64": Architecture.RISCV64,
    # Xtensa
    "xtensa": Architecture.XTENSA,
    # MSP430
    "msp430x": Architecture.MSP430X,
    "msp430": Architecture.MSP430,
    # LoongArch
    "loongarch64": Architecture.LOONGARCH64,
    "loongarch32": Architecture.LOONGARCH32,
}


class BinjaDatabase(Executable):
    """Executable loaded from an arbitrary Binary Ninja database (.bndb) or
    any file that Binary Ninja can open via ``binaryninja.load()``.

    Arguments:
        path: Filesystem path to a ``.bndb`` file (or raw binary / ELF / PE / etc.)
        platform: Optional platform override; when given the detected platform
                  is verified against it.
        ignore_platform: Skip platform identification and verification entirely.
        user_base: Optional base address override.  When *None* the base
                   recorded in the BinaryView is used.
    """

    def __init__(
        self,
        path: str,
        platform: typing.Optional[Platform] = None,
        ignore_platform: bool = False,
        user_base: typing.Optional[int] = None,
    ):
        # Initialize with null address and size; updated below.
        super().__init__(0, 0)

        self.platform = platform
        self.platdef: typing.Optional[PlatformDef] = None
        self.bounds: RangeCollection = RangeCollection()

        self._user_base = user_base
        self._file_base = 0

        self._symbols: typing.List[typing.Any] = list()

        # Open the database / binary via Binary Ninja.
        # update_analysis=False avoids re-running analysis on an already-
        # analysed .bndb; for raw files the caller should run analysis
        # separately if needed.
        bv = load(path, update_analysis=False)

        if bv is None:
            raise ConfigurationError(
                f"Binary Ninja could not open {path!r} – BinaryView is None"
            )

        self.entry_point = bv.entry_point

        # --- Platform / architecture detection ---
        if not ignore_platform:
            hdr_platform = self._platform_for_bv(bv)
            if self.platform is not None:
                if self.platform != hdr_platform:
                    raise ConfigurationError(
                        "Platform mismatch: "
                        f"specified {self.platform}, but detected {hdr_platform} from database"
                    )
            else:
                self.platform = hdr_platform
            self.platdef = PlatformDef.for_platform(hdr_platform)

        # --- Base address ---
        self._determine_base(bv)

        # --- Sections → memory map ---
        self._map_sections(bv)

        # --- Executable bounds ---
        self._map_bounds(bv)

        # Compute total size from mapped content.
        for offset, value in self.items():
            self.size = max(self.size, offset + value.get_size())

        # --- Symbols ---
        self._extract_symbols(bv)

        bv.file.close()

    # ------------------------------------------------------------------
    # Platform detection – generalised for arbitrary binaries
    # ------------------------------------------------------------------

    @staticmethod
    def _platform_for_bv(bv: BinaryView) -> Platform:
        """Derive an internal :class:`Platform` from the BinaryView metadata.

        Inspects ``bv.arch.name`` (and falls back to ``bv.platform.name``)
        so that this works for ELF, PE, Mach-O, raw, and VxWorks images
        alike.
        """
        if bv.endianness == bv.endianness.BigEndian:
            endianness = Byteorder.BIG
        else:
            endianness = Byteorder.LITTLE

        # Try matching against bv.arch.name first (most reliable),
        # then bv.platform.name as a fallback.
        candidates: typing.List[str] = []
        if bv.arch is not None and bv.arch.name is not None:
            candidates.append(bv.arch.name)
        if bv.platform is not None and bv.platform.name is not None:
            candidates.append(bv.platform.name)

        for name in candidates:
            name_lower = name.lower()
            # Check from most-specific to least-specific by sorting key
            # length descending so "ppc64" matches before "ppc".
            for key in sorted(_ARCH_MAP, key=len, reverse=True):
                if key in name_lower:
                    return Platform(_ARCH_MAP[key], endianness)

        names = ", ".join(candidates) if candidates else "<unknown>"
        raise ConfigurationError(f"Unsupported architecture: {names}. ")

    # ------------------------------------------------------------------
    # Base address
    # ------------------------------------------------------------------

    def _determine_base(self, bv: BinaryView):
        if self._user_base is None:
            self._file_base = bv.start
            if self._file_base == 0:
                print("Warning: BinaryView base address is 0")
            self.address = self._file_base
        else:
            # User-supplied base overrides whatever Binary Ninja detected.
            self.address = self._user_base

    # ------------------------------------------------------------------
    # Section mapping – reads bytes directly from the BinaryView
    # ------------------------------------------------------------------

    def _map_sections(self, bv: BinaryView):
        """Map every section recorded in the BinaryView into *self*.

        Instead of slicing raw file bytes we use ``bv.read()`` which works
        correctly for both freshly-loaded binaries and saved ``.bndb`` files
        where the original file may no longer be adjacent.
        """
        for sec in bv.sections.values():
            sect_addr = sec.start
            sect_size = sec.length

            # Read the section content from the BinaryView's virtual memory.
            sect_data = bv.read(sec.start, sec.length)

            if sect_data is None:
                sect_data = b""

            if len(sect_data) < sect_size:
                # Zero-pad if the BinaryView doesn't back the full range
                # (e.g. .bss or uninitialised data).
                sect_data += b"\x00" * (sect_size - len(sect_data))

            sect_value = BytesValue(sect_data, None)

            # Store at offset relative to the image base address, because
            # downstream consumers (SMWO etc.) adjust for base internally.
            self[sect_addr - self.address] = sect_value

    # ------------------------------------------------------------------
    # Executable bounds
    # ------------------------------------------------------------------

    def _map_bounds(self, bv: BinaryView):
        for seg in bv.segments:
            if seg.executable:
                self.bounds.add_range((seg.start, seg.end))

    # ------------------------------------------------------------------
    # Symbol extraction
    # ------------------------------------------------------------------

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
                        "type": str(sym.type),
                        "binding": str(sym.binding),
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
