import typing

import lief

from ....exceptions import ConfigurationError
from ....platforms import Architecture, Byteorder, Platform, PlatformDef
from ....utils import RangeCollection
from ...state import BytesValue
from ..code import Executable
from .structs import PEExport, PEImport

# PE32+ machine types
# There are a lot more of these, but I can only test on amd64 and i386
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x14C

# Section flags
# Currently, the only one we care about is "code".
# Not sure how the others interact with file loading.
IMAGE_SCN_CNT_CODE = 0x20

# Relocation types
# All of these adjust based on the difference between
# the requested and actual load addresses
IMAGE_REL_BASED_ABSOLUTE = 0x0  # No-op
IMAGE_REL_BASED_HIGHLOW = 0x3  # Add 32-bit difference to a 32-bit value
IMAGE_REL_BASED_DIR64 = 0xA  # Add 64-bit difference to a 64-bit value


class PEExecutable(Executable):
    """Executable loaded from a PE32+

    This loads a single PE32+ file into a SmallWorld memory object.
    It performs no relocation or initialization,
    just maps the file into memory as the kernel intended.

    Arguments:
        file: File-like object containing the image
        platform: Optional platform; used for header verification
        ignore_platform: Do not try to ID or verify platform from headers
        user_base: Optional user-specified base address
        page_size: System page size
    """

    def __init__(
        self,
        file: typing.BinaryIO,
        platform: typing.Optional[Platform] = None,
        ignore_platform: bool = False,
        user_base: typing.Optional[int] = None,
        page_size: int = 0x1000,
    ):
        # Initialize with null address and size;
        # we will update these later
        super().__init__(0, 0)

        self.platform = platform
        self.platdef: typing.Optional[PlatformDef] = None
        self.bounds: RangeCollection = RangeCollection()

        self._page_size = page_size
        self._user_base = user_base
        self._file_base = 0

        self._exports: typing.List[PEExport] = list()
        self._exports_by_name: typing.Dict[typing.Tuple[str, str], PEExport] = dict()
        self._exports_by_ordinal: typing.Dict[typing.Tuple[str, int], PEExport] = dict()

        self._imports: typing.List[PEImport] = list()
        self._imports_by_name: typing.Dict[typing.Tuple[str, str], PEImport] = dict()
        self._imports_by_ordinal: typing.Dict[typing.Tuple[str, int], PEImport] = dict()

        # Read the entire image out of the file
        image = file.read()

        # Use lief to check if this is a PE
        # NOTE: For some reason, this takes list(int), not bytes
        if not lief.is_pe(list(image)):
            raise ConfigurationError("Image is not a PE")

        # Use lief to parse the PE
        # NOTE: For some reason, this takes list(int), not bytes
        # NOTE: lief objects aren't deep-copyable.
        # I'd love to keep `pe` around for later use, but I can't.
        pe = lief.PE.parse(list(image))
        if pe is None:
            raise ConfigurationError("Failed parsing PE image")

        # Check machine compatibility
        if not ignore_platform:
            hdr_platform = self._platform_for_chdr(pe)
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
        self._file_base = pe.imagebase
        self._determine_base()

        for section in pe.sections:
            # TODO: How do PE32+ files distinguish loadable segments?
            # mingw objdump has some notion of allocated segments,
            # but it doesn't map to anything in any of the flags.
            self._map_section(section, image)

        # Fix up the memory image to account for changes in the base address
        self._apply_base_relocations(pe)

        # Compute the final total capacity
        for offset, value in self.items():
            self.size = max(self.size, offset + value.get_size())

        # Extract exports
        self._extract_exports(pe)

        # Extract imports
        self._extract_imports(pe)

    def _platform_for_chdr(self, pe):
        if pe.header.machine.value == IMAGE_FILE_MACHINE_AMD64:
            return Platform(Architecture.X86_64, Byteorder.LITTLE)
        elif pe.header.machine.value == IMAGE_FILE_MACHINE_I386:
            return Platform(Architecture.X86_32, Byteorder.LITTLE)
        else:
            raise ConfigurationError(f"Unsupported machine type {pe.header.machine}")

    def _determine_base(self):
        if self._user_base is None:
            # No user base requested
            if self._file_base == 0:
                # No file base defined (unusal for PE32+)
                # Need the user to provide one
                raise ConfigurationError(
                    "No base address provided, and none defined in PE file"
                )
            else:
                self.address = self._file_base
        else:
            # PE files are always position-independent;
            # we'll just have to fix things up later.
            self.address = self._user_base

    def _rebase_file(self, val: int):
        # Rebase an offset from file-relative to image-relative
        res = val + self.address
        return res

    def _page_align(self, val: int, up: bool = True):
        if up:
            val += self._page_size - 1
        return (val // self._page_size) * self._page_size

    def _map_section(self, sect, image):
        # NOTE: Unlike ELFs, The physical address of PE sections is not page-aligned.
        sect_start = sect.offset
        sect_end = sect.offset + sect.size
        sect_addr = self._page_align(self._rebase_file(sect.virtual_address), up=False)
        sect_size = self._page_align(sect.virtual_size)

        sect_data = image[sect_start:sect_end]
        if len(sect_data) < sect_size:
            # Section is shorter than what's available in the file;
            # THis will get zero-padded.
            pad_size = sect_size - len(sect_data)
            sect_data += b"\0" * pad_size
        if len(sect_data) != sect_size:
            raise ConfigurationError(
                f"Expected segment of size {sect_size}, but got {len(sect_data)}"
            )

        if 0 != (sect.characteristics & IMAGE_SCN_CNT_CODE):
            # This is a code segment; add it to program bounds
            self.bounds.add_range((sect_addr, sect_addr + sect_size))

        sect_value = BytesValue(sect_data, None)
        self[sect_addr - self.address] = sect_value

    def _apply_base_relocations(self, pe):
        # PE32+ files always allow the loader to override
        # the program's base address.
        #
        # The relocation section marks places where
        # an absolute offset needs fixing
        # if the loader decides to override
        if self.address == self._file_base:
            # This file was not relocated.  Nothing to do.
            return

        if self.platform.byteorder == Byteorder.LITTLE:
            byteorder = "little"
        elif self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            raise ConfigurationError(
                f"Can't encode byteorder {self.platform.byteorder}"
            )

        for base_reloc in pe.relocations:
            for entry in base_reloc.entries:
                if entry.type.value == IMAGE_REL_BASED_ABSOLUTE:
                    # Entry is a no-op; continue
                    continue
                for off, val in self.items():
                    if entry.address >= off and entry.address <= val.get_size():
                        # Find the section containing this address
                        contents = bytearray(val.get_content())
                        fix_off = entry.address - off

                        if entry.type.value == IMAGE_REL_BASED_HIGHLOW:
                            # 4-byte repair
                            tofix = int.from_bytes(
                                contents[fix_off : fix_off + 4], byteorder
                            )
                            tofix += self.address - self._file_base
                            contents[fix_off : fix_off + 4] = tofix.to_bytes(
                                4, byteorder
                            )

                        elif entry.type.value == IMAGE_REL_BASED_DIR64:
                            # 8-byte repair
                            tofix = int.from_bytes(
                                contents[fix_off : fix_off + 8], byteorder
                            )
                            tofix += self.address - self._file_base
                            contents[fix_off : fix_off + 8] = tofix.to_bytes(
                                8, byteorder
                            )

                        else:
                            raise ConfigurationError(
                                "Unhandled relocation type {entry.type}"
                            )
                        # Reset the data
                        val.set_content(bytes(contents))
                        break

    def _extract_exports(self, pe) -> None:
        if not pe.has_exports:
            return

        d = pe.get_export()
        for e in d.entries:
            if e.is_forwarded:
                raise NotImplementedError(
                    "{d.name}.{e.name} is forwarded to {e.forward_information}"
                )
            else:
                exp = PEExport(
                    dll=d.name,
                    name=e.name,
                    ordinal=e.ordinal,
                    forwarder=None,
                    value=e.value + self.address,
                )
            self._exports.append(exp)
            self._exports_by_name[(d.name, e.name)] = exp
            self._exports_by_ordinal[(d.name, e.ordinal)] = exp

    def _extract_imports(self, pe) -> None:
        if not pe.has_imports:
            return

        # Iterate over the import directories
        # These group imports by the DLL that provides them
        for d in pe.imports:
            for e in d.entries:
                imp = PEImport(
                    dll=d.name,
                    name=e.name if not e.is_ordinal else None,
                    ordinal=e.ordinal if e.is_ordinal else None,
                    iat_address=e.iat_address + self.address,
                    forwarder=None,
                    value=None,
                )
                if e.name == "puts":
                    print(f"puts IAT at {e.iat_address:x} or {e.iat_value:x}")
                self._imports.append(imp)
                if e.is_ordinal:
                    self._imports_by_ordinal[(d.name, e.ordinal)] = imp
                else:
                    self._imports_by_name[(d.name, e.name)] = imp

    def update_import(
        self, dll: str, hint: typing.Union[str, int, PEImport], value: int
    ) -> None:
        """Update an imported symbol in this PE file

        Arguments:
            dll: Name of the DLL where the import is defined
            hint: Symbol name or ordinal
            value: New value of the symbol
        """
        # No platform specified
        if self.platform is None or self.platdef is None:
            raise ConfigurationError("No platform specified; can't update imports")

        if isinstance(hint, str):
            # Look up by name
            if (dll, hint) not in self._imports_by_name:
                raise ConfigurationError(
                    f"No import for {dll}.{hint}.  Try by ordinal?"
                )
            imp = self._imports_by_name[(dll, hint)]
        elif isinstance(hint, int):
            # Look up by ordinal
            if (dll, hint) not in self._imports_by_ordinal:
                raise ConfigurationError(f"No import for {dll}.#{hint}.  Try by name?")
            imp = self._imports_by_ordinal[(dll, hint)]
        elif isinstance(hint, PEImport):
            imp = hint
        else:
            raise TypeError(f"Unexpected hint {hint} of type {type(hint)}")

        # Save the new value to the import
        # This marks it as initialized
        imp.value = value

        # Convert value to bytes
        if self.platform.byteorder == Byteorder.LITTLE:
            value_bytes = value.to_bytes(self.platdef.address_size, "little")
        elif self.platform.byteorder == Byteorder.BIG:
            value_bytes = value.to_bytes(self.platdef.address_size, "big")
        else:
            raise ConfigurationError(
                f"Can't encode int for byteorder {self.platform.byteorder}"
            )

        # Rewrite IAT slot
        # NOTE: PE files can have overlapping segments; check all of them.
        for off, seg in self.items():
            start = off + self.address
            stop = start + seg.get_size()
            if imp.iat_address >= start and imp.iat_address < stop:
                start = imp.iat_address - start
                end = start + len(value_bytes)
                contents = typing.cast(bytes, seg.get_content())
                contents = contents[0:start] + value_bytes + contents[end:]
                seg.set_content(contents)

    def link_pe(self, dll: "PEExecutable"):
        for imp in self._imports:
            if imp.value is not None:
                continue

            if imp.name is not None and (imp.dll, imp.name) in dll._exports_by_name:
                exp = dll._exports_by_name[(imp.dll, imp.name)]
            elif (
                imp.ordinal is not None
                and (imp.dll, imp.ordinal) in dll._exports_by_ordinal
            ):
                exp = dll._exports_by_ordinal[(imp.dll, imp.ordinal)]
            else:
                continue

            self.update_import(imp.dll, imp, exp.value)
