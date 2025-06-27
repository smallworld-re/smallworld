import typing

import lief

from ....exceptions import ConfigurationError
from ....platforms import Architecture, Byteorder, Platform
from ....utils import RangeCollection
from ...state import BytesValue
from ..code import Executable

# PE32+ machine types
# There are a lot more of these, but I can only test on amd64 and i386
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x14C

IMAGE_SCN_CNT_CODE = 0x20
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80


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
        self.bounds: RangeCollection = RangeCollection()

        self._page_size = page_size
        self._user_base = user_base
        self._file_base = 0

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
        if self.address == self._file_base:
            # This file was not relocated.  Nothing to do.
            return

        for base_reloc in pe.relocations:
            for entry in base_reloc.entries:
                print(entry)
