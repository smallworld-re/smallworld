import logging
import typing

import lief

from ...exceptions import ConfigurationError
from ...hinting import Hint, get_hinter
from ..state import BytesValue
from .code import Executable

log = logging.getLogger(__name__)
hinter = get_hinter(__name__)

# Program header types
PT_NULL = 0  # Empty/unused program header
PT_LOAD = 1  # Describes loadable program segment
PT_DYNAMIC = 2  # Points to dynamic linking metadata
PT_INTERP = 3  # Points to program interpreter
PT_NOTE = 4  # Points to auxiliary information
PT_SHLIB = 5  # Reserved value; I think it's unused
PT_PHDR = 6  # Points to program header table
PT_TLS = 7  # Indicates need for thread-local storage
PT_LOOS = 0x60000000  # Start of OS-specific types
PT_GNU_EH_FRAME = 0x6474E550  # GNU-specific: Points to exception handler segment
PT_GNU_STACK = 0x6474E551  # GNU-specific: Describes stack permissions
PT_GNU_RELRO = 0x6474E552  # GNU-specific: Describes read-only after relocation segment
PT_GNU_PROPERTY = 0x6474E553  # GNU-specific: Points to GNU property
PT_HIOS = 0x6FFFFFFF  # End of OS-specific types
PT_LOPROC = 0x70000000  # Start of processor-specific types
PT_HIPROC = 0x7FFFFFFF  # End of processor-specific types

# Program header flags
PF_X = 0x1  # Segment is executable
PF_W = 0x2  # Segment is writable
PF_R = 0x4  # Segment is readable


class ElfExecutable(Executable):
    def __init__(
        self,
        file: typing.BinaryIO,
        user_base: typing.Optional[int] = None,
        page_size: int = 0x1000,
    ):
        # Initialize with null address and size;
        # we will update these later.
        super().__init__(0, 0)
        self.bounds: typing.List[range] = []
        self._page_size = page_size
        self._user_base = user_base
        self._file_base = 0

        # Read the entire image out of the file.
        image = file.read()

        # Use lief to check if this is an ELF.
        # NOTE: For some reason, this takes list(int), not bytes
        if not lief.is_elf(list(image)):
            raise ConfigurationError("Image is not an ELF")

        # Use lief to parse the ELF.
        # NOTE: For some reason, this takes list(int), not bytes
        elf = lief.ELF.parse(list(image))
        if elf is None:
            raise ConfigurationError("Failed parsing ELF")

        # Extract the file header
        ehdr = elf.header
        if ehdr is None:
            raise ConfigurationError("Failed extracting ELF header")

        # TODO: Check machine compatibility

        # Figure out if this file is loadable.
        # If there are program headers, it's loadable.
        # This doesn't support .ko files, are relocatable objects,
        # and have no program headers.
        if ehdr.program_header_offset == 0:
            # No program headers; not a loadable ELF.
            raise ConfigurationError("ELF is not loadable")

        if ehdr.program_header_offset >= len(image):
            # Obviously-invalid program headers
            raise ConfigurationError(
                f"Invalid program header offset {hex(ehdr.program_header_offset)}"
            )

        # Determine the file base address.
        self._file_base = elf.imagebase
        self._determine_base()

        # Determine if the file specifies an entrypoint
        if elf.entrypoint is not None and elf.entrypoint != 0:
            # Check if the entrypoint is valid (falls within the image)
            entrypoint = elf.entrypoint - self._file_base
            if entrypoint < 0 or entrypoint >= len(image):
                raise ConfigurationError(
                    f"Invalid entrypoint address {hex(entrypoint)}"
                )
            # Entrypoint is relative to the file base; rebase it to whatever base we picked.
            self.entrypoint = entrypoint + self.address
        else:
            # No entrypoint specified
            self.entrypoint = None

        for phdr in elf.segments:
            log.debug(f"{phdr}")
            if phdr.type == PT_LOAD:
                # Loadable segment
                # Map its data into memory
                self._map_segment(phdr, image)
            elif phdr.type == PT_DYNAMIC:
                # Dynamic linking metadata.
                # This ELF needs dynamic linking
                hint = Hint(message="Program includes dynamic linking metadata")
                hinter.info(hint)
            elif phdr.type == PT_INTERP:
                # Program interpreter
                # This completely changes how program loading works.
                # Whether you care is a different matter.
                interp = image[phdr.file_offset : phdr.file_offset + phdr.physical_size]
                hint = Hint(message=f"Program specifies interpreter {interp!r}")
                hinter.info(hint)
            elif phdr.type == PT_NOTE:
                # Auxiliary information
                # Possibly useful for comparing machine/OS type.
                pass
            elif phdr.type == PT_PHDR:
                # Program header self-reference
                # Useful for the dynamic linker, but not for us
                pass
            elif phdr.type == PT_TLS:
                # TLS Segment
                # Your analysis is about to get nasty :(
                hint = Hint(message="Program includes thread-local storage")
                hinter.info(hint)
            elif phdr.type == PT_GNU_EH_FRAME:
                # Exception handler frame.
                # GCC puts one of these in everything.  Do we care?
                pass
            elif phdr.type == PT_GNU_STACK:
                # Stack executability
                # If this is missing, assume executable stack
                hint = Hint(message="Program specifies stack permissions")
                hinter.info(hint)
            elif phdr.type == PT_GNU_RELRO:
                # Read-only after relocation
                # Only the dynamic linker should write this data.
                hint = Hint(message="Program specifies RELRO data")
                hinter.info(hint)
            elif phdr.type == PT_GNU_PROPERTY:
                # GNU property segment
                # Contains extra metadata which I'm not sure anything uses
                pass
            elif phdr.type >= PT_LOOS and phdr.type <= PT_HIOS:
                # Unknown OS-specific program header
                # Either this is a weird ISA that extends the generic GNU ABI,
                # or this isn't a Linux ELF.
                hint = Hint(f"Unknown OS-specific program header: {phdr.type:08x}")
                hinter.warn(hint)
            elif phdr.type >= PT_LOPROC and phdr.type <= PT_HIPROC:
                # Unknown machine-specific program header
                # This is probably a non-Intel ISA.
                # Most of these are harmless, serving to tell the RTLD
                # where to find machine-specific metadata
                hint = Hint(f"Unknown machine-specific program header: {phdr.type:08x}")
                hinter.warn(hint)
            else:
                # Unknown program header outside the allowed custom ranges
                hint = Hint(f"Invalid program header: {phdr.type:08x}")
                hinter.warn(hint)

        # Compute the final total capacity
        for offset, value in self.items():
            self.size = max(self.size, offset + value.get_size())

    def _determine_base(self):
        # Determine the base address of this image
        #
        # Normally, the loader respects the wishes of the file;
        # an external base address is only used if the image doesn't define one.
        #
        # Here, the user doesn't know the image layout ahead of time,
        # and may need to adjust their environment to fit,
        # so a user-provided base is given equal weight.
        #
        # If both base addresses are specified,
        # or neither is specified, it's a configuratione rror.

        if self._user_base is None:
            # No user base requested
            if self._file_base == 0:
                # No file base defined.
                # Need the user to provide one
                raise ConfigurationError(
                    "No base address provided for position-independent ELF image"
                )
            else:
                self.address = self._file_base
        else:
            # User base requested
            if self._file_base == 0:
                # No file base requested; we are okay with this.
                self.address = self._user_base
            elif self._user_base == self._file_base:
                # Everyone requested the same base address, so we're okay.
                self.address = self._user_base
            else:
                # File base is defined.
                # We (probably) cannot move the image without problems.
                raise ConfigurationError("Base address defined for fixed-position ELF")

    def _rebase_file(self, val: int):
        # Rebase an offset from file-relative to image-relative
        return val - self._file_base + self.address

    def _page_align(self, val: int, up: bool = True):
        # Align an address to a page boundary
        # There are a number of cases where ELF files are imprecise;
        # they rely on the kernel/libc to map things at page-aligned addresses.
        if up:
            val += self._page_size - 1
        return (val // self._page_size) * self._page_size

    def _map_segment(self, phdr, image):
        # Compute segment boundaries
        seg_start = self._page_align(phdr.file_offset, up=False)
        seg_end = self._page_align(phdr.file_offset + phdr.physical_size)
        seg_addr = self._page_align(self._rebase_file(phdr.virtual_address), up=False)
        seg_size = self._page_align(phdr.virtual_size + (phdr.file_offset - seg_start))

        log.debug("Mapping: ")
        log.debug(f"    f: [ {seg_start:012x} -> {seg_end:012x} ]")
        log.debug(f"    m: [ {seg_addr:012x} -> {seg_addr + seg_size:012x} ]")

        # Extract segment data
        seg_data = image[seg_start:seg_end]
        if len(seg_data) < seg_size:
            # Segment is shorter than is available from the file;
            # this will get zero-padded.
            seg_data += b"\0" * (seg_size - (seg_start - seg_end))
        elif len(seg_data) != seg_size:
            raise ConfigurationError(
                f"Expected segment of size {seg_size}, but got {len(seg_data)}"
            )
        if (phdr.flags & PF_X) != 0:
            # This is a code segment; add it to program bounds
            self.bounds.append(range(seg_addr, seg_addr + seg_size))

        # Add the segment to the memory map
        seg_value = BytesValue(seg_data, None)
        self[seg_addr - self.address] = seg_value
