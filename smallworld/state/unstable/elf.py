import logging
import typing

import lief

from ..emulators import Emulator
from ..exceptions import ConfigurationError
from ..hinting import Hint, get_hinter
from .state import Code, Memory

log = logging.getLogger(__name__)
hinter = get_hinter(__name__)

# Prorgam header types
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


class ELFImage(Code):
    default_base = 0x400000
    page_size = 0x1000

    def __init__(
        self,
        image: bytes,
        format: typing.Optional[str] = None,
        arch: typing.Optional[str] = None,
        mode: typing.Optional[str] = None,
        base: typing.Optional[int] = None,
        entry: typing.Optional[int] = None,
        bounds: typing.Optional[typing.Iterable[range]] = None,
    ):
        super().__init__(
            image,
            base=0,
            format=format,
            arch=arch,
            mode=mode,
            entry=None,
            bounds=bounds,
        )
        self.user_base: typing.Optional[int] = base
        self.file_base: int = 0
        self.user_entry: typing.Optional[int] = entry
        self.file_entry: int = 0

        self.code_segments: typing.List[Code] = list()
        self.data_segments: typing.List[Memory] = list()

        self.load_elf()

    def determine_base(self):
        """Determine base address to load ELF

        There are two possible sources for a base address.
        ELF files can specify a base address by setting the address
        of their first loaded segment to non-zero.
        Otherwise, a user can request a specific base address.

        If both the user and the file specify an address, it's an error.
        If only one specifies a base address, use it.
        If neither specify one, halucinate a value.

        Raises:
            ConfigurationError: If file_base is non-zero, and user_base is not None
        """
        if self.user_base is None:
            # No base address requested
            if self.file_base == 0:
                # Progam file does not need a specific base address
                # Use a default
                # FIXME: Using a fixed value will not be valid if we load multiple files
                hint = Hint(
                    message=f"No base address requested, and ELF is PIC.  Using {hex(self.default_base)}"
                )
                hinter.info(hint)
                self.base = self.default_base
            else:
                # Program file needs a specific base address
                # Use the specified address
                self.base = self.file_base
        else:
            # Base address requested
            if self.file_base == 0:
                # Program file does not need a specific base address
                # Use the requested address
                self.user_base
            elif self.file_base == self.user_base:
                # User and file request the same base address.
                # We are okay with this.
                self.user_base
            else:
                # Program file needs a specific base address
                # Not possible to rebase
                hint = Hint(
                    message=f"Requested base address {hex(self.user_base)}, but program needs {hex(self.file_base)}"
                )
                hinter.error(hint)
                raise ConfigurationError("Contradictory base addresses.")

    def determine_entry(self):
        """Determine entrypoint address to use

        This performs two jobs.
        One is to determine which entrypoint to use;
        it can be specified by the ELF header, or by the user.

        The second job is to rebase that address
        according to the base address.
        An entrypoint from the file is relative to the file's base address.
        An entrypoint from the user is assumed relative to the user's base address.
        If the user does not specify a base address, their entrypoint
        should be relative to the start of the file.

        Raises:
            ConfigurationError: If neither user nor file specify an entrypoint

        """
        if self.user_entry is None:
            # No entrypoint requested.
            # Get entry from the file
            if self.file_entry == 0:
                # No one specified an entrypoint.
                # No entrypoint will be set for this file.
                self.entry = None
            # file_entry is relative to file_base; rebase relative to base
            self.entry = self.file_entry - self.file_base + self.base
        else:
            # Entrypoint requested.
            if self.user_base is None:
                user_base = 0
            else:
                user_base = self.user_base
            # user_entry is relative to user_base, or zero if none requested
            # rebase relative to base
            self.entry = self.user_entry - user_base + self.base

    def rebase_user(self, addr: int):
        """Helper function for rebasing user-relative addresses"""
        if self.user_base is None:
            old_base = 0
        else:
            old_base = self.user_base
        if self.base is None:
            base = 0
        else:
            base = self.base
        return addr - old_base + base

    def rebase_file(self, addr: int):
        """Helper function for rebasing file-relative addresses"""
        if self.base is None:
            base = 0
        else:
            base = self.base
        return addr - self.file_base + base

    def page_align(self, x: int, up: bool = True):
        """Align an address to a page boundary

        Arguments:
            x (int): Address to align
            up (bool): If true, round up.  If false, round down

        Return:
            (int): Aligned version of the address
        """
        if up:
            x += self.page_size - 1
        return (x // self.page_size) * self.page_size

    def load_elf(self):
        """Load an ELF file into a SmallWorld machine state object.

        This parses the ELF header and the program headers,
        does minimal validation, and then maps the loadable segments into memory.
        It also reports RE-relevant features of the binary as hints.

        This function assumes that the program should be loaded
        using the architecture and mode from the CPU object.

        The user can specify a base address and entrypoint.
        If not specified, this function defaults to the addresses specified in the ELF.

        If both user and ELF specify a base address,
        this function will raise an exception.

        If netither user nor ELF specify a base address,
        a default will be used.

        If both user and ELF specify an entrypoint,
        the user's entrypoint takes precedence.

        If neither user nor elf specify an entrypoint,
        no entrypoint will be set for this file.

        Raises:
            ConfigurationError: If the ELF is invalid, or user-provided data conflicts with ELF.
        """
        # Use lief to check if this is an ELF
        # NOTE: for some reason, this takes list[int], not bytes
        if not lief.is_elf(list(self.image)):
            hint = Hint(message="File is not an elf.")
            hinter.error(hint)
            raise ConfigurationError("Input is not an elf")

        # Use lief to parse the ELF
        # NOTE: for some reason, this takes list[int], not bytes
        elf = lief.ELF.parse(list(self.image))
        if elf is None:
            raise ConfigurationError("Failed parsing input")

        ehdr = elf.header
        if ehdr is None:
            raise ConfigurationError("Failed extracting Elf header")

        # TODO: Check machine compatibility?
        # - ei_class
        # - ei_data
        # - ei_osabi (some ABIs)
        # - e_machine
        # - e_flags (some ABIs)

        # Figure out if this file is loadable.
        # Easiest way to tell is if there are program headers
        if ehdr.program_header_offset == 0:
            # NULL phoff means no program headers.
            # This file is not loadable; time to use another ELF loader.
            hint = Hint(message="No program headers; file is not loadable")
            hinter.error(hint)
            raise ConfigurationError("File not loadable")
        if ehdr.program_header_offset >= len(self.image):
            hint = Hint(
                message=f"Invalid program header offset: {hex(ehdr.program_header_offset)}"
            )
            hinter.error(hint)
            raise ConfigurationError("Invalid program header offset")

        # Determine the file base address,
        # entrypoint, and exit points
        self.file_base = elf.imagebase
        self.file_entry = elf.entrypoint
        self.determine_base()
        self.determine_entry()
        self.exits = list(map(lambda x: self.rebase_user(x), self.exits))

        for phdr in elf.segments:
            log.debug(f"{phdr}")
            if phdr.type == PT_LOAD:
                # Loadable segment
                # Map its data into memory
                self.map_segment(phdr)
            elif phdr.type == PT_DYNAMIC:
                # Dynamic linking metadata.
                # This ELF needs dynamic linking
                hint = Hint(message="Program includes dynamic linking metadata")
                hinter.info(hint)
            elif phdr.type == PT_INTERP:
                # Program interpreter
                # This completely changes how program loading works.
                # Whether you care is a different matter.
                interp = self.image[
                    phdr.file_offset : phdr.file_offset + phdr.physical_size
                ]
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

    def map_segment(self, phdr):
        """Map a segment into a SmallWorld machine state object

        This computes the actual mapping boundaries from a LOAD segment,
        and then maps it into Smallworld.

        Executable segments are mapped as Code objects.
        Other segments are mapped as Memory.

        Arguments:
            phdr: Program header object to load
        """

        # Compute segment boundaries
        seg_start = self.page_align(phdr.file_offset, up=False)
        seg_end = self.page_align(phdr.file_offset + phdr.physical_size)
        seg_addr = self.page_align(self.rebase_file(phdr.virtual_address), up=False)
        seg_size = self.page_align(phdr.virtual_size + (phdr.file_offset - seg_start))

        log.debug(f"{phdr.physical_size:012x}")

        log.debug("Mapping: ")
        log.debug(f"    f: [ {seg_start:012x} -> {seg_end:012x} ]")
        log.debug(f"    m: [ {seg_addr:012x} -> {seg_addr + seg_size:012x} ]")

        # Extract segment data, and zero-fill out to seg_size
        seg_data = self.image[seg_start:seg_end]
        if len(seg_data) < seg_size:
            seg_data += b"\x00" * (seg_size - len(seg_data))
        elif len(seg_data) != seg_size:
            # Virtual size should always be greater or equal to file size.
            # If not, something's wrong.
            raise ConfigurationError(
                f"Expected segment of size {seg_size}, but got {len(seg_data)}"
            )

        if (phdr.flags & PF_X) != 0:
            # If this is an executable segment, treat it as code
            code = Code(
                image=seg_data,
                format="blob",
                arch=self.arch,
                mode=self.mode,
                base=seg_addr,
                entry=self.entry,
                exits=self.exits,
            )
            self.code_segments.append(code)
        else:
            # Otherwise, treat it as Memory
            data = Memory(seg_addr, seg_size)
            data.set(seg_data)
            self.data_segments.append(data)

    def apply(self, emulator: Emulator, override: bool = True):
        for code in self.code_segments:
            code.apply(emulator)
        for data in self.data_segments:
            data.apply(emulator)
