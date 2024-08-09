import logging
import typing

import lief

from ..emulators import Emulator
from ..exceptions import ConfigurationError
from ..hinting import Hint, getHinter
from .state import Code, Memory

log = logging.getLogger(__name__)
hinter = getHinter(__name__)

MEM_EXECUTE = 536870912
MEM_READ = 1073741824
MEM_WRITE = 2147483648


class PEImage(Code):
    default_base = 0x140000000
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
            entry=entry,
            bounds=bounds,
        )
        # pdb.set_trace()
        self.user_base: typing.Optional[int] = base
        self.file_base: int = 0
        self.user_entry: typing.Optional[int] = entry
        self.file_entry: int = 0
        self.code_segments: typing.List[Code] = list()
        self.data_segments: typing.List[Memory] = list()

        self.load_pe()

    def determine_base(self):
        """Determine base address to load PE

        There are two possible sources for a base address.
        PE files can specify a base address by setting the address
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
                    message=f"No base address requested, and PE is PIC.  Using {hex(self.default_base)}"
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
                self.base = self.user_base
            elif self.file_base == self.user_base:
                # User and file request the same base address.
                # We are okay with this.
                self.base = self.user_base
                logging.debug(f"USER BASE = {self.user_base}")
                logging.debug(f"FILE BASE = {self.file_base}")
                logging.debug(f"BASE = {self.base}")
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
        it can be specified by the PE header, or by the user.

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
        logging.debug(f"ENTRY = {self.entry}")

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

    def load_pe(self):
        """Load a PE file into a SmallWorld machine state object."""
        # ijfdhsfghgf()
        # pdb.set_trace()
        log.debug("HERE I AM")
        # pdb.set_trace()
        if not lief.is_pe(list(self.image)):
            hint = Hint(message="File is not a PE.")
            hinter.error(hint)
            raise ConfigurationError("Input is not a PE")

        pe = lief.PE.parse(list(self.image))
        if pe is None:
            raise ConfigurationError("Failed parsing input")

        p_doshdr = pe.dos_header
        if p_doshdr is None:
            raise ConfigurationError("Failed extracting PE DOS Header")

        phdr = pe.header
        if phdr is None:
            raise ConfigurationError("Failed extracting PE Header")

        p_opthdr = pe.optional_header
        if p_opthdr is None:
            raise ConfigurationError("Failed extracting PE Optional Header")

        if p_opthdr.sizeof_headers == 0:
            hint = Hint(message="No program headers; file is not loadable")
            hinter.error(hint)
            raise ConfigurationError("File not loadable")

        self.file_base = pe.imagebase
        self.file_entry = pe.entrypoint
        self.determine_base()
        self.determine_entry()
        # self.exits = list(map(lambda x: self.rebase_user(x), self.exits))

        for hdr in pe.sections:
            if hdr.virtual_size != 0:
                log.debug(hdr)
                self.map_segment(hdr)

    def map_segment(self, hdr):
        """Map a segment into a SmallWorld machine state object

        This computes the actual mapping boundaries from a LOAD segment,
        and then maps it into Smallworld.

        Executable segments are mapped as Code objects.
        Other segments are mapped as Memory.

        Arguments:
            phdr: Program header object to load
        """

        seg_start = self.page_align(hdr.offset, up=False)
        seg_end = self.page_align(hdr.offset + hdr.size)
        seg_addr = self.page_align(
            self.rebase_file(self.file_base + hdr.virtual_address), up=False
        )
        # seg_size = self.page_align(hdr.virtual_size + (hdr.offset - seg_start))
        seg_size = hdr.sizeof_raw_data

        log.debug(f"{hdr.size:012x}")

        log.debug("Mapping: ")
        log.debug(f"    f: [ {seg_start:012x} -> {seg_end:012x} ]")
        log.debug(f"    m: [ {seg_addr:012x} -> {seg_addr + seg_size:012x} ]")

        # Extract segment data, and zero-fill out to seg_size
        seg_data = bytes(hdr.content)
        if MEM_EXECUTE in hdr.characteristics_lists:
            # If this is an executable segment, treat it as code
            log.debug(f"Mapping executable {hdr.name}")
            log.debug(f"Amount of bytes: {hex(len(seg_data))}")
            code = Code(
                image=seg_data,
                format="PE",
                arch=self.arch,
                mode=self.mode,
                base=seg_addr,
                entry=self.entry,
            )
            self.code_segments.append(code)
            log.debug(f"Code: {code}")
        else:
            # Otherwise, treat it as Memory
            data = Memory(seg_addr, seg_size)
            data.value = seg_data
            self.data_segments.append(data)
            log.debug(f"Memory: {hex(data.address)}")

    def apply(self, emulator: Emulator, override: bool = True):
        for code in self.code_segments:
            code.apply(emulator)
        for data in self.data_segments:
            data.apply(emulator)
