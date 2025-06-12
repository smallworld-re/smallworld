import logging
import typing

import lief

from ....exceptions import ConfigurationError
from ....hinting import Hint, get_hinter
from ....platforms import Architecture, Byteorder, Platform
from ....utils import RangeCollection
from ...state import BytesValue
from ..code import Executable
from .rela import ElfRelocator
from .structs import ElfRela, ElfSymbol

log = logging.getLogger(__name__)
hinter = get_hinter(__name__)

# ELF machine values
# See /usr/include/elf.h for the complete list
EM_386 = 3  # Intel 80386
EM_MIPS = 8  # MIPS; all kinds
EM_PPC = 20  # PowerPC 32-bit
EM_PPC64 = 21  # PowerPC 64-bit
EM_ARM = 40  # ARM 32-bit
EM_X86_64 = 62  # AMD/Intel x86-64
EM_XTENSA = 94  # Xtensa
EM_AARCH64 = 183  # ARM v9, or AARCH64
EM_RISCV = 243  # RISC-V

# ARM-specific flag values
EF_ARM_VFP_FLOAT = 0x400
EF_ARM_SOFT_FLOAT = 0x200
EF_ARM_EABI_VER5 = 0x05000000

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

# Universal dynamic tag values
DT_PLTGOT = 0x3

# MIPS-specific dynamic tag values
DT_MIPS_LOCAL_GOTNO = 0x7000000A
DT_MIPS_GOTSYM = 0x70000013

# MIPS-specific relocation type
R_MIPS_32 = 2
R_MIPS_64 = 18


class ElfExecutable(Executable):
    """Executable loaded from an ELF

    This loads a single ELF file into a SmallWorld memory object.
    It performs no relocation or any other initialization,
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
        # we will update these later.
        super().__init__(0, 0)
        self.platform = platform
        self.bounds: RangeCollection = RangeCollection()
        self._page_size = page_size
        self._user_base = user_base
        self._file_base = 0

        # Initialize dynamic tag info
        self._dtags: typing.Dict[int, int] = dict()

        # Initialize symbol info
        self._dynamic_symbols: typing.List[ElfSymbol] = list()
        self._static_symbols: typing.List[ElfSymbol] = list()
        self._dynamic_relas: typing.List[ElfRela] = list()
        self._static_relas: typing.List[ElfRela] = list()
        self._syms_by_name: typing.Dict[str, typing.List[ElfSymbol]] = dict()
        self._relocator: typing.Optional[ElfRelocator] = None

        # Read the entire image out of the file.
        image = file.read()

        # Use lief to check if this is an ELF.
        # NOTE: For some reason, this takes list(int), not bytes
        if not lief.is_elf(list(image)):
            raise ConfigurationError("Image is not an ELF")

        # Use lief to parse the ELF.
        # NOTE: For some reason, this takes list(int), not bytes
        # NOTE: lief objects aren't deep-copyable.
        # I'd love to keep `elf` around for later use, but I can't.
        elf = lief.ELF.parse(list(image))
        if elf is None:
            raise ConfigurationError("Failed parsing ELF")

        # Extract the file header
        ehdr = elf.header
        if ehdr is None:
            raise ConfigurationError("Failed extracting ELF header")

        # Check machine compatibility
        if not ignore_platform:
            hdr_platform = self._platform_for_ehdr(elf)
            if self.platform is not None:
                if self.platform != hdr_platform:
                    raise ConfigurationError(
                        "Platform mismatch: "
                        f"specified {self.platform}, but got {hdr_platform} from header"
                    )
            else:
                self.platform = hdr_platform

        if self.platform is not None:
            # If we have a platform, we can relocate
            self._relocator = ElfRelocator.for_platform(self.platform)

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
                hint = Hint(
                    f"Unknown machine-specific program header: {phdr.type.value:08x}"
                )
                hinter.warn(hint)
            else:
                # Unknown program header outside the allowed custom ranges
                hint = Hint(f"Invalid program header: {phdr.type.value:08x}")
                hinter.warn(hint)

        # Compute the final total capacity
        for offset, value in self.items():
            self.size = max(self.size, offset + value.get_size())

        # Determine if the file specifies an entrypoint
        if elf.entrypoint is not None and elf.entrypoint != 0:
            # Check if the entrypoint is valid (falls within the image)
            entrypoint = self._rebase_file(elf.entrypoint)
            if not self.bounds.contains_value(entrypoint):
                if (
                    self.platform is not None
                    and self.platform.architecture == Architecture.POWERPC64
                ):
                    # NOTE: PowerPC64's ABI is trippy.
                    # It uses "function descriptor" structs instead of
                    # simple function pointers.
                    # Thus, the entrypoint points to something in the data section.
                    log.warn("Entrypoint for PowerPC64 file is not a code address")
                else:
                    raise ConfigurationError(
                        f"Invalid entrypoint address {hex(entrypoint)}"
                    )
            else:
                self.entrypoint = entrypoint
        else:
            # No entrypoint specified,
            # Or this is PowerPC64 and the entrypoint is gibberish
            self.entrypoint = None

        # Organize dynamic tags
        self._extract_dtags(elf)

        # Organize symbols for later relocation
        self._extract_symbols(elf)

    def _platform_for_ehdr(self, elf):
        # Determine byteorder.  This bit's easy
        if elf.header.identity_data.value == 1:
            # LSB byteorder
            byteorder = Byteorder.LITTLE
        elif elf.header.identity_data.value == 2:
            # MSB byteorder
            byteorder = Byteorder.BIG
        else:
            raise ConfigurationError(
                f"Unknown value of ei_data: {hex(elf.header.identity_data.value)}"
            )

        # Determine arch/mode.  This bit's harder.
        if elf.header.machine_type.value == EM_X86_64:
            # amd64
            architecture = Architecture.X86_64
        elif elf.header.machine_type.value == EM_AARCH64:
            # aarch64
            architecture = Architecture.AARCH64
        elif elf.header.machine_type.value == EM_386:
            # i386
            architecture = Architecture.X86_32
        elif elf.header.machine_type.value == EM_ARM:
            # Some kind of arm32
            flags = set(map(lambda x: x.value, elf.header.arm_flags_list))

            if EF_ARM_EABI_VER5 in flags and EF_ARM_SOFT_FLOAT in flags:
                # This is either ARMv5T or some kind of ARMv6.
                # We're currently assuming v5T, but this isn't always correct.
                architecture = Architecture.ARM_V5T
            elif EF_ARM_EABI_VER5 in flags and EF_ARM_VFP_FLOAT in flags:
                # This is ARMv7a, as built by gcc.
                architecture = Architecture.ARM_V7A
            else:
                # The file might be a core dump or some uncommon flavor of ARM.
                # Fallback to a default if flags are missing.
                log.warning(
                    f"No recognized ARM flags found. flags={list(map(hex, flags))}, "
                    "defaulting to ARM_V7A."
                )
                architecture = Architecture.ARM_V7A
        elif elf.header.machine_type.value == EM_MIPS:
            # Some kind of mips.
            # TODO: There are more parameters than just word size
            if elf.header.identity_class.value == 1:
                # 32-bit ELF
                architecture = Architecture.MIPS32
            elif elf.header.identity_class.value == 2:
                architecture = Architecture.MIPS64
            else:
                raise ConfigurationError(
                    f"Unknown value of ei_class: {hex(elf.header.identity_class.value)}"
                )
        elif elf.header.machine_type.value == EM_PPC:
            # PowerPC 32-bit
            architecture = Architecture.POWERPC32
        elif elf.header.machine_type.value == EM_PPC64:
            # PowerPC 64-bit
            architecture = Architecture.POWERPC64
        elif elf.header.machine_type.value == EM_RISCV:
            # RISC-V
            if elf.header.identity_class.value == 1:
                raise ConfigurationError("RISC-V 32-bit isn't supported")
            elif elf.header.identity_class.value == 2:
                architecture = Architecture.RISCV64
            else:
                raise ConfigurationError(
                    f"Unknown value of ei_class: {hex(elf.header.identity_class.value)}"
                )
        elif elf.header.machine_type.value == EM_XTENSA:
            architecture = Architecture.XTENSA
        else:
            raise ConfigurationError(
                f"Unknown value of e_machine: {hex(elf.header.machine_type.value)}"
            )
        return Platform(architecture, byteorder)

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
        log.info(f"Address: {self.address:x}")

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
        log.debug(
            f"    f: [ {seg_start:012x} -> {seg_end:012x} ] ( {seg_end - seg_start:x} bytes )"
        )
        log.debug(
            f"    m: [ {seg_addr:012x} -> {seg_addr + seg_size:012x} ] ( {seg_size:x} bytes )"
        )

        # Extract segment data
        seg_data = image[seg_start:seg_end]
        if len(seg_data) < seg_size:
            # Segment is shorter than is available from the file;
            # this will get zero-padded.
            pad_size = seg_size - len(seg_data)
            log.debug(f"Padding segment by {pad_size} bytes")
            seg_data += b"\0" * pad_size
        if len(seg_data) != seg_size:
            raise ConfigurationError(
                f"Expected segment of size {seg_size}, but got {len(seg_data)}"
            )
        if (phdr.flags & PF_X) != 0:
            # This is a code segment; add it to program bounds
            self.bounds.add_range((seg_addr, seg_addr + seg_size))

        # Add the segment to the memory map
        seg_value = BytesValue(seg_data, None)
        assert (
            seg_value._size == seg_size
        ), f"Expected {seg_size:x} bytes, got {seg_value._size:x}"
        self[seg_addr - self.address] = seg_value

    def _extract_dtags(self, elf):
        for dt in elf.dynamic_entries:
            self._dtags[dt.tag.value] = dt.value

    def _extract_symbols(self, elf):
        lief_to_elf = dict()

        # Figure out the base address
        # TODO: Currently, this only handles PIC or Non-PIC
        # It will be wrong for .o and .ko
        if self._file_base is not None and self._file_base != 0:
            # This is a non-PIC binary.
            # Dollars to ducats the symbol is absolute.
            baseaddr = 0
        else:
            # This is a PIC binary
            # Relative symbols will be relative to the load address
            baseaddr = self.address

        dynsyms = set(elf.dynamic_symbols)
        idx = 0
        dynamic = True
        for s in elf.symbols:
            # Lief lets you access dynamic symbols separately,
            # but you need to access static symbols through
            # the list of all symbols
            if dynamic and s not in dynsyms:
                idx = 0
                dynamic = False

            # Build a symbol
            sym = ElfSymbol(
                idx=idx,
                dynamic=dynamic,
                name=s.name,
                type=s.type.value,
                bind=s.binding.value,
                visibility=s.visibility.value,
                shndx=s.shndx,
                value=s.value,
                size=s.size,
                baseaddr=baseaddr,
                defined=(s.shndx != 0),
            )
            # Save the sym, and temporarily tie it to its lief partner
            if dynamic:
                self._dynamic_symbols.append(sym)
            else:
                self._static_symbols.append(sym)

            self._syms_by_name.setdefault(sym.name, list()).append(sym)
            lief_to_elf[s] = sym

        if (
            self.platform.architecture == Architecture.MIPS32
            or self.platform.architecture == Architecture.MIPS64
        ):
            # All MIPS dynamic symbols have an implicit rela.
            # MIPS dynamic symbols always have a GOT entry;
            # to save space, the ABI just assumes that the rela exists
            if (
                DT_MIPS_GOTSYM not in self._dtags
                or DT_MIPS_LOCAL_GOTNO not in self._dtags
                or DT_PLTGOT not in self._dtags
            ):
                # GOT is missing... not sure what's up.
                log.error("MIPS binary missing GOT information")
            else:
                # We found the GOT info; we're actually a dynamic binary
                # Figure out the GOT entry size based on arch
                gotsym = self._dtags[DT_MIPS_GOTSYM]
                local_gotno = self._dtags[DT_MIPS_LOCAL_GOTNO]
                gotoff = self._dtags[DT_PLTGOT]

                if self.platform.architecture == Architecture.MIPS32:
                    gotent = 4
                    rela_type = R_MIPS_32
                else:
                    gotent = 8
                    rela_type = R_MIPS_64

                # Rebase the GOT offset relative to the image
                gotoff = self._rebase_file(gotoff)

                # Skip the first local_gotno entries
                gotoff += gotent * local_gotno

                for s in list(elf.dynamic_symbols)[gotsym:]:
                    sym = lief_to_elf[s]
                    rela = ElfRela(offset=gotoff, type=rela_type, symbol=sym, addend=0)
                    sym.relas.append(rela)
                    self._dynamic_relas.append(rela)

                    gotoff += gotent

        for r in list(elf.dynamic_relocations) + list(elf.pltgot_relocations):
            # Build a rela, and tie it to its symbol
            # TODO: some relas have no symbols.  Live with it.
            if r.symbol is None:
                continue
            sym = lief_to_elf[r.symbol]
            rela = ElfRela(
                offset=r.address + baseaddr, type=r.type, symbol=sym, addend=r.addend
            )
            sym.relas.append(rela)
            self._dynamic_relas.append(rela)

        for r in elf.object_relocations:
            if r.symbol is None:
                continue
            sym = lief_to_elf[r.symbol]
            rela = ElfRela(
                offset=r.address + baseaddr, type=r.type, symbol=sym, addend=r.addend
            )
            sym.relas.append(rela)
            self._static_relas.append(rela)

    def _get_symbols(
        self, name: typing.Union[str, int], dynamic: bool
    ) -> typing.List[ElfSymbol]:
        if isinstance(name, str):
            # Caller wants to look up a symbol by name
            if name not in self._syms_by_name:
                raise ConfigurationError(f"No symbol named {name}")

            syms = self._syms_by_name[name]
            return list(syms)
        elif isinstance(name, int):
            if dynamic:
                return [self._dynamic_symbols[name]]
            else:
                return [self._static_symbols[name]]
        else:
            raise TypeError("Symbols must be specified by str names or int indexes")

    def get_symbol_value(
        self, name: typing.Union[str, int], dynamic: bool = False, rebase: bool = True
    ) -> int:
        """Get the value for a symbol

        The value of a symbol is usually an address or offset,
        although the precise meaning can vary a little.

        Arguments:
            name: The name of the symbol, or its index into the symbol table
            dynamic: If specified by index, whether to look in the static or dynamic symbol table
            rebase: Whether the recorded value is relative to the base address of this ELF.

        Returns:
            The integer value of this symbol
        """
        syms = self._get_symbols(name, dynamic)
        if len(syms) > 1:
            for sym in syms:
                if sym.value != syms[0].value and sym.baseaddr != syms[0].baseaddr:
                    raise ConfigurationError(f"Conflicting syms named {name}")

        val = syms[0].value
        if rebase:
            val += syms[0].baseaddr
        return val

    def get_symbol_size(self, name: typing.Union[str, int], dynamic: bool = False):
        """Get the size for a symbol

        If a symbol references a function or a data structure,
        this will hold its size in bytes

        Arguments:
            name: The name of the symbol, or its index into the symbol table
            dynamic: If specified by index, whether to look in the static or dynamic symbol table
            rebase: Whether the recorded value is relative to the base address of this ELF.

        Returns:
            The size of this symbol
        """
        syms = self._get_symbols(name, dynamic)
        if len(syms) > 1:
            for sym in syms:
                if sym.size != syms[0].size:
                    raise ConfigurationError(f"Conflicting syms named {name}")
        return syms[0].size

    def update_symbol_value(
        self,
        name: typing.Union[str, int, ElfSymbol],
        value: int,
        dynamic: bool = False,
        rebase: bool = True,
    ) -> None:
        """Update the value of a symbol

        This will alter the value of the symbol,
        and also propagate that updated value according to any associated relocations.

        Arguments:
            name: The name of the symbol, its index into the symbol table, or a specific symbol object
            value: The new value for the symbol
            dynamic: If specified by index, whether to look in the static or dynamic symbol table
            rebase: Whether the recorded value is relative to the base address of this ELF.
        """

        if isinstance(name, ElfSymbol):
            sym = name
        else:
            syms = self._get_symbols(name, dynamic)
            if len(syms) > 1:
                raise ConfigurationError(f"Multiple syms named {name}")
            sym = syms[0]

        if rebase:
            # Value provided is absolute; rebase it to the symbol's base address
            value -= sym.baseaddr

        # Update the value
        sym.value = value

        # Mark this symbol as defined
        sym.defined = True

        if self._relocator is not None:
            for rela in sym.relas:
                # Relocate!
                self._relocator.relocate(self, rela)
        else:
            log.error(f"No platform defined; cannot relocate {name}!")

    def link_elf(self, elf: "ElfExecutable", dynamic: bool = True) -> None:
        """Link one ELF against another

        This roughly mimics the ELF linker;
        it looks for undefined symbols in the current file,
        and tries to populate their values from matching defined symbols
        from another file.

        Arguments:
            elf: The ELF from which to draw symbol values
            dynamic: Whether to link static or dynamic symbols
        """
        if dynamic:
            # Relocate rela.dyn and rela.plt
            relas = self._dynamic_relas
        else:
            # relocate static relocations
            relas = self._static_relas

        for rela in relas:
            my_sym = rela.symbol
            if my_sym.name == "":
                # This isn't a real symbol
                continue
            if my_sym.defined:
                # This is a defined symbol
                continue

            try:
                o_syms = elf._get_symbols(my_sym.name, dynamic)
            except ConfigurationError:
                continue

            o_syms = list(filter(lambda x: x.defined, o_syms))
            if len(o_syms) == 0:
                continue

            if len(set(map(lambda x: x.value, o_syms))) > 1:
                # Catch multiple symbols
                # If they all have the same value, we don't care.
                log.warning(f"Multiple symbols for {my_sym.name}")
                continue

            o_sym = o_syms[0]
            self.update_symbol_value(my_sym, o_sym.value + o_sym.baseaddr, rebase=True)


__all__ = ["ElfExecutable"]
