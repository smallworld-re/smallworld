import ctypes
import logging
import typing

from .exceptions import ConfigurationError
from .hinting import Hint, getHinter
from .state import CPU, Code, Memory

log = logging.getLogger(__name__)
hinter = getHinter(__name__)


class Elf_EIDENT(ctypes.LittleEndianStructure):
    """Elf Identity array

    Encodes basic compatibility information in a machine-agnostic form.
    """

    _fields_ = [
        ("ei_magic", ctypes.c_byte * 4),  # Magic bytes; always b'\x7fELF'
        ("ei_class", ctypes.c_byte),  # Word-size: 32-bit or 64-bit
        ("ei_data", ctypes.c_byte),  # Byte order: LSB or MSB
        ("ei_version", ctypes.c_byte),  # File version; always b'\x01'
        ("ei_osabi", ctypes.c_byte),  # OS/ABI code.  Annoyingly, usually "none"
        ("ei_abi", ctypes.c_byte),  # ABI Version
        ("ei_pad", ctypes.c_byte * 7),  # Padding to bump this out to 16 bytes
    ]


class Elf32EL_Ehdr(ctypes.LittleEndianStructure):
    """ELF file header (32-bit LSB)

    Root-level struct of the entire file.
    Includes critical metadata, and references
    to the section and segment tables to navigate
    the rest of the file.
    """

    _fields_ = [
        ("e_ident", Elf_EIDENT),
        ("e_type", ctypes.c_uint16),
        ("e_machine", ctypes.c_uint16),
        ("e_version", ctypes.c_uint32),
        ("e_entry", ctypes.c_uint32),
        ("e_phoff", ctypes.c_uint32),
        ("e_shoff", ctypes.c_uint32),
        ("e_flags", ctypes.c_uint32),
        ("e_ehsize", ctypes.c_uint16),
        ("e_phentsize", ctypes.c_uint16),
        ("e_phnum", ctypes.c_uint16),
        ("e_shentsize", ctypes.c_uint16),
        ("e_shnum", ctypes.c_uint16),
        ("e_shstrndx", ctypes.c_uint16),
    ]


class Elf32BE_Ehdr(ctypes.BigEndianStructure):
    """ELF file header (32-bit MSB)

    Root-level struct of the entire file.
    Includes critical metadata, and references
    to the section and segment tables to navigate
    the rest of the file.
    """

    _fields_ = [
        ("e_ident", Elf_EIDENT),
        ("e_type", ctypes.c_uint16),
        ("e_machine", ctypes.c_uint16),
        ("e_version", ctypes.c_uint32),
        ("e_entry", ctypes.c_uint32),
        ("e_phoff", ctypes.c_uint32),
        ("e_shoff", ctypes.c_uint32),
        ("e_flags", ctypes.c_uint32),
        ("e_ehsize", ctypes.c_uint16),
        ("e_phentsize", ctypes.c_uint16),
        ("e_phnum", ctypes.c_uint16),
        ("e_shentsize", ctypes.c_uint16),
        ("e_shnum", ctypes.c_uint16),
        ("e_shstrndx", ctypes.c_uint16),
    ]


class Elf64EL_Ehdr(ctypes.LittleEndianStructure):
    """ELF file header (64-bit LSB)

    Root-level struct of the entire file.
    Includes critical metadata, and references
    to the section and segment tables to navigate
    the rest of the file.
    """

    _fields_ = [
        ("e_ident", Elf_EIDENT),
        ("e_type", ctypes.c_uint16),
        ("e_machine", ctypes.c_uint16),
        ("e_version", ctypes.c_uint32),
        ("e_entry", ctypes.c_uint64),
        ("e_phoff", ctypes.c_uint64),
        ("e_shoff", ctypes.c_uint64),
        ("e_flags", ctypes.c_uint32),
        ("e_ehsize", ctypes.c_uint16),
        ("e_phentsize", ctypes.c_uint16),
        ("e_phnum", ctypes.c_uint16),
        ("e_shentsize", ctypes.c_uint16),
        ("e_shnum", ctypes.c_uint16),
        ("e_shstrndx", ctypes.c_uint16),
    ]


class Elf64BE_Ehdr(ctypes.BigEndianStructure):
    """ELF file header (64-bit MSB)

    Root-level struct of the entire file.
    Includes critical metadata, and references
    to the section and segment tables to navigate
    the rest of the file.
    """

    _fields_ = [
        ("e_ident", Elf_EIDENT),
        ("e_type", ctypes.c_uint16),
        ("e_machine", ctypes.c_uint16),
        ("e_version", ctypes.c_uint32),
        ("e_entry", ctypes.c_uint64),
        ("e_phoff", ctypes.c_uint64),
        ("e_shoff", ctypes.c_uint64),
        ("e_flags", ctypes.c_uint32),
        ("e_ehsize", ctypes.c_uint16),
        ("e_phentsize", ctypes.c_uint16),
        ("e_phnum", ctypes.c_uint16),
        ("e_shentsize", ctypes.c_uint16),
        ("e_shnum", ctypes.c_uint16),
        ("e_shstrndx", ctypes.c_uint16),
    ]


Elf_Ehdr_type = typing.Union[
    Elf32BE_Ehdr, Elf32EL_Ehdr, Elf64BE_Ehdr, Elf64EL_Ehdr, None
]


class Elf32EL_Phdr(ctypes.LittleEndianStructure):
    """ELF program header (32-bit LSB)

    Effectively a command to the program loader.
    Describes a physical program segment,
    or metadata critical to the program loading process.
    """

    _fields_ = [
        ("p_type", ctypes.c_uint32),
        ("p_offset", ctypes.c_uint32),
        ("p_vaddr", ctypes.c_uint32),
        ("p_paddr", ctypes.c_uint32),
        ("p_filesz", ctypes.c_uint32),
        ("p_memsz", ctypes.c_uint32),
        ("p_flags", ctypes.c_uint32),
        ("p_align", ctypes.c_uint32),
    ]


class Elf32BE_Phdr(ctypes.BigEndianStructure):
    """ELF program header (32-bit MSB)

    Effectively a command to the program loader.
    Describes a physical program segment,
    or metadata critical to the program loading process.
    """

    _fields_ = [
        ("p_type", ctypes.c_uint32),
        ("p_offset", ctypes.c_uint32),
        ("p_vaddr", ctypes.c_uint32),
        ("p_paddr", ctypes.c_uint32),
        ("p_filesz", ctypes.c_uint32),
        ("p_memsz", ctypes.c_uint32),
        ("p_flags", ctypes.c_uint32),
        ("p_align", ctypes.c_uint32),
    ]


class Elf64EL_Phdr(ctypes.LittleEndianStructure):
    """ELF program header (64-bit LSB)

    Effectively a command to the program loader.
    Describes a physical program segment,
    or metadata critical to the program loading process.
    """

    _fields_ = [
        ("p_type", ctypes.c_uint32),
        ("p_flags", ctypes.c_uint32),
        ("p_offset", ctypes.c_uint64),
        ("p_vaddr", ctypes.c_uint64),
        ("p_paddr", ctypes.c_uint64),
        ("p_filesz", ctypes.c_uint64),
        ("p_memsz", ctypes.c_uint64),
        ("p_align", ctypes.c_uint64),
    ]


class Elf64BE_Phdr(ctypes.BigEndianStructure):
    """ELF program header (64-bit MSB)

    Effectively a command to the program loader.
    Describes a physical program segment,
    or metadata critical to the program loading process.
    """

    _fields_ = [
        ("p_type", ctypes.c_uint32),
        ("p_flags", ctypes.c_uint32),
        ("p_offset", ctypes.c_uint64),
        ("p_vaddr", ctypes.c_uint64),
        ("p_paddr", ctypes.c_uint64),
        ("p_filesz", ctypes.c_uint64),
        ("p_memsz", ctypes.c_uint64),
        ("p_align", ctypes.c_uint64),
    ]


Elf_Phdr_type = typing.Union[
    Elf32BE_Phdr, Elf32EL_Phdr, Elf64BE_Phdr, Elf64EL_Phdr, None
]


def Elf_Ehdr(elf: bytes, off: int, wordsize: int, byteorder: str):
    """Decode an ELF file header from a byte stream

    This picks the correct struct class based on word size and byteorder,
    and performs memory bounds checks to ensure we're not reading outside the file.

    Args:
        elf (bytes): Raw data from the ELF file
        off (int): Offset into the ELF to start reading from
        wordsize (int): Number of bits in an address expected by file.  Must be 32 or 64
        byteorder (str): Byte order expected by file.  Must be 'little' or 'big'.

    Returns:
        ELF file header struct object

    Raises:
        ConfigurationError: wordsize or byteorder are invalid, or off is out of bounds
    """
    out: Elf_Ehdr_type = None
    if wordsize == 32:
        if byteorder == "big":
            out = Elf32BE_Ehdr()
        elif byteorder == "little":
            out = Elf32EL_Ehdr()
        else:
            raise ConfigurationError(f"Unknown byteorder: {byteorder}")
    elif wordsize == 64:
        if byteorder == "big":
            out = Elf64BE_Ehdr()
        elif byteorder == "little":
            out = Elf64EL_Ehdr()
        else:
            raise ConfigurationError(f"Unknown byteorder: {byteorder}")
    else:
        raise ConfigurationError(f"Unknown wordsize: {wordsize}")

    left = len(elf) - off
    need = ctypes.sizeof(out)
    if left < need:
        raise ConfigurationError(f"Need {need} bytes, but only have {left}")
    ctypes.memmove(ctypes.pointer(out), elf[off : off + need], need)
    return out


def Elf_Phdr(elf: bytes, off: int, wordsize: int, byteorder: str):
    """Decode an ELF program header from a byte stream

    This picks the correct struct class based on word size and byteorder,
    and performs memory bounds checks to ensure we're not reading outside the file.

    Args:
        elf (bytes): Raw data from the ELF file
        off (int): Offset into the ELF to start reading from
        wordsize (int): Number of bits in an address expected by file.  Must be 32 or 64
        byteorder (str): Byte order expected by file.  Must be 'little' or 'big'.

    Returns:
        ELF file header struct object

    Raises:
        ConfigurationError: wordsize or byteorder are invalid, or off is out of bounds
    """
    out: Elf_Phdr_type = None
    if wordsize == 32:
        if byteorder == "big":
            out = Elf32BE_Phdr()
        elif byteorder == "little":
            out = Elf32EL_Phdr()
        else:
            raise ConfigurationError(f"Unknown byteorder: {byteorder}")
    elif wordsize == 64:
        if byteorder == "big":
            out = Elf64BE_Phdr()
        elif byteorder == "little":
            out = Elf64EL_Phdr()
        else:
            raise ConfigurationError(f"Unknown byteorder: {byteorder}")
    else:
        raise ConfigurationError(f"Unknown wordsize: {wordsize}")

    left = len(elf) - off
    need = ctypes.sizeof(out)
    if left < need:
        raise ConfigurationError(f"Need {need} bytes, but only have {left}")
    ctypes.memmove(ctypes.pointer(out), elf[off : off + need], need)
    return out


def parse_eident(elf: bytes):
    """Decode an ELF identity array

    This verifies that the file starts with a valid identity array,
    and reports the wordsize and byteorder.

    Returns:
        Tuple[int, str]: Tuple of (wordsize, byteorder), fit to be passed to other decoders

    Raises:
        ConfigurationError: If `elf` does not contain a valid ELF file
    """
    # load EIDENT
    eident = Elf_EIDENT()
    need = ctypes.sizeof(eident)
    if len(elf) < need:
        raise ConfigurationError(f"Need {need} bytes, but only have {len(elf)}")
    ctypes.memmove(ctypes.pointer(eident), elf[0:need], need)

    # Check ei_magic
    if bytes(eident.ei_magic) != b"\x7fELF":
        raise ConfigurationError(f"Invalid ELF magic: {bytes(eident.ei_magic)!r}")

    # Parse wordsize out of ei_class
    if eident.ei_class == 0x1:
        # 32-bit
        wordsize = 32
    elif eident.ei_class == 0x2:
        wordsize = 64
    else:
        raise ConfigurationError(f"Unknown ei_class: {eident.ei_data}")

    # Parse ei_data
    if eident.ei_data == 0x1:
        # 2s-compliment LSB
        byteorder = "little"
    elif eident.ei_data == 0x2:
        # 2s-compliment MSB
        byteorder = "big"
    else:
        raise ConfigurationError(f"Unknown ei_data: {eident.ei_data}")

    return (wordsize, byteorder)


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
phdr_types = {
    PT_NULL: "NULL",
    PT_LOAD: "LOAD",
    PT_DYNAMIC: "DYNAMIC",
    PT_INTERP: "INTERP",
    PT_NOTE: "NOTE",
    PT_SHLIB: "SHLIB",
    PT_PHDR: "PHDR",
    PT_TLS: "TLS",
    PT_GNU_EH_FRAME: "GNU_EH_FRAME",
    PT_GNU_STACK: "GNU_STACK",
    PT_GNU_RELRO: "GNU_RELRO",
    PT_GNU_PROPERTY: "GNU_PROPERTY",
}

# Program header flags
PF_X = 0x1  # Segment is executable
PF_W = 0x2  # Segment is writable
PF_R = 0x4  # Segment is readable


def print_phdr(i, phdr):
    """Pretty-print a program header

    Arguments:
        i (int): Index of phdr; just for printing
        phdr: Program header object
    """
    if phdr.p_type in phdr_types:
        kind = phdr_types[phdr.p_type]
    else:
        kind = hex(phdr.p_type)
    flag_bits = ["X", "W", "R"]
    flags = "".join(
        map(
            lambda x: flag_bits[x],
            filter(lambda x: ((1 << x) & phdr.p_flags) != 0, range(0, len(flag_bits))),
        )
    )
    log.debug(f"Phdr {i:2d}: t: {kind}, flags: {flags}")
    log.debug(f"    v: {phdr.p_vaddr:012x}, m: {phdr.p_memsz:012x}")
    log.debug(f"    o: {phdr.p_offset:012x}, f: {phdr.p_filesz:012x}")


def determine_base(file_base: int, user_base: typing.Optional[int]):
    """Determine base address to load ELF

    There are two possible sources for a base address.
    ELF files can specify a base address by setting the address
    of their first loaded segment to non-zero.
    Otherwise, a user can request a specific base address.

    If both the user and the file specify an address, it's an error.
    If only one specifies a base address, use it.
    If neither specify one, halucinate a value.

    Arguments:
        file_base (int): Base address requested by the ELF file
        user_base (typing.Optional[int]): Base address requested by the user

    Returns:
        (int) Base address to use when loading this file.

    Raises:
        ConfigurationError: If file_base is non-zero, and user_base is not None
    """
    if user_base is None:
        # No base address requested
        if file_base == 0:
            # Progam file does not need a specific base address
            # Use a default
            # FIXME: Using a fixed value will not be valid if we load multiple files
            default = 0x400000
            hint = Hint(
                message=f"No base address requested, and ELF is PIC.  Using {hex(default)}"
            )
            hinter.info(hint)
            return default
        else:
            # Program file needs a specific base address
            # Use the specified address
            return file_base
    else:
        # Base address requested
        if file_base == 0:
            # Program file does not need a specific base address
            # Use the requested address
            return user_base
        elif file_base == user_base:
            # User and file request the same base address.
            # We are okay with this.
            return user_base
        else:
            # Program file needs a specific base address
            # Not possible to rebase
            hint = Hint(
                message=f"Requested base address {hex(user_base)}, but program needs {hex(file_base)}"
            )
            hinter.error(hint)
            raise ConfigurationError("Contradictory base addresses.")


def determine_entry(
    file_entry: int,
    user_entry: typing.Optional[int],
    base: int,
    file_base: int,
    user_base: typing.Optional[int],
):
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

    Arguments:
        file_entry (int): Entrypoint specified by the ELF header
        user_entry (typing.Optional[int]): Entrypoint specified by the user
        base (int): Final base address used to load the file
        file_base (int): Base address specified by the file
        user_base (typing.Optional[int]): Base address specified by the user

    Returns:
        (typing.Optional[int]) Entrypoint address to be used when executing this file

    Raises:
        ConfigurationError: If neither user nor file specify an entrypoint

    """
    if user_entry is None:
        # No entrypoint requested.
        # Get entry from the file
        if file_entry == 0:
            # No one specified an entrypoint.
            # No entrypoint will be set for this file.
            return None
        # file_entry is relative to file_base; rebase relative to base
        return file_entry - file_base + base
    else:
        # Entrypoint requested.
        if user_base is None:
            user_base = 0
        # user_entry is relative to user_base, or zero if none requested
        # rebase relative to base
        return user_entry - user_base + base


def rebase_addr(addr: int, base: int, old_base: typing.Optional[int]):
    if old_base is None:
        old_base = 0
    return addr - old_base + base


def page_align(x: int, page_size: int = 0x1000, up: bool = True):
    """Align an address to a page boundary

    Arguments:
        x (int): Address to align
        page_size (int): System page size
        up (bool): If true, round up.  If false, round down

    Return:
        (int): Aligned version of the address
    """
    if up:
        x += page_size - 1
    return (x // page_size) * page_size


def map_segment(
    cpu: CPU,
    elf: bytes,
    phdr,
    baseaddr: int,
    filebase: int,
    entry: typing.Optional[int],
    exits: typing.List[int],
):
    """Map a segment into a SmallWorld machine state object

    This computes the actual mapping boundaries from a LOAD segment,
    and then maps it into Smallworld.

    Executable segments are mapped as Code objects.
    Other segments are mapped as Memory.

    Arguments:
        cpu (CPU): CPU object to populate
        elf (bytes): Raw binary of ELF file
        phdr: Program header object to load
        baseaddr (int): Base address to load the program at
        entry (typing.Optional[int]): Entrypoint address, if this is the entry binary
        exits (typing.List[int]): List of exit points in this binary
    """

    # Compute segment boundaries
    seg_start = page_align(phdr.p_offset, up=False)
    seg_end = page_align(phdr.p_offset + phdr.p_filesz)
    seg_size = page_align(phdr.p_memsz)
    seg_addr = page_align(rebase_addr(phdr.p_vaddr, baseaddr, filebase), up=False)

    # Extract segment data, and zero-fill out to seg_size
    seg_data = elf[seg_start:seg_end]
    if len(seg_data) < seg_size:
        seg_data += b"\x00" * (seg_size - len(seg_data))

    log.debug("Mapping: ")
    log.debug(f"    f: [ {seg_start:012x} -> {seg_end:012x} ]")
    log.debug(f"    m: [ {seg_addr:012x} -> {seg_addr + seg_size:012x} ]")

    if (phdr.p_flags & PF_X) != 0:
        # If this is an executable segment, treat it as code
        code = Code(
            image=seg_data,
            type="blob",
            arch=cpu.arch,
            mode=cpu.mode,
            base=seg_addr,
            entry=entry,
            exits=exits,
        )
        cpu.map(code)
    else:
        # Otherwise, treat it as Memory
        mem = Memory(seg_addr, seg_size)
        mem.set(seg_data)
        cpu.map(mem)


def load_elf(
    cpu: CPU,
    elf: bytes,
    base: typing.Optional[int] = None,
    entry: typing.Optional[int] = None,
    exits: typing.List[int] = [],
):
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

    Arguments:
        cpu (CPU): SmallWorld machine state object to populate
        elf (bytes): Raw bytes of ELF file to load
        base (typing.Optional[int]): User-specified base address
        entry (typing.Optional[int]): User-specified entrypoint address
        exits (typing.List[int]): User-specified exit points

    Raises:
        ConfigurationError: If the ELF is invalid, or user-provided data conflicts with ELF.
    """

    # Remember if we've seen a loadable segment
    seen_loadable = False

    # Parse the basic properties out of EIDENT
    (wordsize, byteorder) = parse_eident(elf)
    # Parse the ELF header
    ehdr = Elf_Ehdr(elf, 0x0, wordsize, byteorder)

    # TODO: Check machine compatibility?
    # - ei_class
    # - ei_data
    # - ei_osabi (some ABIs)
    # - e_machine
    # - e_flags (some ABIs)

    # Figure out if this file is loadable.
    # Easiest way to tell is if there are program headers
    if ehdr.e_phoff == 0:
        # NULL phoff means no program headers.
        # This file is not loadable; time to use another ELF loader.
        hint = Hint(message="No program headers; file is not loadable")
        hinter.error(hint)
        raise ConfigurationError("File not loadable")
    if ehdr.e_phoff < 0 or ehdr.e_phoff >= len(elf):
        hint = Hint(message=f"Invalid program header offset: {hex(ehdr.e_phoff)}")
        hinter.error(hint)
        raise ConfigurationError("Invalid program header offset")

    for i in range(0, ehdr.e_phnum):
        off = ehdr.e_phoff + (ehdr.e_phentsize * i)
        # Parse each program header
        phdr = Elf_Phdr(elf, off, wordsize, byteorder)

        if ctypes.sizeof(phdr) != ehdr.e_phentsize:
            hint = Hint(
                message="Program header size mismatch: expected {ehdr.e_phentsize}, got {ctypes.sizeof(phdr)}"
            )
            hinter.error(hint)
            raise ConfigurationError("Program header size mismatch")
        print_phdr(i, phdr)

        if phdr.p_type == PT_LOAD:
            # Loadable segment
            if not seen_loadable:
                # If this is the first loadable segment,
                # use it to determine base address,
                # entrypoint, and exitpoints
                filebase = phdr.p_vaddr
                baseaddr = determine_base(filebase, base)
                entry = determine_entry(ehdr.e_entry, entry, baseaddr, filebase, base)
                exits = list(map(lambda x: rebase_addr(x, baseaddr, base), exits))
                seen_loadable = True

            map_segment(cpu, elf, phdr, baseaddr, filebase, entry, exits)
        elif phdr.p_type == PT_DYNAMIC:
            # Dynamic linking metadata.
            # This ELF needs dynamic linking
            hint = Hint(message="Program includes dynamic linking metadata")
            hinter.info(hint)
        elif phdr.p_type == PT_INTERP:
            # Program interpreter
            # This completely changes how program loading works.
            # Whether you care is a different matter.
            interp = elf[phdr.p_offset : phdr.p_offset + phdr.p_filesz]
            hint = Hint(message=f"Program specifies interpreter {interp!r}")
            hinter.info(hint)
        elif phdr.p_type == PT_NOTE:
            # Auxiliary information
            # Possibly useful for comparing machine/OS type.
            pass
        elif phdr.p_type == PT_PHDR:
            # Program header self-reference
            # Useful for the dynamic linker, but not for us
            pass
        elif phdr.p_type == PT_TLS:
            # TLS Segment
            # Your analysis is about to get nasty :(
            hint = Hint(message="Program includes thread-local storage")
            hinter.info(hint)
        elif phdr.p_type == PT_GNU_EH_FRAME:
            # Exception handler frame.
            # GCC puts one of these in everything.  Do we care?
            pass
        elif phdr.p_type == PT_GNU_STACK:
            # Stack executability
            # If this is missing, assume executable stack
            hint = Hint(message="Program specifies stack permissions")
            hinter.info(hint)
        elif phdr.p_type == PT_GNU_RELRO:
            # Read-only after relocation
            # Only the dynamic linker should write this data.
            hint = Hint(message="Program specifies RELRO data")
            hinter.info(hint)
        elif phdr.p_type == PT_GNU_PROPERTY:
            # GNU property segment
            # Contains extra metadata which I'm not sure anything uses
            pass
        elif phdr.p_type >= PT_LOOS and phdr.p_type <= PT_HIOS:
            # Unknown OS-specific program header
            # Either this is a weird ISA that extends the generic GNU ABI,
            # or this isn't a Linux ELF.
            hint = Hint(f"Unknown OS-specific program header: {phdr.p_type:08x}")
            hinter.warn(hint)
        elif phdr.p_type >= PT_LOPROC and phdr.p_type <= PT_HIPROC:
            # Unknown machine-specific program header
            # This is probably a non-Intel ISA.
            # Most of these are harmless, serving to tell the RTLD
            # where to find machine-specific metadata
            hint = Hint(f"Unknown machine-specific program header: {phdr.p_type:08x}")
            hinter.warn(hint)
        else:
            # Unknown program header outside the allowed custom ranges
            hint = Hint(f"Invalid program header: {phdr.p_type:08x}")
            hinter.warn(hint)

    # Return the entrypoint determined for this file
    return entry
