import itertools
import logging
import typing

import lief

from ....exceptions import ConfigurationError
from ....platforms import Architecture, Byteorder, IsaBit, Platform, PlatformDef
from ....utils import RangeCollection
from ...state import BytesValue
from ..code import Executable
from .rela import ElfRelocator
from .structs import ElfRela, ElfSymbol

log = logging.getLogger(__name__)

# ELF machine values
# See /usr/include/elf.h for the complete list
EM_386 = 3  # Intel 80386
EM_68K = 4  # Motorola 68k family
EM_MIPS = 8  # MIPS; all kinds
EM_PPC = 20  # PowerPC 32-bit
EM_PPC64 = 21  # PowerPC 64-bit
EM_V800 = 36  # NEC V800; the RH850 ELF ABI, which GNU as uses by default
EM_ARM = 40  # ARM 32-bit
EM_SH = 42  # Renesas/Hitachi SuperH; all generations
EM_TRICORE = 44  # Infineon TriCore
EM_X86_64 = 62  # AMD/Intel x86-64
EM_V850 = 87  # NEC/Renesas V850, the GCC ELF ABI
EM_XTENSA = 94  # Xtensa
EM_AARCH64 = 183  # ARM v9, or AARCH64
EM_RISCV = 243  # RISC-V
EM_LOONGARCH = 258  # LoongArch

# ARM-specific flag values
EF_ARM_VFP_FLOAT = 0x400
EF_ARM_SOFT_FLOAT = 0x200
EF_ARM_EABI_VER5 = 0x05000000
EF_ARM_EABIMASK = 0xFF000000
EF_ARM_BE8 = 0x00800000

_AARCH64_ARCHITECTURES = frozenset(
    {
        Architecture.AARCH64,
        Architecture.AARCH64_V8_5A,
    }
)

_ARM32_ARCHITECTURES = frozenset(
    {
        Architecture.ARM_V4,
        Architecture.ARM_V4T,
        Architecture.ARM_V5T,
        Architecture.ARM_V6K,
        Architecture.ARM_V6M,
        Architecture.ARM_V7M,
        Architecture.ARM_V7EM,
        Architecture.ARM_V7R,
        Architecture.ARM_V7A,
        Architecture.ARM_V8A,
        Architecture.ARM_V8R,
        Architecture.ARM_V8M,
    }
)

# ARM32 platforms whose C models pass floats soft- or hard-float.
# The float ABI is a build choice, so an ELF's can differ from its platform's;
# loading warns when it does, since float arguments to models won't match.
# Big-endian ARMv4 and ARMv5 are BE32, with big-endian code; big-endian ARMv6
# and later are BE8, with little-endian code.
_ARM32_BE32_ARCHITECTURES = frozenset(
    {
        Architecture.ARM_V4,
        Architecture.ARM_V4T,
        Architecture.ARM_V5T,
    }
)
_ARM32_SOFT_FLOAT_ARCHITECTURES = frozenset(
    {
        Architecture.ARM_V4,
        Architecture.ARM_V4T,
        Architecture.ARM_V5T,
        Architecture.ARM_V6K,
        Architecture.ARM_V6M,
        Architecture.ARM_V7M,
        Architecture.ARM_V8M,
    }
)
_ARM32_HARD_FLOAT_ARCHITECTURES = frozenset(
    {
        Architecture.ARM_V7A,
        Architecture.ARM_V7EM,
        Architecture.ARM_V7R,
        Architecture.ARM_V8A,
        Architecture.ARM_V8R,
    }
)

# V850-specific flag values: the field naming the core, and its value for
# V850E3v5.
EF_V850_ARCH = 0xF0000000
E_V850E3V5_ARCH = 0x60000000

_V850_RH850_WARNING = (
    "running it as V850E2M. RH850-only instructions fail to decode, "
    "or run as different V850 instructions"
)

# PowerPC-specific flag values, marking code in the Variable Length Encoding:
# on a section in sh_flags, and on a segment in p_flags.
SHF_PPC_VLE = 0x10000000
PF_PPC_VLE = 0x10000000

# MIPS-specific flag values
EF_MIPS_MICROMIPS = 0x02000000  # ASE: the image contains microMIPS code
STO_MIPS_ISA = 0xC0  # st_other: the bits that say which MIPS ISA a symbol is
STO_MICROMIPS = 0x80  # st_other: this symbol is microMIPS code

# SuperH-specific flag values.
#
# EM_SH covers every SuperH generation, and they are not binary compatible with
# each other, so e_flags is the only way to tell them apart. The low five bits
# name the ISA; values confirmed empirically against binutils 2.46 by assembling
# with each --isa= and reading back e_flags.
EF_SH_MACH_MASK = 0x1F
EF_SH_UNKNOWN = 0x0
EF_SH1 = 0x1
EF_SH2 = 0x2
EF_SH3 = 0x3
EF_SH_DSP = 0x4
EF_SH3E = 0x8
EF_SH4 = 0x9
EF_SH2E = 0xB
EF_SH4A = 0xC
EF_SH2A = 0xD
EF_SH4_NOFPU = 0x10
EF_SH4A_NOFPU = 0x11
EF_SH4_NOMMU_NOFPU = 0x12
EF_SH2A_NOFPU = 0x13
EF_SH3_NOMMU = 0x14
EF_SH2A_SH4_NOFPU = 0x15
EF_SH2A_SH3_NOFPU = 0x16
EF_SH2A_SH4 = 0x17
EF_SH2A_SH3E = 0x18

# ISA values we can map onto a SmallWorld platform.
#
# The `NOFPU` variants are included: they only say the image does not *use* the
# FPU, and our SH-2A and SH-4 models have one, so running them is safe.
EF_SH_SH2A_MACHINES = {
    EF_SH2A,
    EF_SH2A_NOFPU,
    EF_SH2A_SH3_NOFPU,
    EF_SH2A_SH3E,
    EF_SH2A_SH4,
    EF_SH2A_SH4_NOFPU,
}
EF_SH_SH4_MACHINES = {
    EF_SH4,
    EF_SH4A,
    EF_SH4_NOFPU,
    EF_SH4A_NOFPU,
    EF_SH4_NOMMU_NOFPU,
}

# Deriving the architecture from the ELF header.
#
# Each detector takes the parsed ELF and the platform the caller requested,
# if any, and returns the architecture the header describes.

ArchitectureDetector = typing.Callable[
    [typing.Any, typing.Optional[Platform]], Architecture
]


def _fixed_architecture(architecture: Architecture) -> ArchitectureDetector:
    """A machine value that names exactly one architecture."""
    return lambda elf, requested: architecture


def _architecture_by_class(
    elf32: typing.Optional[Architecture],
    elf64: typing.Optional[Architecture],
    elf32_unsupported: str = "",
) -> ArchitectureDetector:
    """A machine value whose word size is given by the ELF class."""

    def detect(elf, requested):
        if elf.header.identity_class.value == 1:
            if elf32 is None:
                raise ConfigurationError(elf32_unsupported)
            return elf32
        elif elf.header.identity_class.value == 2:
            assert elf64 is not None
            return elf64
        else:
            raise ConfigurationError(
                f"Unknown value of ei_class: {hex(elf.header.identity_class.value)}"
            )

    return detect


def _aarch64_architecture(elf, requested):
    # The header doesn't record the architecture version, so a requested
    # version wins over the ARMv8.0 default.
    if requested is not None and requested.architecture in _AARCH64_ARCHITECTURES:
        return requested.architecture
    return Architecture.AARCH64


def _arm_architecture(elf, requested):
    # Some kind of arm32
    flags = set(map(lambda x: x.value & 0xFFFFFFFF, elf.header.flags_list))

    # NOTE: ELF stopped numbering ARM version numbers at 5.
    # This would be fine, except v6 and v7 are absolutely not
    # binary compatible with v5. Past that, the flags only record
    # the float ABI, which is a build choice, not the architecture.
    soft_float = EF_ARM_EABI_VER5 in flags and EF_ARM_SOFT_FLOAT in flags
    hard_float = EF_ARM_EABI_VER5 in flags and EF_ARM_VFP_FLOAT in flags
    # A big-endian EABI image records whether its code is BE8. Core
    # dumps carry no flags at all, so they say nothing either way.
    raw_flags = elf.header.processor_flag & 0xFFFFFFFF
    be8: typing.Optional[bool] = None
    if elf.header.identity_data.value == 2 and raw_flags & EF_ARM_EABIMASK:
        be8 = bool(raw_flags & EF_ARM_BE8)
    if requested is not None and requested.architecture in _ARM32_ARCHITECTURES:
        # An explicitly requested ARM32 platform wins, whatever the
        # float ABI. The file might also be a core dump, which
        # carries no ABI flags.
        architecture = requested.architecture
        # Unlike the float ABI, the code byte order is fixed by the
        # image: on the wrong one, every instruction decodes wrongly.
        if be8 is not None and be8 == (architecture in _ARM32_BE32_ARCHITECTURES):
            image, wanted = ("BE8", "BE32") if be8 else ("BE32", "BE8")
            raise ConfigurationError(
                f"ELF code is {image} (EF_ARM_BE8 {'set' if be8 else 'clear'}), "
                f"but big-endian {architecture} is {wanted}"
            )
        if (soft_float and architecture in _ARM32_HARD_FLOAT_ARCHITECTURES) or (
            hard_float and architecture in _ARM32_SOFT_FLOAT_ARCHITECTURES
        ):
            elf_abi, model_abi = ("soft", "hard") if soft_float else ("hard", "soft")
            log.warning(
                f"ELF uses the {elf_abi}-float ABI, but {architecture}'s "
                f"C models use {model_abi}-float; float arguments and "
                "return values of C models won't match"
            )
        return architecture
    elif soft_float and be8:
        # Big-endian ARMv6 or later; ARMv6K is the oldest BE8 platform.
        log.warning("Ambiguous ARM ABI version; assuming v6k (BE8)")
        return Architecture.ARM_V6K
    elif soft_float:
        # This is either ARMv5T or some kind of ARMv6.
        # We're currently assuming v5T,
        # unless the user specifically asks for another platform.
        log.warning("Ambiguous ARM ABI version; assuming v5t")
        return Architecture.ARM_V5T
    elif hard_float and be8 is False:
        # BE32 code is ARMv5 or older, and no BE32 platform has
        # hard-float C models.
        log.warning(
            "Hard-float BE32 image; assuming v5t, whose C models use "
            "soft-float, so float arguments and return values of C "
            "models won't match"
        )
        return Architecture.ARM_V5T
    elif hard_float:
        # This is ARMv7a, as built by gcc, unless the user asks for
        # another platform.
        return Architecture.ARM_V7A
    else:
        # The file might be a core dump or some uncommon flavor of ARM.
        # Fallback to a default if flags are missing.
        log.warning(
            f"No recognized ARM flags found. flags={list(map(hex, flags))}, "
            "defaulting to ARM_V7A."
        )
        return Architecture.ARM_V7A


def _superh_architecture(elf, requested):
    # Some kind of SuperH.
    #
    # NOTE: lief has no SuperH flag enums, so `flags_list` comes back
    # empty here and we have to read the raw e_flags.
    mach = elf.header.processor_flag & EF_SH_MACH_MASK

    if mach in EF_SH_SH2A_MACHINES:
        return Architecture.SUPERH_SH2A_FPU
    elif mach in EF_SH_SH4_MACHINES:
        return Architecture.SUPERH_SH4
    elif mach == EF_SH1:
        return Architecture.SUPERH_SH1
    elif mach == EF_SH2:
        return Architecture.SUPERH_SH2
    elif mach == EF_SH2E:
        # SH-2 with a single-precision FPU, which Ghidra has no
        # language for. SH-2A is a strict superset.
        log.warning(
            f"SuperH ISA {hex(mach)} has no SmallWorld model; running it as SH-2A-FPU"
        )
        return Architecture.SUPERH_SH2A_FPU
    elif mach in (EF_SH3, EF_SH3E, EF_SH3_NOMMU):
        # SH-4 is a superset of these.
        log.warning(
            f"SuperH ISA {hex(mach)} has no SmallWorld model; running it as SH-4"
        )
        return Architecture.SUPERH_SH4
    elif mach == EF_SH_UNKNOWN:
        # No ISA recorded at all - a core dump, or an image linked by a
        # toolchain that never set the field. Same fallback as the ARM
        # detector rather than a hard failure.
        log.warning("SuperH image records no ISA in e_flags; defaulting to SH-4")
        return Architecture.SUPERH_SH4
    else:
        # SH-DSP and friends.
        raise ConfigurationError(f"Unsupported SuperH ISA in e_flags: {hex(mach)}")


def _v850_architecture(elf, requested):
    # SmallWorld's V850 model has no RH850 (V850E3v5) instructions. Most
    # RH850-only instructions fail to decode, but RH850 reused some encodings
    # that V850 decodes as other instructions, so those run wrongly without
    # failing: `loop` runs as `mulhi`, `synci` as `mov`, `ld.dw`/`st.dw` as
    # `ld.bu` plus a stray halfword, the 17-bit-displacement branches as
    # `ld.hu`, and `dbhvtrap`/`dbcp` as `divh`. See support.rst. GCC-ABI
    # images record their core, so warn only for RH850 code; V850E2V3 is the
    # V850E2M modelled.
    if elf.header.processor_flag & EF_V850_ARCH == E_V850E3V5_ARCH:
        log.warning(f"EM_V850 image flagged as V850E3v5 (RH850); {_V850_RH850_WARNING}")
    return Architecture.V850


def _v800_architecture(elf, requested):
    # V850 and RH850 images built for the RH850 ABI, GNU as's default. Its
    # relocations are numbered differently from the GCC ABI's, and it does not
    # record which core the code is for.
    raise ConfigurationError(
        "EM_V800 (RH850 ABI) images are not supported; "
        "build V850 code for the GCC ABI (EM_V850) instead"
    )


def _ppc_architecture(elf, requested):
    # PowerPC 32-bit. The header doesn't distinguish VLE; its code is flagged
    # in the section headers and the program headers instead. Either may be
    # missing (a stripped image has no section headers), so both are read.
    vle_code = any(section.flags & SHF_PPC_VLE for section in elf.sections) or any(
        segment.raw_flags & PF_PPC_VLE for segment in elf.segments
    )
    if any(section.size > 0 for section in elf.sections):
        standard_code = any(
            section.flags & SHF_EXECINSTR
            and not section.flags & SHF_PPC_VLE
            and section.size > 0
            for section in elf.sections
        )
    else:
        standard_code = any(
            segment.raw_flags & PF_X and not segment.raw_flags & PF_PPC_VLE
            for segment in elf.segments
            if segment.type.value & 0xFFFFFFFF == PT_LOAD
        )
    if vle_code and standard_code:
        # A file mixing VLE and standard code, as several e200 cores run.
        # Each platform decodes one encoding for the whole run, so the caller
        # picks which code to run; VLE is the default, since it is usually
        # most of such a file.
        if requested is not None and requested.architecture in (
            Architecture.POWERPC32,
            Architecture.POWERPC32_VLE,
        ):
            architecture = requested.architecture
        else:
            architecture = Architecture.POWERPC32_VLE
        log.warning(
            "PowerPC image mixes VLE and standard code; running it as "
            f"{architecture}, so code in the other encoding will be "
            "misdecoded"
        )
        return architecture
    elif vle_code:
        return Architecture.POWERPC32_VLE
    return Architecture.POWERPC32


def _mips_architecture(elf, requested):
    # Some kind of MIPS.
    # TODO: There are more parameters than just word size
    architecture = _architecture_by_class(Architecture.MIPS32, Architecture.MIPS64)(
        elf, requested
    )
    if (
        architecture == Architecture.MIPS32
        and elf.header.processor_flag & EF_MIPS_MICROMIPS
    ):
        ElfExecutable._warn_mixed_micromips(elf)
        return Architecture.MIPS32_MICROMIPS
    return architecture


# The architecture detector for each e_machine value.
ARCHITECTURE_DETECTORS: typing.Dict[int, ArchitectureDetector] = {
    EM_386: _fixed_architecture(Architecture.X86_32),
    EM_68K: _fixed_architecture(Architecture.M68K),
    EM_AARCH64: _aarch64_architecture,
    EM_ARM: _arm_architecture,
    EM_LOONGARCH: _architecture_by_class(
        Architecture.LOONGARCH32, Architecture.LOONGARCH64
    ),
    EM_MIPS: _mips_architecture,
    EM_PPC: _ppc_architecture,
    EM_PPC64: _fixed_architecture(Architecture.POWERPC64),
    EM_RISCV: _architecture_by_class(Architecture.RISCV32, Architecture.RISCV64),
    EM_SH: _superh_architecture,
    EM_TRICORE: _fixed_architecture(Architecture.TRICORE),
    EM_V800: _v800_architecture,
    EM_V850: _v850_architecture,
    EM_X86_64: _fixed_architecture(Architecture.X86_64),
    EM_XTENSA: _fixed_architecture(Architecture.XTENSA),
}

# Families whose e_machine value cannot tell their members apart well enough,
# keyed by e_machine. When the caller requests a member of the family, it wins
# over the member derived from the header: SuperH's ISA field cannot express,
# say, an SH-2A image the caller wants to run on our SH-4 model.
REQUESTED_ARCHITECTURE_WINS: typing.Dict[int, typing.FrozenSet[Architecture]] = {
    EM_SH: frozenset(
        {
            Architecture.SUPERH_SH1,
            Architecture.SUPERH_SH2,
            Architecture.SUPERH_SH2A_FPU,
            Architecture.SUPERH_SH4,
        }
    ),
}

# Program header types
PT_NULL = 0  # Empty/unused program header
PT_LOAD = 1  # Describes loadable program segment
PT_DYNAMIC = 2  # Points to dynamic linking metadata
PT_INTERP = 3  # Points to program interpreter
PT_NOTE = 4  # Points to auxiliary information
PT_SHLIB = 5  # Reserved value; I think it's unused
PT_PHDR = 6  # Points to program header table
PT_TLS = 7  # Indicates need for thread-local storage
STT_TLS = 6  # Symbol names a thread-local; its value is a TLS-block offset
PT_LOOS = 0x60000000  # Start of OS-specific types
PT_GNU_EH_FRAME = 0x6474E550  # GNU-specific: Points to exception handler segment
PT_GNU_STACK = 0x6474E551  # GNU-specific: Describes stack permissions
PT_GNU_RELRO = 0x6474E552  # GNU-specific: Describes read-only after relocation segment
PT_GNU_PROPERTY = 0x6474E553  # GNU-specific: Points to GNU property
PT_HIOS = 0x6FFFFFFF  # End of OS-specific types
PT_LOPROC = 0x70000000  # Start of processor-specific types
PT_HIPROC = 0x7FFFFFFF  # End of processor-specific types

# Section header flags
SHF_WRITE = 0x1  # Section is writable
SHF_ALLOC = 0x2  # Section occupies memory durring execution
SHF_EXECINSTR = 0x4  # Section is executable
SHF_TLS = 0x400  # Section holds thread-local storage
SHT_NOBITS = 8  # Section occupies no file space (.bss/.tbss)

# Program header flags
PF_X = 0x1  # Segment is executable
PF_W = 0x2  # Segment is writable
PF_R = 0x4  # Segment is readable

# Universal dynamic tag values
DT_PLTRELSZ = 2  # Size of PLT relocation table
DT_PLTGOT = 3  # Address of some kind of GOT; processor-dependent
DT_RELA = 7  # Address of dynamic rela table
DT_RELASZ = 8  # Size of dynamic rela table
DT_RELAENT = 9  # Size of dynamic relas
DT_REL = 17  # Address of dynamic rel table
DT_RELSZ = 18  # Size of dynamic rel table
DT_RELENT = 19  # Size of dynamic rels
DT_PLTREL = 20  # Type of PLT relocation
DT_JMPREL = 23  # Address of PLT relocation table

# MIPS-specific dynamic tag values
DT_MIPS_LOCAL_GOTNO = 0x7000000A
DT_MIPS_GOTSYM = 0x70000013

# MIPS-specific relocation type
R_MIPS_32 = 2
R_MIPS_64 = 18
R_MIPS_JUMP_SLOT = 127


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
        self._segments: typing.Dict[int, typing.Tuple[int, int]] = dict()
        self._section_offsets: typing.Dict[int, int] = dict()

        # Lief struct.
        # We can't keep it around forever, since it's not copyable.
        self._elf: typing.Optional[typing.Any] = None

        # Initialize dynamic tag info
        self._dtags: typing.Dict[int, int] = dict()

        # Initialize symbol info
        self._dynamic_symbols: typing.List[ElfSymbol] = list()
        self._static_symbols: typing.List[ElfSymbol] = list()
        self._dynamic_relas: typing.List[ElfRela] = list()
        self._static_relas: typing.List[ElfRela] = list()
        self._syms_by_name: typing.Dict[str, typing.List[ElfSymbol]] = dict()
        self._relocator: typing.Optional[ElfRelocator] = None
        # The header's e_flags.  Its meaning is architecture-specific;
        # e.g. on PowerPC64 it records which ELF ABI version the file uses.
        self.processor_flags: int = 0
        # PT_TLS: the module's thread-local initialization image, its full
        # size including .tbss, and its required alignment.  Empty when the
        # image declares no thread-locals.
        self._tls_image = b""
        self._tls_size = 0
        self._tls_align = 1
        # Where the next reserve_synthetic() reservation goes, past the loaded
        # image; None before the first.
        self._synthetic_next: typing.Optional[int] = None

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

        # Save the lief struct
        self._elf = elf

        # Extract the file header
        ehdr = elf.header
        if ehdr is None:
            raise ConfigurationError("Failed extracting ELF header")
        self.processor_flags = ehdr.processor_flag

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

        # Determine the file base address.
        self._file_base = elf.imagebase
        self._determine_base()

        # Load this file.
        # Prefer to use the program headers if available,
        # since that's what the kernel will be using.
        # Otherwise, patch something together from the section headers.
        if ehdr.program_header_offset == 0:
            # No program headers; not a loadable ELF.
            self._load_from_shdrs(elf, image)
        else:
            # Program headers; it's a loadable ELF.
            self._load_from_phdrs(elf, image)

        # Compute the final total capacity
        for offset, value in self.items():
            self.size = max(self.size, offset + value.get_size())

        # Determine if the file specifies an entrypoint
        if elf.entrypoint is not None and elf.entrypoint != 0:
            # Check if the entrypoint is valid (falls within the image)
            entrypoint = self._rebase_file(elf.entrypoint)
            address = entrypoint
            if (
                self.platform is not None
                and PlatformDef.for_platform(self.platform).isa_bit is not IsaBit.NONE
            ):
                # Bit 0 of a code address selects the instruction set; the
                # code itself is at the even address.
                address &= ~1
            if (
                self.platform is not None
                and self.platform.architecture == Architecture.MIPS32_MICROMIPS
                and not entrypoint & 1
            ):
                log.warning(
                    "The ELF entrypoint is standard MIPS32 code, but runs "
                    "start in microMIPS; set isa_mode to 0 before running "
                    "it (Ghidra only)"
                )
            if not self.bounds.contains_value(address):
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
        self._extract_symbols(elf, image)

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
        #
        # LIEF gives a plain int, not an ARCH, for a machine type it doesn't
        # know; `int` accepts both, and the lookup refuses the unknown ones.
        machine = int(elf.header.machine_type)
        detect = ARCHITECTURE_DETECTORS.get(machine)
        if detect is None:
            raise ConfigurationError(f"Unknown value of e_machine: {hex(machine)}")
        architecture = detect(elf, self.platform)

        # An explicitly requested member of the family wins over the derived
        # one.
        #
        # This has to come *after* the derivation, not instead of it.
        # `_platform_for_ehdr` feeds the "Platform mismatch" guard in
        # `__init__`, so short-circuiting on `self.platform` would make the
        # detector's refusals unreachable - an SH-DSP image loaded with
        # `platform=SH-4` would be silently accepted - and swallow its
        # warnings. Say so out loud when it happens, rather than overriding in
        # silence.
        family = REQUESTED_ARCHITECTURE_WINS.get(machine, frozenset())
        if (
            self.platform is not None
            and self.platform.architecture != architecture
            and self.platform.architecture in family
        ):
            log.warning(
                f"ELF header describes {architecture}, but "
                f"{self.platform.architecture} was requested; using the "
                "requested platform"
            )
            architecture = self.platform.architecture
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

        if self._file_base in ((1 << 32) - 1, (1 << 64) - 1):
            # This is lief's way of saying the file has no load address.
            self._file_base = 0

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
        log.debug(f"Address: {self.address:x}")

    @staticmethod
    def _warn_mixed_micromips(elf) -> None:
        """Warn if a microMIPS image also has standard MIPS32 functions.

        Only the Ghidra backend switches between the two encodings, and the
        header flag says only that some of the code is microMIPS. Function
        symbols say which is which; a stripped image has none to check.
        """
        standard = sorted(
            sym.name
            for sym in elf.symbols
            if sym.type == lief.ELF.Symbol.TYPE.FUNC
            and sym.value != 0
            and sym.other & STO_MIPS_ISA != STO_MICROMIPS
        )
        if standard:
            shown = ", ".join(standard[:5]) + (", ..." if len(standard) > 5 else "")
            log.warning(
                "ELF image mixes microMIPS and standard MIPS32 code; loading it "
                "as MIPS32_MICROMIPS. Only the Ghidra backend switches between "
                "the two; on angr and Unicorn these standard MIPS32 functions "
                f"will not run correctly: {shown}"
            )

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

    def _virtual_to_physical(self, elf, val: int) -> int:
        for vaddr, (paddr, size) in self._segments.items():
            if val >= vaddr and val < vaddr + size:
                return val - vaddr + paddr
        raise ConfigurationError(
            f"Virutal address {val:x} is not in any loaded segment"
        )

    def _load_from_phdrs(self, elf, image):
        ehdr = elf.header
        if ehdr.program_header_offset >= len(image):
            # Obviously-invalid program headers
            raise ConfigurationError(
                f"Invalid program header offset {hex(ehdr.program_header_offset)}"
            )

        for phdr in elf.segments:
            log.debug(f"{phdr}")
            phdr_type = phdr.type.value & 0xFFFFFFFF
            if phdr_type == PT_LOAD:
                # Loadable segment
                # Map its data into memory
                self._segments[phdr.virtual_address] = (
                    phdr.file_offset,
                    phdr.physical_size,
                )
                self._map_segment(phdr, image)
            elif phdr_type == PT_DYNAMIC:
                # Dynamic linking metadata.
                # This ELF needs dynamic linking
                log.debug("Program includes dynamic linking metadata")
            elif phdr_type == PT_INTERP:
                # Program interpreter
                # This completely changes how program loading works.
                # Whether you care is a different matter.
                interp = image[phdr.file_offset : phdr.file_offset + phdr.physical_size]
                log.debug(f"Program specifies interpreter {interp!r}")
            elif phdr_type == PT_NOTE:
                # Auxiliary information
                # Possibly useful for comparing machine/OS type.
                pass
            elif phdr_type == PT_PHDR:
                # Program header self-reference
                # Useful for the dynamic linker, but not for us
                pass
            elif phdr_type == PT_TLS:
                # This module's thread-local initialization image: `filesz`
                # initialized bytes then `memsz - filesz` zeroes (.tbss). A
                # TLS symbol's st_value indexes into it, so whoever hands out
                # thread-local storage can seed it from here.
                self._tls_image = bytes(phdr.content)[: phdr.physical_size]
                self._tls_size = int(phdr.virtual_size)
                self._tls_align = max(1, int(phdr.alignment))
                log.debug(
                    f"Program includes thread-local storage: "
                    f"{len(self._tls_image):#x} init bytes of {self._tls_size:#x}"
                )
            elif phdr_type == PT_GNU_EH_FRAME:
                # Exception handler frame.
                # GCC puts one of these in everything.  Do we care?
                pass
            elif phdr_type == PT_GNU_STACK:
                # Stack executability
                # If this is missing, assume executable stack
                log.debug("Program specifies stack permissions")
            elif phdr_type == PT_GNU_RELRO:
                # Read-only after relocation
                # Only the dynamic linker should write this data.
                log.debug("Program specifies RELRO data")
            elif phdr_type == PT_GNU_PROPERTY:
                # GNU property segment
                # Contains extra metadata which I'm not sure anything uses
                pass
            elif phdr_type >= PT_LOOS and phdr_type <= PT_HIOS:
                # Unknown OS-specific program header
                # Either this is a weird ISA that extends the generic GNU ABI,
                # or this isn't a Linux ELF.
                log.warn(f"Unknown OS-specific program header: {phdr_type:08x}")
            elif phdr_type >= PT_LOPROC and phdr_type <= PT_HIPROC:
                # Unknown machine-specific program header
                # This is probably a non-Intel ISA.
                # Most of these are harmless, serving to tell the RTLD
                # where to find machine-specific metadata
                log.warn(f"Unknown machine-specific program header: {phdr_type:08x}")
            else:
                # Unknown program header outside the allowed custom ranges
                log.warn(f"Invalid program header: {phdr_type:08x}")

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
        if (phdr.flags.value & PF_X) != 0:
            # This is a code segment; add it to program bounds
            self.bounds.add_range((seg_addr, seg_addr + seg_size))

        # Add the segment to the memory map
        seg_value = BytesValue(seg_data, None)
        assert (
            seg_value._size == seg_size
        ), f"Expected {seg_size:x} bytes, got {seg_value._size:x}"
        self[seg_addr - self.address] = seg_value

    def _load_from_shdrs(self, elf, image):
        text = bytearray()
        data = bytearray()
        rodata = bytearray()

        section_text_offsets: typing.Dict[int, int] = dict()
        section_data_offsets: typing.Dict[int, int] = dict()
        section_rodata_offsets: typing.Dict[int, int] = dict()

        # TLS sections are a template, not process memory: st_value is an
        # offset within the module's TLS block, not the image, so they get
        # their own layout, used by the symbol loop below. They still go into
        # the data blob as before -- dead bytes, but excluding them would
        # shift every offset in existing images.
        tls = bytearray()
        tls_section_offsets: typing.Dict[int, int] = dict()

        # Basically every architecture needs a GOT;
        # they will have relocations that reference either the GOT itself,
        # or a symbol's GOT slot

        for index in range(0, len(elf.sections)):
            section = elf.sections[index]

            if (section.flags & SHF_ALLOC) == 0:
                # Section is not allocated;
                # It's metadata that won't get referenced later.
                continue

            if (section.flags & SHF_TLS) != 0:
                skew = len(tls) % section.alignment
                if skew != 0:
                    tls.extend(b"\0" * (section.alignment - skew))
                tls_section_offsets[index] = len(tls)
                self._tls_align = max(self._tls_align, section.alignment)
                if section.type == SHT_NOBITS:
                    # .tbss occupies no file space; it contributes zeroes.
                    tls.extend(b"\0" * section.original_size)
                else:
                    tls.extend(
                        image[
                            section.file_offset : section.file_offset
                            + section.original_size
                        ]
                    )

            if (section.flags & SHF_EXECINSTR) != 0:
                # Section is executable
                skew = len(text) % section.alignment
                if skew != 0:
                    text.extend(b"\0" * (section.alignment - skew))
                section_text_offsets[index] = len(text)
                text.extend(
                    image[
                        section.file_offset : section.file_offset
                        + section.original_size
                    ]
                )
            elif (section.flags & SHF_WRITE) != 0:
                # Section is writable
                skew = len(data) % section.alignment
                if skew != 0:
                    data.extend(b"\0" * (section.alignment - skew))
                section_data_offsets[index] = len(data)
                data.extend(
                    image[
                        section.file_offset : section.file_offset
                        + section.original_size
                    ]
                )
            else:
                # Section is read-only
                skew = len(rodata) % section.alignment
                if skew != 0:
                    rodata.extend(b"\0" * (section.alignment - skew))
                section_rodata_offsets[index] = len(rodata)
                rodata.extend(
                    image[
                        section.file_offset : section.file_offset
                        + section.original_size
                    ]
                )

        text_offset = 0
        rodata_offset = self._page_align(text_offset + len(text), up=True)
        data_offset = self._page_align(rodata_offset + len(rodata), up=True)

        for index in section_text_offsets:
            self._section_offsets[index] = section_text_offsets[index] + text_offset

        for index in section_rodata_offsets:
            self._section_offsets[index] = section_rodata_offsets[index] + rodata_offset

        for index in section_data_offsets:
            self._section_offsets[index] = section_data_offsets[index] + data_offset

        if len(text) > 0:
            self[text_offset] = BytesValue(bytes(text), None)
        if len(rodata) > 0:
            self[rodata_offset] = BytesValue(bytes(rodata), None)
        if len(data) > 0:
            self[data_offset] = BytesValue(bytes(data), None)

        if len(tls) > 0:
            self._tls_image = bytes(tls)
            self._tls_size = len(tls)

        if self._relocator is not None:
            # Some architectures' relocations depend on tables a linker
            # would have created (e.g. PowerPC64's TOC).
            self._relocator.prepare_object(
                self,
                {i: elf.sections[i].name for i in self._section_offsets},
                self._section_offsets,
                {i for i in section_data_offsets if i not in tls_section_offsets},
            )

        for sym in elf.symbols:
            if sym.type.value == STT_TLS:
                # Relative to the TLS block, not the image: adding the
                # section's image offset would point outside the block.
                if sym.shndx in tls_section_offsets:
                    sym.value += tls_section_offsets[sym.shndx]
            elif sym.shndx in self._section_offsets:
                sym.value += self._section_offsets[sym.shndx]

    def _extract_dtags(self, elf):
        for dt in elf.dynamic_entries:
            self._dtags[dt.tag.value & 0xFFFFFFFF] = dt.value

    def _extract_symbols(self, elf, image):
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

        # The st_other bits above visibility are processor-specific.
        is_mips = int(elf.header.machine_type) == EM_MIPS

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

            # A microMIPS code symbol's value carries the ISA bit, as code
            # addresses do on platforms with two instruction sets. LLD sets
            # it in .dynsym but not in .symtab, so set it from st_other for
            # both, and the two agree.
            value = s.value
            if is_mips and s.other & STO_MIPS_ISA == STO_MICROMIPS and s.shndx != 0:
                value |= 1

            # Build a symbol
            sym = ElfSymbol(
                idx=idx,
                dynamic=dynamic,
                name=s.name,
                type=s.type.value,
                bind=s.binding.value,
                # Visibility is the low two bits of st_other. Read them
                # directly: LIEF's enum rejects the processor-specific bits
                # above them, such as STO_MICROMIPS or PowerPC64 ELFv2's
                # offset of the function's local entry point.
                visibility=s.other & 0x3,
                other=s.other,
                shndx=s.shndx,
                value=value,
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

            idx += 1

        # self.platform is None when constructed with ignore_platform=True and
        # no explicit platform; guard the access as the header-block paths do.
        if self.platform is not None and (
            self.platform.architecture == Architecture.MIPS32
            or self.platform.architecture == Architecture.MIPS32_MICROMIPS
            or self.platform.architecture == Architecture.MIPS64
        ):
            # All MIPS dynamic symbols have an implicit rela.
            # MIPS dynamic symbols always have a GOT entry;
            # to save space, the ABI just assumes that the rela exists
            if not self._dtags:
                # No dynamic section: a static image, with no GOT to find.
                pass
            elif (
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

                rela_type = R_MIPS_JUMP_SLOT
                if self.platform.architecture == Architecture.MIPS64:
                    gotent = 8
                else:
                    gotent = 4

                # Rebase the GOT offset relative to the image
                gotoff = self._rebase_file(gotoff)

                # Skip the first local_gotno entries
                gotoff += gotent * local_gotno

                for s in list(elf.dynamic_symbols)[gotsym:]:
                    sym = lief_to_elf[s]
                    rela = ElfRela(
                        is_rela=False,
                        offset=gotoff,
                        type=rela_type,
                        symbol=sym,
                        addend=0,
                    )
                    sym.relas.append(rela)
                    self._dynamic_relas.append(rela)

                    gotoff += gotent

        # Okay, lief's relocation parsing is an embarrassing disaster.
        # I'm taking over because I know how to read C structs, dammit.

        jmpreloff = 0
        dynreloff = 0

        # Handle .rel(a).plt
        if DT_JMPREL in self._dtags:
            # We need three dynamic tags to define .rel(a).plt:
            #
            # - DT_JMPREL: Offset of the table itself
            # - DT_PLTREL: Relocation type
            # - DT_PLTRELSZ: Size of relocation table

            if DT_PLTREL not in self._dtags:
                raise ConfigurationError(
                    "ELF specifies a PLT relocation table, but not DT_PLTREL"
                )
            if DT_PLTRELSZ not in self._dtags:
                raise ConfigurationError(
                    "Elf specifies a PLT relocation table, but not DT_PLTRELSZ"
                )

            jmprel = self._dtags[DT_JMPREL]
            pltrel = self._dtags[DT_PLTREL]
            pltrelsz = self._dtags[DT_PLTRELSZ]

            # Figure out if we're dealing with rels or relas
            if pltrel == DT_RELA:
                is_rela = True
            elif pltrel == DT_REL:
                is_rela = False
            else:
                raise ConfigurationError(f"Unknown value for DT_PLTREL: {pltrel}")

            # Figure out the entry size based on EH_CLASS and the relocation type
            if elf.header.identity_class.value == 1:
                if is_rela:
                    pltrelent = 12
                else:
                    pltrelent = 8
            else:
                if is_rela:
                    pltrelent = 24
                else:
                    pltrelent = 16

            # Find the table within the image.
            jmpreloff = self._virtual_to_physical(elf, jmprel)

            # Parse the table
            for i in range(0, pltrelsz // pltrelent):
                rela = ElfRela.from_bytes(
                    i,
                    is_rela,
                    elf.header.identity_class.value,
                    elf.header.identity_data.value,
                    int(elf.header.machine_type),
                    image,
                    jmpreloff,
                    baseaddr,
                    self._dynamic_symbols,
                )
                rela.symbol.relas.append(rela)
                self._dynamic_relas.append(rela)

        # Handle .rela.dyn
        if DT_RELA in self._dtags:
            # We need three dynamic tags to define .rela.dyn:
            #
            # - DT_RELA: Offset of the table itself
            # - DT_RELAENT: Relocation size
            # - DT_RELASZ: Size of relocation table

            if DT_RELASZ not in self._dtags:
                raise ConfigurationError(
                    "ELF specifies a dynamic relocation table, but not DT_RELASZ"
                )
            if DT_RELAENT not in self._dtags:
                raise ConfigurationError(
                    "ELF specifies a dynamic relocation table, but not DT_RELAENT"
                )

            is_rela = True
            relaoff = self._dtags[DT_RELA]
            relasz = self._dtags[DT_RELASZ]
            relaent = self._dtags[DT_RELAENT]

            # Find the table within the image
            dynreloff = self._virtual_to_physical(elf, relaoff)

            # Parse the table
            for i in range(0, relasz // relaent):
                rela = ElfRela.from_bytes(
                    i,
                    is_rela,
                    elf.header.identity_class.value,
                    elf.header.identity_data.value,
                    int(elf.header.machine_type),
                    image,
                    dynreloff,
                    baseaddr,
                    self._dynamic_symbols,
                )
                rela.symbol.relas.append(rela)
                self._dynamic_relas.append(rela)

        # Handle .rel.dyn
        if DT_REL in self._dtags:
            # We need three dynamic tags to define .rel.dyn:
            #
            # - DT_REL: Offset of the table itself
            # - DT_RELENT: Relocation size
            # - DT_RELSZ: Size of relocation table

            if DT_RELSZ not in self._dtags:
                raise ConfigurationError(
                    "ELF specifies a dynamic relocation table, but not DT_RELSZ"
                )
            if DT_RELENT not in self._dtags:
                raise ConfigurationError(
                    "ELF specifies a dynamic relocation table, but not DT_RELENT"
                )

            is_rela = False
            reloff = self._dtags[DT_REL]
            relsz = self._dtags[DT_RELSZ]
            relent = self._dtags[DT_RELENT]

            # Find the table within the image
            dynreloff = self._virtual_to_physical(elf, reloff)

            # Parse the table
            for i in range(0, relsz // relent):
                rel = ElfRela.from_bytes(
                    i,
                    is_rela,
                    elf.header.identity_class.value,
                    elf.header.identity_data.value,
                    int(elf.header.machine_type),
                    image,
                    dynreloff,
                    baseaddr,
                    self._dynamic_symbols,
                )
                rel.symbol.relas.append(rel)
                self._dynamic_relas.append(rel)

        # Handle static relocations
        for section in elf.sections:
            if section.type in (section.TYPE.REL, section.TYPE.RELA):
                is_rela = section.type == section.TYPE.RELA
                if section.information not in self._section_offsets:
                    # This links to a non-allocated section,
                    # or the program was loaded through the phdrs
                    # and we're just using the dynamic metadata.
                    continue

                # Static relocations are relative to the section they relocate,
                # so we need to know the section offset.
                for i in range(0, section.size // section.entry_size):
                    rela = ElfRela.from_bytes(
                        i,
                        is_rela,
                        elf.header.identity_class.value,
                        elf.header.identity_data.value,
                        int(elf.header.machine_type),
                        image,
                        section.offset,
                        baseaddr,
                        self._static_symbols,
                        r_offset_rebase=self._section_offsets[section.information],
                    )
                    rela.symbol.relas.append(rela)
                    self._static_relas.append(rela)

        for sym in self._static_symbols:
            if sym.shndx in self._section_offsets:
                self.update_symbol_value(sym, sym.value, rebase=False)

        if self._relocator is not None:
            # An object file leaves the symbols a linker defines (e.g.
            # PowerPC64's `.TOC.`) undefined; define them as it would.
            for sym in self._static_symbols:
                if sym.shndx == 0:
                    value = self._relocator.linker_symbol_value(sym.name)
                    if value is not None:
                        self.update_symbol_value(sym, value)

        if len(self._dynamic_symbols) > 0:
            # Any rela tied to the NULL symbol needs to be relocated
            null_sym = self._dynamic_symbols[0]
            self.update_symbol_value(null_sym, 0, rebase=False)

            # Self-resolve GOT slots (e.g. GLOB_DAT) for dynamic symbols that
            # are DEFINED in this image. A real loader resolves these against
            # the image's own definition; without it their relocations stay
            # null (e.g. a rip-relative load of a defined data symbol reads 0).
            # A symbol is defined-in-image when its section index is a real
            # section: not SHN_UNDEF (0, external -> left for link_elf) and
            # below SHN_LORESERVE (0xFF00, which excludes SHN_ABS/SHN_COMMON
            # whose values are not base-relative). We cannot use
            # self._section_offsets here: it is empty for images loaded via
            # program headers (e.g. stripped shared objects).
            SHN_UNDEF = 0
            SHN_LORESERVE = 0xFF00
            for sym in self._dynamic_symbols[1:]:
                if SHN_UNDEF < sym.shndx < SHN_LORESERVE:
                    self.update_symbol_value(sym, sym.value, rebase=False)

        self._relocate_undefined_tls_descriptors()

    def _relocate_undefined_tls_descriptors(self) -> None:
        """Relocate and record TLS descriptors whose thread-local is external.

        The loops above skip undefined symbols, leaving them for `link_elf`.
        That is fine for a data or function reference -- an unrelocated one
        reads or calls null and the caller notices -- but a descriptor's first
        word is a resolver called INDIRECTLY, so a null one jumps to address
        zero, and an unrecorded descriptor cannot be bound later either.

        Relocating them here enrolls them for binding, so the call reaches the
        resolver. The real block offset is still unknown and every such access
        aliases onto one slot, hence the warning. A definer linked later
        re-relocates through `update_symbol_value` and writes the true offset.
        """
        if self._relocator is None:
            return
        unresolved: typing.Dict[str, int] = dict()
        for rela in itertools.chain(self._dynamic_relas, self._static_relas):
            if rela.symbol.defined:
                continue
            if not (
                self._relocator.is_tls_descriptor(rela)
                or self._relocator.is_tls_descriptor_reference(rela)
            ):
                continue
            self._relocator.relocate(self, rela)
            name = rela.symbol.name or f"<symbol {rela.symbol.idx}>"
            unresolved[name] = unresolved.get(name, 0) + 1
        if unresolved:
            listed = ", ".join(sorted(unresolved))
            log.warning(
                f"{sum(unresolved.values())} TLS descriptor(s) reference "
                f"thread-locals no loaded module defines ({listed}). They are "
                f"bound to the resolver so they no longer call address zero, "
                f"but their block offsets are unknown and all such accesses "
                f"share one slot. Load the defining module to resolve them."
            )

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
                if sym.value != syms[0].value or sym.baseaddr != syms[0].baseaddr:
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
            syms = [name]
        else:
            syms = self._get_symbols(name, dynamic)
            for sym in syms:
                if (
                    sym.value != syms[0].value
                    or sym.size != syms[0].size
                    or sym.baseaddr != syms[0].baseaddr
                ):
                    raise ConfigurationError(f"Conflicting symbols for {name}")

        if rebase:
            # Value provided is absolute; rebase it to the symbol's base address
            value -= syms[0].baseaddr

        # Update the value
        for sym in syms:
            sym.value = value

        # Mark this symbol as defined
        for sym in syms:
            sym.defined = True

        log.debug(f"Updating {syms}")

        if self._relocator is not None:
            for sym in syms:
                for rela in sym.relas:
                    # Relocate!
                    self._relocator.relocate(self, rela)
        else:
            log.error(f"No platform defined; cannot relocate {name}!")

    @property
    def relocator(self) -> typing.Optional[ElfRelocator]:
        """This image's relocator, or None if its platform is unknown.

        Architecture-specific relocation state lives there, such as the TLS
        descriptors a model library binds a resolver to.
        """
        return self._relocator

    @property
    def tls_image(self) -> bytes:
        """The module's thread-local initialization image, zero-extended to
        its full size (`memsz`), or empty if it declares no thread-locals."""
        if not self._tls_size:
            return b""
        return self._tls_image.ljust(self._tls_size, b"\x00")

    def reserve_synthetic(self, size: int, description: str) -> int:
        """Reserve zeroed space past the loaded image, for content no file holds.

        For what a linker would have built but an object file lacks, such as
        the GOT slots of its TLS descriptors.  The first reservation starts on
        a page of its own rather than abutting the last section: a synthetic
        region overlapping real content would be far harder to recognise in a
        memory dump than a gap.  Each one grows the image, so it is mapped
        with everything else.

        Arguments:
            size: The number of bytes to reserve
            description: A label for the reserved bytes

        Returns:
            The reservation's address
        """
        if self._synthetic_next is None:
            self._synthetic_next = self._page_align(self.size, up=True)
        offset = self._synthetic_next
        self._synthetic_next += size
        self.size = max(self.size, offset + size)
        self[offset] = BytesValue(b"\0" * size, description)
        return self.address + offset

    def link_elf(
        self, elf: "ElfExecutable", dynamic: bool = True, all_syms: bool = False
    ) -> None:
        """Link one ELF against another

        This roughly mimics the ELF linker;
        it looks for undefined symbols in the current file,
        and tries to populate their values from matching defined symbols
        from another file.

        Arguments:
            elf: The ELF from which to draw symbol values
            dynamic: Whether to link static or dynamic symbols
            all_syms: Whether to override defined symbols
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
            if not all_syms and my_sym.defined:
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
            if o_sym.type == STT_TLS:
                # A block offset, not an address: rebasing would leave the
                # delta between the two load addresses, which indexes nothing
                # -- and goes negative if the definer loaded lower.
                self.update_symbol_value(my_sym, o_sym.value, rebase=False)
            else:
                self.update_symbol_value(
                    my_sym, o_sym.value + o_sym.baseaddr, rebase=True
                )

    def __getstate__(self):
        # Override the default pickling mechanism.
        # We can't save any lief data through a copy.
        state = self.__dict__.copy()
        state["_elf"] = None
        return state


__all__ = ["ElfExecutable"]
