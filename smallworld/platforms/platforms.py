import enum
from dataclasses import dataclass


class Architecture(enum.Enum):
    """Architecture and mode.

    Names take the form ``{ARCH}_{MODE}`` where ``{ARCH}`` and ``{MODE}``
    match the regex ``[A-Z0-9]+``.

    Values are lowercase, kebab-case.

    A member names a CPU: the instruction decoder (or sleigh language) that
    runs it, and the instruction set it starts in. An instruction set the CPU
    can switch to while running, such as ARM's Thumb or MIPS32 from
    microMIPS, is runtime mode (see :attr:`PlatformDef.isa_bit`), not a
    separate member. A CPU that starts in a different instruction set, or
    decodes a different one, is its own member, such as
    ``MIPS32_MICROMIPS`` and ``POWERPC32_VLE``.
    """

    X86_16 = "x86-16"
    """16-bit x86 in real mode, with the 80386's 32-bit registers."""

    X86_32 = "x86-32"
    """32-bit x86 supporting SSE extensions."""

    X86_64 = "x86-64"
    """64-bit x86 supporting AVX2 extensions."""

    X86_64_AVX512 = "x86-64-avx512"
    """64-bit x86 supporting AVX512 extensions."""

    AARCH64 = "aarch64"
    """arm64 v8a or later"""

    M68K = "m68k"
    """Motorola 68k"""

    MIPS32 = "mips32"
    """MIPS32 rel 2"""

    MIPS32_MICROMIPS = "mips32-micromips"
    """MIPS32 with the microMIPS (16/32-bit) encoding, starting in microMIPS"""

    MIPS64 = "mips64"
    """MIPS32 rel 2"""

    POWERPC32 = "powerpc32"
    """32-bit PowerPC"""

    POWERPC32_VLE = "powerpc32-vle"
    """32-bit PowerPC with the Variable Length Encoding, as on the
    VLE-capable e200 cores in NXP's MPC55xx/56xx/57xx (not the MPC5553 and
    MPC5554)"""

    POWERPC64 = "powerpc64"
    """64-bit PowerPC"""

    ARM_V5T = "arm-v5t"
    """arm32 v5t"""

    ARM_V6M = "arm-v6m"
    """arm32 v6m, ARM isa"""

    ARM_V6M_THUMB = "arm-v6m-thumb"
    """arm32 v6m, THUMB isa"""

    ARM_V7M = "arm-v7m"
    """arm32 v7m"""

    ARM_V7R = "arm-v7r"
    """arm32 v7r"""

    ARM_V7A = "arm-v7a"
    """arm32 v7a"""

    LOONGARCH32 = "loongarch32"
    """32-bit LoongArch"""

    LOONGARCH64 = "loongarch64"
    """64-bit LoongArch"""

    RISCV64 = "riscv-64"
    """64-bit RiscV"""

    SUPERH_SH4 = "superh-sh4"
    """Renesas SuperH SH-4/SH-4A"""

    SUPERH_SH2A_FPU = "superh-sh2a-fpu"
    """Renesas SuperH SH-2A with FPU"""

    SUPERH_SH1 = "superh-sh1"
    """Renesas SuperH SH-1"""

    SUPERH_SH2 = "superh-sh2"
    """Renesas SuperH SH-2"""

    TRICORE = "tricore"
    """Infineon TriCore"""

    V850 = "v850"
    """Renesas V850E1, V850E2 and V850E2M"""

    XTENSA = "xtensa"
    """Xtensa"""

    MSP430 = "msp430"
    """TI msp430"""

    MSP430X = "msp430x"
    """TI msp430x"""


class Byteorder(enum.Enum):
    """Endianness."""

    BIG = "big"
    """Big endian - most significant bit first."""

    LITTLE = "little"
    """Little endian - least significant bit first."""


class ABI(enum.Enum):
    """Application binary interface.

    Names match the regex ``[A-Z]+``.

    Values are lowercase, kebab-case.
    """

    SYSTEMV = "system-v"
    """System V."""

    CDECL = "cdecl"
    """Microsoft cdecl."""

    VECTORCALL = "vectorcall"
    """Microsoft vectorcall."""

    FASTCALL = "fastcall"
    """Microsoft fastcall."""

    WINDOWS = "windows"
    """The native Windows (PE) calling convention of the platform: the
    Microsoft x64 convention on x86-64, cdecl on x86-32."""

    STDCALL = "stdcall"
    """Microsoft stdcall (x86-32; the callee pops its arguments)."""

    THISCALL = "thiscall"
    """Microsoft thiscall (x86-32 C++ member functions; ``this`` in ecx)."""

    NONE = "none"
    """No ABI"""


@dataclass(frozen=True)
class Platform:
    """Platform metadata/configuration storage class."""

    architecture: Architecture
    """Architecture and mode."""

    byteorder: Byteorder
    """Endianness."""

    def __repr__(self) -> str:
        return f"{self.architecture}:{self.byteorder}"


__all__ = ["Platform", "Architecture", "Byteorder", "ABI"]
