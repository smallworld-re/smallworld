from triton import ARCH

from ....platforms import Architecture, Byteorder
from .machdef import TritonMachineDef

# Triton's ARM32 target exposes a deliberately small register set: r0-r12, sp,
# r14, pc, apsr, and the individual flags. It has NO lr/r13/r15 names, no
# cpsr/spsr, no M-profile system registers, and no FP/VFP/NEON registers. The
# machdefs below therefore map only the registers Triton actually models; every
# other SmallWorld register (banked regs, VFP/NEON, M-profile sysregs) is
# omitted and raises ``UnsupportedRegisterError``.

# Shared base register set for all ARM variants.
_BASE_REGS = {
    "r0": "r0",
    "r1": "r1",
    "r2": "r2",
    "r3": "r3",
    "r4": "r4",
    "r5": "r5",
    "r6": "r6",
    "r7": "r7",
    "r8": "r8",
    "r9": "r9",
    "r10": "r10",
    "r11": "r11",
    "r12": "r12",
    # SmallWorld aliases; Triton has no alias names, but each is a full-width
    # alias of its parent so the parent's Triton name is byte-exact.
    "sb": "r9",
    "sl": "r10",
    "fp": "r11",
    "ip": "r12",
    "sp": "sp",
    "lr": "r14",  # Triton exposes the link register only as "r14"
    "pc": "pc",
}

# Program-status register. Triton has no cpsr/psr; APSR is its only status
# register and holds N/Z/C/V. This is lossy (APSR omits mode/interrupt bits) but
# matches how the Unicorn and angr backends handle psr/cpsr.
_M_REGS = {"psr": "apsr"}
_RA_REGS = {"cpsr": "apsr"}

_V5T_REGS = {**_BASE_REGS, **_M_REGS}
_V6M_REGS = {**_BASE_REGS, **_M_REGS}
_V7M_REGS = {**_BASE_REGS, **_M_REGS}
_V7R_REGS = {**_BASE_REGS, **_RA_REGS}
_V7A_REGS = {**_BASE_REGS, **_RA_REGS}


class TritonARMMachineDef(TritonMachineDef):
    """Base Triton machine definition for 32-bit ARM (abstract on ``arch``)."""

    byteorder = Byteorder.LITTLE
    triton_arch = ARCH.ARM32
    pc_register = "pc"
    sp_register = "sp"
    lr_register = "lr"
    address_size = 4
    interrupt_mnemonics = {"svc", "swi"}


class TritonARMv5TMachineDef(TritonARMMachineDef):
    arch = Architecture.ARM_V5T
    _registers = _V5T_REGS


class TritonARMv6MMachineDef(TritonARMMachineDef):
    arch = Architecture.ARM_V6M
    _registers = _V6M_REGS


class TritonARMv6MThumbMachineDef(TritonARMv6MMachineDef):
    arch = Architecture.ARM_V6M_THUMB
    is_thumb = True


class TritonARMv7MMachineDef(TritonARMMachineDef):
    arch = Architecture.ARM_V7M
    _registers = _V7M_REGS


class TritonARMv7RMachineDef(TritonARMMachineDef):
    arch = Architecture.ARM_V7R
    _registers = _V7R_REGS


class TritonARMv7AMachineDef(TritonARMMachineDef):
    arch = Architecture.ARM_V7A
    _registers = _V7A_REGS
