import typing

from ... import platforms
from .. import state
from . import cpu
from ...arch import aarch64_arch


class AArch64(cpu.CPU):
    """Auto-generated CPU state for aarch64:v8a:little

    Generated from Pcode language AARCH64:LE:64:v8A, and Unicorn package
    unicorn.arm64_const.
    """

    platform = platforms.Platform(
        platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
    )

    arch_info = aarch64_arch.info


    def get_general_purpose_registers(self) -> typing.List[str]:
        # Special registers:
        # x29: frame pointer
        # x30: link register
        # x31: stack pointer or zero, depending on instruction
        return [f"x{i}" for i in range(0, 29)]
