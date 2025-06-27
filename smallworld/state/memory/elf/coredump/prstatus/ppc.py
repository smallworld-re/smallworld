import typing

import lief

from ...... import platforms
from .prstatus import PrStatus


class PowerPC(PrStatus):
    byteorder = platforms.Byteorder.BIG

    @property
    def register_coords(
        self,
    ) -> typing.List[typing.Tuple[typing.Optional[str], int, int]]:
        return self._register_coords

    def __init__(self, elf: lief.ELF.Binary, wordsize):
        _register_list = [
            "r0",
            "r1",
            "r2",
            "r3",
            "r4",
            "r5",
            "r6",
            "r7",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "r16",
            "r17",
            "r18",
            "r19",
            "r20",
            "r21",
            "r22",
            "r23",
            "r24",
            "r25",
            "r26",
            "r27",
            "r28",
            "r29",
            "r30",
            "r31",
            "pc",
            # No idea what these are, as it's not documented.
            None,
            None,
            "ctr",
            "lr",
        ]
        self._register_coords = [
            (_register_list[i], i * wordsize, wordsize)
            for i in range(0, len(_register_list))
        ]
        super().__init__(elf)


class PowerPC32(PowerPC):
    architecture = platforms.Architecture.POWERPC32
    pr_regs_off = 72
    pr_regs_size = 192

    def __init__(self, elf: lief.ELF.Binary):
        super().__init__(elf, 4)


class PowerPC64(PowerPC):
    architecture = platforms.Architecture.POWERPC64

    pr_regs_off = 112
    pr_regs_size = 384

    def __init__(self, elf: lief.ELF.Binary):
        super().__init__(elf, 8)
