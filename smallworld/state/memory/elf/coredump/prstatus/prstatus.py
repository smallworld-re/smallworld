import abc
import typing

import lief

from ...... import exceptions, platforms, utils
from .....cpus import CPU
from .....state import FixedRegister


class PrStatus:
    """Class for extracting process information from a core dump

    The prstatus struct is arch-specific.
    Lief can interpret them for a small number of architectures,
    but definitely not all supported by SmallWorld.
    """

    @property
    @abc.abstractmethod
    def architecture(self) -> platforms.Architecture:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def byteorder(self) -> platforms.Byteorder:
        raise NotImplementedError()

    def __init__(self, elf: lief.ELF.Binary):
        assert elf.header.file_type == lief.ELF.E_TYPE.CORE

        self.platform = platforms.Platform(self.architecture, self.byteorder)
        self.platdef = platforms.PlatformDef.for_platform(self.platform)

        self._registers: typing.Dict[str, int] = dict()

        # Find the PrStatus note
        prstatus: typing.Optional[lief.ELF.CorePrStatus] = None
        for note in elf.notes:
            if isinstance(note, lief.ELF.CorePrStatus):
                prstatus = note
                break

        if prstatus is None:
            # Didn't find one.
            raise exceptions.ConfigurationError("ELF core file has no PrStatus note")

        self._parse_prstatus(prstatus)

    @property
    @abc.abstractmethod
    def pr_regs_off(self) -> int:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def pr_regs_size(self) -> int:
        raise NotImplementedError()

    @property
    def register_coords(
        self,
    ) -> typing.List[typing.Tuple[typing.Optional[str], int, int]]:
        raise NotImplementedError()

    def _parse_prstatus(self, prstatus: lief.ELF.CorePrStatus) -> None:
        # Load the registers from prstatus.
        #
        # All prstatus structs have the same layout:
        # a single field called 'pr_regs' that contains a list of registers.
        # The only trick is knowng the offset of that field
        # and the offset and size of each register within it.

        # Get byteorder literals
        byteorder: typing.Literal["little", "big"]
        if self.byteorder is platforms.Byteorder.LITTLE:
            byteorder = "little"
        elif self.byteorder is platforms.Byteorder.BIG:
            # NOTE: Core dumps generated on a little-endian machine appear to come out little-endian.
            # This may be a problem in the future
            byteorder = "little"
        else:
            raise exceptions.ConfigurationError(
                f"Can't decode byteorder {self.byteorder}"
            )

        # Extract the raw bytes
        data = prstatus.description.tobytes()

        # Extract the registers from the struct
        for name, reg_off, reg_size in self.register_coords:
            if name is None:
                # Register we don't handle, or padding.
                continue
            reg_start = self.pr_regs_off + reg_off
            reg_end = self.pr_regs_off + reg_off + reg_size

            reg_bytes = data[reg_start:reg_end]
            if (
                self.platdef.address_size == 8
                and self.byteorder is platforms.Byteorder.BIG
            ):
                # 64-bit registers are somehow presented middle-endian
                # I have no idea.
                reg_bytes = reg_bytes[4:8] + reg_bytes[0:4]

            self._registers[name] = int.from_bytes(reg_bytes, byteorder)

    def populate_cpu(self, cpu: CPU) -> None:
        for reg, value in self._registers.items():
            if not hasattr(cpu, reg):
                raise exceptions.ConfigurationError(
                    f"PrStatus register {reg} not in CPU for platform {self.platform}"
                )
            field = getattr(cpu, reg)
            if not isinstance(field, FixedRegister):
                field.set(value)

    @classmethod
    def for_platform(cls, platform: platforms.Platform, elf: lief.ELF.Binary):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.architecture == platform.architecture
                and x.byteorder == platform.byteorder,
                elf,
            )
        except Exception as e:
            raise ValueError(f"No PrStatus class for {platform}") from e
