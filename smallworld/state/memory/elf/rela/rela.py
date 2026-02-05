from __future__ import annotations

import abc

from ..... import platforms, utils
from .. import elf
from ..structs import ElfRela


class ElfRelocator:
    """Platform-specific ELF relocator

    Each platform defines its own set of relocation types,
    defining how symbol values can update an image at link-time.


    """

    @property
    @abc.abstractmethod
    def arch(self) -> platforms.Architecture:
        """The architecture ID"""
        raise NotImplementedError("This is an abstract method")

    @property
    @abc.abstractmethod
    def byteorder(self) -> platforms.Byteorder:
        """The byte order"""
        raise NotImplementedError("This is an abstract method.")

    @abc.abstractmethod
    def _compute_value(self, rela: ElfRela, elf: elf.ElfExecutable) -> bytes:
        raise NotImplementedError("This is an abstract method.")

    def relocate(self, elf: elf.ElfExecutable, rela: ElfRela) -> None:
        val = self._compute_value(rela, elf)
        elf.write_bytes(rela.offset, val, self.byteorder)

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.arch == platform.architecture
                and x.byteorder == platform.byteorder,
            )
        except:
            raise ValueError(f"No relocator for {platform}")
