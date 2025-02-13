from __future__ import annotations

import abc

from ..... import platforms, utils
from .....exceptions import ConfigurationError
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
    def _compute_value(self, rela: ElfRela) -> bytes:
        raise NotImplementedError("This is an abstract method.")

    def relocate(self, elf: elf.ElfExecutable, rela: ElfRela) -> None:
        val = self._compute_value(rela)
        for off, seg in elf.items():
            start = off + elf.address
            stop = start + seg.get_size()

            if rela.offset >= start and rela.offset < stop:
                start = rela.offset - start
                end = start + len(val)

                contents = seg.get_content()
                contents = contents[0:start] + val + contents[end:]
                seg.set_content(contents)
                return
        raise ConfigurationError(
            f"No segment in ELF loaded at {hex(elf.address)} covers address {hex(rela.offset)}"
        )

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
