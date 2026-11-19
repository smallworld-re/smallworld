from __future__ import annotations

import abc
import typing

from ..... import platforms, utils
from .. import elf
from ..structs import ElfRela


class ElfRelocator:
    """Platform-specific ELF relocator

    Each platform defines its own set of relocation types,
    defining how symbol values can update an image at link-time.

    A relocator covers every platform in `supported_platforms`;
    an architecture family whose members relocate alike
    shares one relocator.

    Arguments:
        platform: The platform to relocate for. It may be omitted
            when the relocator covers only one platform.
    """

    supported_platforms: typing.FrozenSet[platforms.Platform] = frozenset()

    def __init__(self, platform: typing.Optional[platforms.Platform] = None):
        if platform is None:
            if len(self.supported_platforms) != 1:
                raise ValueError(
                    f"{type(self).__name__} covers several platforms; pass one"
                )
            (platform,) = self.supported_platforms
        elif platform not in self.supported_platforms:
            raise ValueError(f"{type(self).__name__} does not cover {platform}")
        self.platform = platform

    @property
    def arch(self) -> platforms.Architecture:
        """The architecture ID"""
        return self.platform.architecture

    @property
    def byteorder(self) -> platforms.Byteorder:
        """The byte order"""
        return self.platform.byteorder

    @abc.abstractmethod
    def _compute_value(self, rela: ElfRela, elf: elf.ElfExecutable) -> bytes:
        raise NotImplementedError("This is an abstract method.")

    def relocate(self, elf: elf.ElfExecutable, rela: ElfRela) -> None:
        val = self._compute_value(rela, elf)
        elf.write_bytes(rela.offset, val)

    def is_tls_descriptor(self, rela: ElfRela) -> bool:
        """Whether this rela fills in a TLS descriptor { resolver, argument }.

        Relocation types are per-architecture, so only a relocator can answer
        this; the loader needs it to spot descriptors whose thread-local no
        loaded module defines. Those are left unrelocated like any other
        external reference, but unlike a data or function reference an
        unrelocated descriptor is CALLED -- its null resolver word sends
        control to address zero. Architectures with no descriptor ABI say no.
        """
        return False

    def is_tls_descriptor_reference(self, rela: ElfRela) -> bool:
        """Whether this rela is a PC-relative reference to a descriptor SLOT.

        The unlinked form of the same thing: a linker would have placed the
        two-word descriptor in the GOT and left an `is_tls_descriptor` rela to
        fill it in, but an object file has not been through a linker, so it
        names a GOT slot that does not exist yet.
        """
        return False

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        try:
            return utils.find_subclass(
                cls, lambda x: platform in x.supported_platforms, platform
            )
        except ValueError as e:
            # find_subclass raises ValueError only for the no-match case;
            # narrow to it so genuine internal errors (and
            # KeyboardInterrupt/SystemExit) are not masked as "No relocator".
            raise ValueError(f"No relocator for {platform}") from e
