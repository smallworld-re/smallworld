from __future__ import annotations

import abc
import typing

from ..... import platforms, utils
from .....exceptions import ConfigurationError
from .. import elf
from ..structs import ElfRela

#: The TLS module ID relocators give every thread-local, for an
#: architecture's DTPMOD relocations.  SmallWorld emulates one module in
#: isolation, so there is exactly one TLS block, and it gets the
#: conventional ID 1; the TLS models name its storage arena by the same ID.
RELOCATED_TLS_MODULE = 1

DT_PLTGOT = 3  # Dynamic tag for the GOT base address.


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
        # Slots no linker built, by key; see synthetic_slot.
        self._synthetic_slots: typing.Dict[typing.Hashable, int] = {}

    def synthetic_slot(
        self, elf: elf.ElfExecutable, key: typing.Hashable, size: int, label: str
    ) -> int:
        """Address of a slot a linker would have built, creating it if needed.

        An object file has no GOT, and so none of the GOT entries or TLS
        descriptors its relocations name: building them is the linker's job.
        This reserves one past the image's loaded sections for each key.
        Keyed and idempotent, since `update_symbol_value` re-relocates every
        rela attached to a symbol.

        Arguments:
            elf: The image being relocated
            key: What the slot is for, such as a kind of slot and a symbol
            size: The slot's size in bytes
            label: A label for the reserved bytes

        Returns:
            The slot's address
        """
        if key not in self._synthetic_slots:
            self._synthetic_slots[key] = elf.reserve_synthetic(size, label)
        return self._synthetic_slots[key]

    def _symbol_name(self, rela: ElfRela) -> str:
        return rela.symbol.name if rela.symbol.name else "<anonymous>"

    def _missing_context(self, rela: ElfRela, detail: str) -> typing.NoReturn:
        raise ConfigurationError(
            f"Relocation {hex(rela.type)} for {self._symbol_name(rela)} requires "
            f"{detail}, which is not available to "
            f"{type(self).__name__}._compute_value()"
        )

    def _proxy_offset(
        self, rela: ElfRela, proxy_types: typing.Collection[int], detail: str
    ) -> int:
        """The one offset among a symbol's relocations of `proxy_types`.

        A relocation that needs an address the linker built, such as the
        symbol's GOT entry, finds it as the target of another relocation of
        the same symbol that fills it in.
        """
        offsets = sorted({r.offset for r in rela.symbol.relas if r.type in proxy_types})
        if len(offsets) == 1:
            return offsets[0]
        if len(offsets) == 0:
            self._missing_context(rela, detail)
        raise ConfigurationError(
            f"Relocation {hex(rela.type)} for {self._symbol_name(rela)} has "
            f"multiple candidate proxy entries for {detail}: "
            f"{', '.join(map(hex, offsets))}"
        )

    def _find_got_base(self, elf) -> typing.Optional[int]:
        """The address of the image's GOT, or None if it has none.

        DT_PLTGOT gives it in a linked image; otherwise it is the start of
        .got.plt, or of .got.
        """
        dtags = getattr(elf, "_dtags", {})
        if DT_PLTGOT in dtags:
            return elf._rebase_file(dtags[DT_PLTGOT])

        lief_elf = getattr(elf, "_elf", None)
        section_offsets = getattr(elf, "_section_offsets", {})
        if lief_elf is not None:
            for name in (".got.plt", ".got"):
                for idx, section in enumerate(lief_elf.sections):
                    if section.name != name:
                        continue
                    if getattr(section, "virtual_address", 0):
                        return elf._rebase_file(section.virtual_address)
                    if idx in section_offsets:
                        return elf.address + section_offsets[idx]
        return None

    def _got_base(self, rela: ElfRela, elf) -> int:
        got_base = self._find_got_base(elf)
        if got_base is None:
            self._missing_context(rela, "the GOT base address")
        return got_base

    def _got_entry_for(
        self,
        rela: ElfRela,
        elf,
        proxy_types: typing.Collection[int],
        size: int,
        value: int,
    ) -> int:
        """The address of the GOT entry for `rela`'s symbol.

        That is the target of the relocation of `proxy_types` (GLOB_DAT and
        the like) that fills it in. An object file has no GOT -- building one
        is the linker's job -- so there this synthesizes the symbol's entry
        and fills it with `value`, as that relocation would; it is rewritten
        whenever the symbol is re-relocated.

        Arguments:
            rela: The relocation that needs the entry
            elf: The image being relocated
            proxy_types: The relocation types that fill in a GOT entry
            size: A GOT entry's size in bytes
            value: What the symbol's entry holds

        Returns:
            The entry's address
        """
        if self._find_got_base(elf) is None and not any(
            r.type in proxy_types for r in rela.symbol.relas
        ):
            slot = self.synthetic_slot(
                elf, ("got", rela.symbol.idx), size, "synthetic GOT entry"
            )
            mask = (1 << (size * 8)) - 1
            elf.write_bytes(slot, (value & mask).to_bytes(size, self.byteorder.value))
            return slot
        return self._proxy_offset(rela, proxy_types, "the symbol's GOT entry address")

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

    def prepare_object(
        self,
        elf: elf.ElfExecutable,
        names: typing.Dict[int, str],
        offsets: typing.Dict[int, int],
        writable: typing.Set[int],
    ) -> None:
        """Set up what a linker would have created for an object file.

        Called once an object file's sections are placed in the image,
        before its symbols and relocations are processed.  Some
        architectures' relocations are relative to a table a linker builds
        (PowerPC64's TOC); this is where a relocator finds it.  The default
        does nothing.

        Arguments:
            elf: The image being loaded
            names: Each loaded section's name, by section index
            offsets: Each loaded section's image offset, by section index
            writable: Indexes of the writable, non-TLS sections
        """
        pass

    def linker_symbol_value(self, name: str) -> typing.Optional[int]:
        """The value a linker would give a symbol it defines itself.

        An object file leaves such symbols (e.g. PowerPC64's `.TOC.`)
        undefined.  The default defines none.

        Arguments:
            name: The undefined symbol's name

        Returns:
            Its address, or None if a linker wouldn't define it
        """
        return None

    @property
    def tls_descriptors(self) -> typing.List[int]:
        """Addresses of the TLS descriptors this relocator has written.

        Each is a { resolver, argument } pair whose resolver word is null at
        load, since no resolver has an address until a model library is
        linked; see :meth:`bind_tls_descriptor_resolver`.  Architectures with
        no descriptor ABI write none.
        """
        return []

    def bind_tls_descriptor_resolver(
        self, elf: elf.ElfExecutable, address: int
    ) -> None:
        """Point every TLS descriptor's resolver word at `address`.

        Called once a model library is linked, which is the first moment a
        resolver has an address at all: the descriptors are relocated at
        load, long before that.  Without this the resolver word stays null
        and code built with -mtls-dialect=gnu2 calls address zero.  The
        relocator also remembers the resolver, so a descriptor relocated
        again later is not written back to null.  The default does nothing,
        having no descriptors.

        Arguments:
            elf: The image the descriptors are in
            address: The resolver's address
        """
        pass

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
