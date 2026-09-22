"""The contract between a model library and the models that serve
thread-local storage.

Two models reach a thread-local by entirely different routes -- ``__tls_get_addr``
for the general-dynamic dialect, ``__tlsdesc_resolve`` for gnu2 descriptors --
and gcc picks the dialect per translation unit, so one image can reach the
*same* thread-local through both. They therefore have to hand out the same
bytes, and the model library is the only thing positioned to arrange it: it
holds the models and the loaded ELF, and neither can see the other.

These are the roles it arranges between. A model opts into one by inheriting
it, which is what lets the library find the participants by role rather than
by hardcoded function name, and keeps ``Model`` itself about modelling an
external function.
"""

import abc
import typing

#: The module id the relocator reports for every thread-local (see
#: R_X86_64_DTPMOD64). The harness loads one image, so there is one TLS block;
#: this names which per-module arena that block's storage lives in.
RELOCATED_TLS_MODULE = 1


class TlsArenaOwner(abc.ABC):
    """A model whose static buffer is the storage thread-locals live in.

    The owner reserves the whole pool and divides it into per-module arenas.
    It also says where a module's PT_TLS initialization image belongs, since
    only the model knows how it indexes its own storage -- and without the
    image every thread-local reads zero instead of its initializer, which is
    silent, zero being a plausible value.
    """

    #: Provided by ``Model``; declared here so this role stands on its own.
    static_buffer_address: typing.Optional[int]
    static_space_required: int

    #: Bytes of storage each module's arena gets.
    TLS_ARENA_SIZE: int
    #: Offset into the pool at which a module's PT_TLS image belongs.
    tls_image_offset: int
    #: How much of that image this model can actually serve. A thread-local is
    #: only ever read within its own arena, so the pool is not the bound.
    tls_image_capacity: int

    @classmethod
    @abc.abstractmethod
    def module_arena_offset(cls, module: int) -> int:
        """Offset within the pool at which ``module``'s arena begins."""
        raise NotImplementedError("This is an abstract method.")

    def tls_arena_address_for(self, module: int) -> typing.Optional[int]:
        """Where ``module``'s arena sits in memory, or None if none was
        reserved."""
        if self.static_buffer_address is None:
            return None
        return self.static_buffer_address + self.module_arena_offset(module)


class TlsArenaBorrower:
    """A model that serves thread-locals out of a :class:`TlsArenaOwner`'s
    storage.

    It reserves nothing itself -- its ``static_space_required`` is 0 -- and the
    library assigns these once the owner's buffer has an address, the way it
    assigns malloc's heap. Two separate pools would disagree silently: a write
    through one dialect would be invisible to a read through the other.

    State, not behaviour: how the borrower indexes the arena is its own
    business, and is not the same computation the owner performs.
    """

    #: None until the library assigns one.
    tls_arena_address: typing.Optional[int] = None
    tls_arena_size: int = 0
