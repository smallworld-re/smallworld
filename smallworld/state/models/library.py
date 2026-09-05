import abc
import itertools
import logging
import typing

from ...emulators import Emulator
from ...platforms import ABI, Platform, PlatformDef
from ..memory import Memory
from ..memory.elf import ElfExecutable
from ..state import BytesValue
from .cstd import CStdModel
from .model import Model
from .tls import RELOCATED_TLS_MODULE, TlsArenaBorrower, TlsArenaOwner

log = logging.getLogger(__name__)


class ElfModelLibrary(Memory):
    """Abstract representation of an ELF shared

    This gives a single interface for adding
    something like libc to your harness,
    rather than adding and linking every single
    function model individually.
    """

    def __init__(
        self,
        address: int,
        platform: Platform,
        abi: ABI,
        allow_imprecise: typing.Set[str] = set(),
    ):
        self.platform = platform
        self.abi = abi

        self.platdef = PlatformDef.for_platform(platform)

        self.models: typing.Dict[str, CStdModel] = dict()

        self.variable_addrs: typing.Dict[str, int] = dict()

        self.code_size: int = 0

        address = address
        data_size = 0

        for name in self.function_names:
            # A model name advertised by function_names may not have a concrete
            # binding for this platform/ABI (models are bound per-arch). Skip
            # those rather than failing to construct the whole library -- the
            # corresponding calls simply stay unmodeled.
            try:
                model = Model.lookup(
                    name, self.platform, self.abi, address + self.code_size
                )
            except ValueError:
                log.debug(
                    f"no model for {name} on {self.platform} ABI {self.abi}; skipping"
                )
                continue
            if model.name in allow_imprecise:
                model.allow_imprecise = True

            self.models[name] = model
            self.code_size += 4
            data_size += model.static_space_required

        # The region holds, in order: model trampolines (code_size), the
        # exported variables (stdin/stdout/stderr, ...), then per-model static
        # buffers (data_size). The variables were previously omitted from the
        # size, so the last static buffer overflowed the region by the total
        # variable size -- harmless until a model whose buffer sits at the edge
        # is actually invoked. Account for them.
        variables_size = sum(size for _, size in self.variables)
        super().__init__(address, self.code_size + variables_size + data_size)

        data_offset = self.code_size

        for name, size in self.variables:
            self.variable_addrs[name] = self.address + data_offset
            self[data_offset] = BytesValue(b"\0" * size, None)
            data_offset += size

        # This should be stable in supported versions of python
        for _, model in self.models.items():
            if model.static_space_required > 0:
                model.static_buffer_address = self.address + data_offset
                self[data_offset] = BytesValue(
                    b"\0" * model.static_space_required, None
                )
                data_offset += model.static_space_required

        self._share_tls_arena()

    @property
    @abc.abstractmethod
    def variables(self) -> typing.List[typing.Tuple[str, int]]:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def function_names(self) -> typing.List[str]:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def alt_names(self) -> typing.Dict[str, str]:
        raise NotImplementedError()

    def link(self, elf: ElfExecutable) -> None:
        for rela in itertools.chain(elf._dynamic_relas, elf._static_relas):
            sym = rela.symbol
            if sym.name == "":
                # This isn't a real symbol
                continue
            if sym.defined:
                # This relocation is already satisfied
                continue

            if sym.name in self.variable_addrs:
                # This relocation references a variable
                elf.update_symbol_value(sym.name, self.variable_addrs[sym.name])
                continue

            if sym.name in self.models:
                model = self.models[sym.name]
            elif sym.name in self.alt_names:
                model = self.models[self.alt_names[sym.name]]
            else:
                continue

            if model.imprecise and not model.allow_imprecise:
                log.warning(
                    f"Harness requires {model.name}, which is imprecise and currently not whitecarded"
                )
            if model.unsupported:
                log.warning(f"Harness requires {model.name}, which is unsupported")
            elf.update_symbol_value(sym, model._address)

        # The models hand out TLS storage but cannot reach the ELF; this is
        # the one place holding both, and without it every thread-local reads
        # zero rather than its initializer.
        self._seed_tls_image(elf)

        # Descriptors carry a resolver address rather than a symbol, so no
        # relocation reaches them; they load with a null resolver and are
        # bound here, the first point at which the model has an address.
        tlsdesc = self.models.get("__tlsdesc_resolve")
        if tlsdesc is not None:
            elf.bind_tlsdesc_resolver(tlsdesc._address)
        elif elf.tlsdesc_descriptors:
            # Silence here would surface much later as a call to address zero,
            # with nothing tying it back to TLS.
            log.warning(
                f"{len(elf.tlsdesc_descriptors)} TLS descriptors need a resolver, "
                f"but this library provides no __tlsdesc_resolve model; "
                f"thread-local accesses will call address zero"
            )

    def _share_tls_arena(self) -> None:
        """Hand every borrowing TLS model the owner's storage.

        gcc picks a TLS dialect per translation unit, so one image can reach
        the same thread-local through both models. Both reduce to an offset
        within the module the relocator reports, so sharing that module's
        arena keeps them consistent; separate pools silently disagree.

        Which model owns the storage is a role, not a function name, so it is
        asked for by role -- see `models/tls.py`.
        """
        arena: typing.Optional[int] = None
        size = 0
        for model in self.models.values():
            if isinstance(model, TlsArenaOwner):
                arena = model.tls_arena_address_for(RELOCATED_TLS_MODULE)
                size = model.TLS_ARENA_SIZE
                break
        if arena is None:
            # No owner in this library, or the owner reserved no buffer.
            return
        for model in self.models.values():
            if isinstance(model, TlsArenaBorrower):
                model.tls_arena_address = arena
                model.tls_arena_size = size

    def _seed_tls_image(self, elf: ElfExecutable) -> None:
        """Copy the image's PT_TLS initialization data into the storage that
        serves thread-locals, at the offset its owner says the image belongs."""
        image = elf.tls_image
        if not image:
            return
        for model in self.models.values():
            if not isinstance(model, TlsArenaOwner):
                continue
            if model.static_buffer_address is None:
                continue
            room = min(
                model.static_space_required - model.tls_image_offset,
                model.tls_image_capacity,
            )
            if room <= 0:
                continue
            if len(image) > room:
                log.warning(
                    f"{model.name}: TLS image is {len(image):#x} bytes but only "
                    f"{room:#x} fit; thread-locals past the end read zero"
                )
            chunk = image[:room]
            base = model.static_buffer_address - self.address + model.tls_image_offset
            self[base] = BytesValue(chunk, None)

    def apply(self, emulator: Emulator) -> None:
        super().apply(emulator)
        for _, model in self.models.items():
            model.apply(emulator)
