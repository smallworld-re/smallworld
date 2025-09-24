import abc
import logging
import typing

from ...emulators import Emulator
from ...platforms import ABI, Platform
from ..memory import Memory
from ..memory.elf import ElfExecutable
from ..state import BytesValue
from .cstd import CStdModel
from .model import Model

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

        self.models: typing.Dict[str, CStdModel] = dict()

        address = address
        code_size = 0
        data_size = 0

        for name in self.function_names:
            model = Model.lookup(name, self.platform, self.abi, address + code_size)
            if model.name in allow_imprecise:
                model.allow_imprecise = True

            self.models[name] = model
            code_size += 4
            data_size += model.static_space_required

        super().__init__(address, code_size + data_size)

        data_offset = code_size

        # This should be stable in supported versions of python
        for _, model in self.models.items():
            model.static_buffer_address = self.address + data_offset
            self[data_offset] = BytesValue(b"\0" * model.static_space_required, None)
            data_offset += model.static_space_required

    @property
    @abc.abstractmethod
    def function_names(self) -> typing.List[str]:
        raise NotImplementedError()

    def link(self, elf: ElfExecutable) -> None:
        for rela in elf._dynamic_relas:
            sym = rela.symbol
            if sym.name == "":
                # This isn't a real symbol
                continue
            if sym.defined:
                # This relocation is already satisfied
                continue

            if sym.name in self.models:
                model = self.models[sym.name]
                if model.imprecise and not model.allow_imprecise:
                    log.warning(
                        f"Harness requires {model.name}, which is imprecise and currently not whitecarded"
                    )
                if model.unsupported:
                    log.warning(f"Harness requires {model.name}, which is unsupported")
                elf.update_symbol_value(sym, model._address, rebase=True)

    def apply(self, emulator: Emulator) -> None:
        super().apply(emulator)
        for _, model in self.models.items():
            model.apply(emulator)
