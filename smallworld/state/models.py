import abc
import logging
import typing

from .. import emulators, initializers
from . import state

logger = logging.getLogger(__name__)


class Model(state.Value):
    """A runtime function model implemented in Python.

    If execution reaches the given address, call the given function instead of
    any code at that address and return.

    Arguments:
        address: The address to hook.
        function: The model function.
    """

    def __init__(
        self, address: int, function: typing.Callable[[emulators.Emulator], None]
    ):
        self.address = address
        self.function = function

    @property
    def value(self):
        raise NotImplementedError()

    @value.setter
    def value(self, value) -> None:
        raise NotImplementedError()

    def initialize(
        self, initializer: initializers.Initializer, override: bool = False
    ) -> None:
        logger.debug(f"skipping initialization for {self} (hook)")

    def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
        logger.debug(f"{self} loading not supported - load skipped")

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.hook(self.address, self.function)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(0x{self.address:x}:{self.function.__name__})"


class ImplementedModel(Model):
    @abc.abstractmethod
    def model(self, emulator: emulators.Emulator) -> None:
        pass

    def __init__(self, address: int):
        def model(emulator: emulators.Emulator) -> None:
            self.model(emulator)

        super().__init__(address, model)


class GetsModel(ImplementedModel):
    """LibC Gets implementation."""

    @property
    @abc.abstractmethod
    def argument(self):
        pass

    def model(self, emulator: emulators.Emulator) -> None:
        s = emulator.read_register(self.argument)
        value = input()
        emulator.write_memory(s, value.encode("utf-8"))


class AMD64SystemVGetsModel(GetsModel):
    argument = "rdi"


class AMD64MicrosoftGetsModel(GetsModel):
    argument = "rcx"


__all__ = [
    "Model",
    "AMD64SystemVGetsModel",
    "AMD64MicrosoftGetsModel",
]
