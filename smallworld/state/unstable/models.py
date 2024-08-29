import abc
import logging
import typing

logger = logging.getLogger(__name__)

from .. import emulators, initializers
from . import state


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
        logger.debug(f"hooking {self} {self.address:x}")
        emulator.hook(self.address, self.function, finish=True)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(0x{self.address:x}:{self.function.__name__})"


class ImplementedModel(Model):
    @property
    def arch(self) -> str:
        return ""

    @property
    def mode(self) -> str:
        return ""

    @property
    def byteorder(self) -> str:
        return ""

    @property
    def abi(self) -> str:
        return ""

    @abc.abstractmethod
    def model(self, emulator: emulators.Emulator) -> None:
        pass

    @property
    @abc.abstractmethod
    def name(self):
        pass

    @property
    @abc.abstractmethod
    def argument1(self):
        pass

    @property
    @abc.abstractmethod
    def argument2(self):
        pass

    @property
    @abc.abstractmethod
    def argument3(self):
        pass

    @property
    @abc.abstractmethod
    def return_val(self):
        pass

    def __init__(self, address: int):
        def model(emulator: emulators.Emulator) -> None:
            self.model(emulator)

        super().__init__(address, model)


class ReturnsNothingImplementedModel(ImplementedModel):
    def model(self, emulator: emulators.Emulator) -> None:
        # so just do nothing
        pass


class Returns0ImplementedModel(ImplementedModel):
    def model(self, emulator: emulators.Emulator) -> None:
        # just return 0
        emulator.write_register(self.return_val, 0)
