import abc
import code
import logging
import pdb
import typing

from .. import emulators, platforms, utils
from . import state

logger = logging.getLogger(__name__)


class Hook(state.Stateful):
    def __init__(
        self, address: int, function: typing.Callable[[emulators.Emulator], None]
    ):
        self._address = address
        self._function = function

    def extract(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError("extracting hooks is not possible")

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.hook_instruction(self._address, self._function)


class Breakpoint(Hook):
    def __init__(self, address: int):
        super().__init__(address=address, function=self.interact)

    @staticmethod
    @abc.abstractmethod
    def interact(emulator: emulators.Emulator) -> None:
        pass


class PDBBreakpoint(Breakpoint):
    @staticmethod
    def interact(emulator: emulators.Emulator) -> None:
        pdb.set_trace()


class PythonShellBreakpoint(Breakpoint):
    @staticmethod
    def interact(emulator: emulators.Emulator) -> None:
        code.interact(local={"emulator": emulator})


class Model(Hook):
    def __init__(self, address: int):
        super().__init__(address=address, function=self.model)

    @property
    @abc.abstractmethod
    def name(self) -> str:
        return ""

    @property
    @abc.abstractmethod
    def platform(self) -> platforms.Platform:
        pass

    @property
    @abc.abstractmethod
    def abi(self) -> platforms.ABI:
        pass

    @classmethod
    def lookup(cls, name: str, platform: platforms.Platform, abi: platforms.ABI):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.name == name and x.platform == platform and x.abi == abi,
            )
        except ValueError:
            raise ValueError(f"no model for '{name}' on {platform} with ABI '{abi}'")

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.hook_function(self._address, self._function)

    @staticmethod
    @abc.abstractmethod
    def model(emulator: emulators.Emulator) -> None:
        pass


__all__ = ["Hook", "Breakpoint", "PDBBreakpoint", "PythonShellBreakpoint", "Model"]
