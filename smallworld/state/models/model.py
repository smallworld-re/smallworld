import abc
import code
import logging
import pdb
import typing

from ... import emulators, platforms, utils
from .. import state

logger = logging.getLogger(__name__)


class Hook(state.Stateful):
    """Hook a particular instruction with a function.

    Runs the function provided when the emulator reaches (but has not
    yet executed) the instruction at a particular address.

    Arguments:
        address: The address of the instruction.
        function: The function to run.
    """
    

    def __init__(
        self, address: int, function: typing.Callable[[emulators.Emulator], None]
    ):
        self._address = address
        self._function = function

    def extract(self, emulator: emulators.Emulator) -> None:
        # Hooks have no state to extract;
        # Just as we assume the memory layout is the same,
        # we have to assume the hook layout is the same.
        pass

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.hook_instruction(self._address, self._function)


class Breakpoint(Hook):

    """An interactive breakpoint.

    Stops execution at the specified address and opens an interactive
    shell, as specified in the self.interact method.

    Arguments:
        address: The address of the breakpoint.

    """

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
    """A runtime function model implemented in Python.

    If execution reaches the given address, call the given function,
    self.model, instead of any code at that address and return. This
    is most often used to model an external function, e.g., libc
    `fread`. It is the responsibility of the model to read arguments
    and generate reasonable return values.

    Arguments:
        address: The address to model.

    """
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
    def lookup(cls, name: str, platform: platforms.Platform, abi: platforms.ABI, address:int):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.name == name and x.platform == platform and x.abi == abi,
                address
            )
        except ValueError:
            raise ValueError(f"no model for '{name}' on {platform} with ABI '{abi}'")

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.hook_function(self._address, self._function)

    @staticmethod
    @abc.abstractmethod
    def model(emulator: emulators.Emulator) -> None:
        pass


class ImplementedModel(Model):

    model = None
    name = "None"
    platform = None
    abi = None

    def __init__(self, address:int, function):
        self.model = function
        super().__init__(address)
    

__all__ = ["Hook", "Breakpoint", "PDBBreakpoint", "PythonShellBreakpoint", "Model", "ImplementedModel"]
