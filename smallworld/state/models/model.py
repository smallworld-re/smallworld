import abc
import code
import logging
import pdb
import typing

from ... import emulators, exceptions, platforms, utils
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
        if not isinstance(emulator, emulators.InstructionHookable):
            raise exceptions.ConfigurationError("Emulator cannot hook instructions")
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
    """A PDB interactive breakpoint."""

    @staticmethod
    def interact(emulator: emulators.Emulator) -> None:
        pdb.set_trace()


class PythonShellBreakpoint(Breakpoint):
    """A Python shell interactive breakpoint."""

    @staticmethod
    def interact(emulator: emulators.Emulator) -> None:
        code.interact(local={"emulator": emulator})


class Model(Hook):
    """A runtime function model implemented in Python.

    If execution reaches the given address, call the function assigned
    to self.model, instead of any code at that address in the
    emulator, and return. This is most often used to model an external
    function, e.g., libc `fread`. It is the responsibility of the
    model to read arguments and generate reasonable return values.

    Some models require static scratch space to operate.
    The quantity is stored in the 'static_space_required' attribute.
    If true, the harness must set the 'static_buffer_address' property
    of this model object.  The model will take care of mapping
    a buffer of the appropriate size at that address.

    A harness doesn't need to include a `Memory` object
    for a static buffer.  A harness can include such an object
    if it wants to initialize that memory with a specific value, or if it
    wants to inspect the contents of that buffer via `Machine.extract()`

    Arguments:
        address: The address to model.
    """

    def __init__(self, address: int):
        super().__init__(address=address, function=self.model)
        self.static_buffer_address: typing.Optional[int] = None

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """A name for this model, e.g., fread or ioctl."""
        return ""

    @property
    @abc.abstractmethod
    def platform(self) -> platforms.Platform:
        """The platform for which this model is defined."""
        pass

    @property
    @abc.abstractmethod
    def abi(self) -> platforms.ABI:
        """The ABI according to which this model works."""
        pass

    static_space_required: int = 0

    @classmethod
    def lookup(
        cls, name: str, platform: platforms.Platform, abi: platforms.ABI, address: int
    ):
        """Instantiate a model by name, platform, and ABI.

        Arguments:
            name: The name of the model.
            platform: The platform for which this model is defined.
            abi: The ABI according to which this model works.
            address: The instruction address which the model will hook.

        Returns:
            The fully instantiated model.
        """
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.name == name and x.platform == platform and x.abi == abi,
                address,
            )
        except ValueError:
            raise ValueError(f"no model for '{name}' on {platform} with ABI '{abi}'")

    def apply(self, emulator: emulators.Emulator) -> None:
        logger.debug(f"Hooking Model {self} {self._address:x}")

        if self.static_space_required != 0:
            # We need a static buffer.
            if self.static_buffer_address is None:
                # Harness author forgot to reserve us one
                raise exceptions.ConfigurationError(
                    f"No static buffer address provided for {self.name}"
                )
            emulator.map_memory(self.static_buffer_address, self.static_space_required)

        # Map just enough memory to jump to the model address without faulting.
        emulator.map_memory(self._address, 16)

        # Add the function hook to the emulator
        if not isinstance(emulator, emulators.FunctionHookable):
            raise exceptions.ConfigurationError("Emulator cannot hook functions")
        emulator.hook_function(self._address, self._function)

    @abc.abstractmethod
    def model(self, emulator: emulators.Emulator) -> None:
        """This is the implementation of the model for the named function.

        Note that implementation will have to make use of knowledge of
        the ABI to obtain arguments and return results, as well as
        modeling the semantics of the modeled functions appropriately.

        """
        pass


__all__ = [
    "Hook",
    "Breakpoint",
    "PDBBreakpoint",
    "PythonShellBreakpoint",
    "Model",
]
