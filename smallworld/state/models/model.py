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
        super().__init__(address=address, function=self.run_model)
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

    skip_return = False

    def run_model(self, emulator: emulators.Emulator) -> None:
        self.model(emulator)

        if self.skip_return or isinstance(emulator, emulators.AngrEmulator):
            return

        # Mimic a platform-specific "return" instruction.
        if self.platform.architecture == platforms.Architecture.X86_32:
            sp = emulator.read_register("esp")
            if self.platform.byteorder == platforms.Byteorder.LITTLE:
                ret = int.from_bytes(emulator.read_memory(sp, 4), "little")
            elif self.platform.byteorder == platforms.Byteorder.BIG:
                ret = int.from_bytes(emulator.read_memory(sp, 4), "big")
            emulator.write_register("esp", sp + 4)
        elif self.platform.architecture == platforms.Architecture.X86_64:
            # amd64: pop an 8-byte value off the stack
            sp = emulator.read_register("rsp")
            if self.platform.byteorder == platforms.Byteorder.LITTLE:
                ret = int.from_bytes(emulator.read_memory(sp, 8), "little")
            elif self.platform.byteorder == platforms.Byteorder.BIG:
                ret = int.from_bytes(emulator.read_memory(sp, 8), "big")
            emulator.write_register("rsp", sp + 8)
        elif (
            self.platform.architecture == platforms.Architecture.AARCH64
            or self.platform.architecture == platforms.Architecture.ARM_V5T
            or self.platform.architecture == platforms.Architecture.ARM_V6M
            or self.platform.architecture == platforms.Architecture.ARM_V6M_THUMB
            or self.platform.architecture == platforms.Architecture.ARM_V7A
            or self.platform.architecture == platforms.Architecture.ARM_V7M
            or self.platform.architecture == platforms.Architecture.ARM_V7R
            or self.platform.architecture == platforms.Architecture.POWERPC32
            or self.platform.architecture == platforms.Architecture.POWERPC64
        ):
            # aarch64, arm32, powerpc and powerpc64: branch to register 'lr'
            ret = emulator.read_register("lr")
        elif (
            self.platform.architecture == platforms.Architecture.LOONGARCH64
            or self.platform.architecture == platforms.Architecture.MIPS32
            or self.platform.architecture == platforms.Architecture.MIPS64
            or self.platform.architecture == platforms.Architecture.RISCV64
        ):
            # mips32, mips64, and riscv64: branch to register 'ra'
            ret = emulator.read_register("ra")
        elif self.platform.architecture == platforms.Architecture.XTENSA:
            # xtensa: branch to register 'a0'
            ret = emulator.read_register("a0")
        else:
            raise exceptions.ConfigurationError(
                "Don't know how to return for {self.platform.architecture}"
            )

        emulator.write_register("pc", ret)


__all__ = [
    "Hook",
    "Breakpoint",
    "PDBBreakpoint",
    "PythonShellBreakpoint",
    "Model",
]
