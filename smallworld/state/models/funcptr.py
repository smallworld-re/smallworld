import logging

import smallworld
from smallworld import emulators, exceptions, utils
from smallworld.state.models.cstd import ArgumentType, CStdCallingContext

logger = logging.getLogger(__name__)


class FunctionPointer:
    """For calling native functions from a model or callback"""

    def __init__(
        self,
        address: int,
        argument_types: list[ArgumentType],
        return_type: ArgumentType,
        platform: smallworld.platforms.Platform,
    ):
        self.address = address
        self.argument_types = argument_types
        self.return_type = return_type
        self.context: CStdCallingContext = utils.find_subclass(
            CStdCallingContext, lambda x: x.platform == platform
        )
        self.context.set_argument_types(argument_types)
        self.context.return_type = self.return_type

    def call(
        self, emulator: emulators.Emulator, args: list[int | float], return_address: int
    ) -> None:
        """Set up the calling stack frame for the function this points to.

        NOTE: The function will not be emulated until control flow returns to the
        emulator. To continue processing in a Model using the function's return
        value, set the `return_address` parameter to the Model's address and set
        `skip_return` on the Model to `True`. The return value can then be read
        using `get_return_value`. Set `skip_return` to `False` to exit the Model.

        Arguments:
            emulator: the emulator whose state will be mutated.
            args: arguments to be passed to the function.
            return_address: the address to return to from function.
                In a Model, set this to `self._address` to return to
                this model and continue processing.
        """
        if not isinstance(self.address, int):
            raise exceptions.ConfigurationError(
                "FunctionPointerValue set to non-integer value"
            )
        self.context.set_return_address(emulator, return_address, push=True)
        for i, arg in enumerate(args):
            self.context.set_argument(i, emulator, arg)
        emulator.write_register("pc", self.address)

    def get_return_value(self, emulator: emulators.Emulator):
        return self.context.get_return_value(emulator)
