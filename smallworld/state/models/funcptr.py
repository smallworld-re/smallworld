import logging

import smallworld
from smallworld import emulators, exceptions, utils
from smallworld.state.models.cstd import ArgumentType, CStdModel, set_argument

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
        self.arch_model: CStdModel = utils.find_subclass(
            CStdModel, lambda x: x.platform == platform, None
        )

    def call(self, emulator: emulators.Emulator, args: list[int]) -> None:
        if not isinstance(self.address, int):
            raise exceptions.ConfigurationError(
                "FunctionPointerValue set to non-integer value"
            )
        # TODO fix/generalize
        if len(args) == 2:
            set_argument(self.arch_model, 0, emulator, args[0])
            set_argument(self.arch_model, 1, emulator, args[1])
        emulator.write_register("pc", self.address)

    def get_return_value(self, emulator: emulators.Emulator):
        return self.arch_model.get_return_value(emulator)
