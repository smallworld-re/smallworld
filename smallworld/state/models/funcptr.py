import logging

import smallworld
from smallworld import emulators, exceptions, utils
from smallworld.state.models.cstd import ArgumentType, CStdModel, signed_int_types

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

    def __handle_args(self, emulator: emulators.Emulator, args: list[int]):
        # TODO fix/generalize
        if len(args) == 2:
            emulator.write_register("r0", args[0])
            emulator.write_register("r1", args[1])
        emulator.write_register("pc", self.address)

    def call(self, emulator: emulators.Emulator, args: list[int]) -> None:
        if not isinstance(self.address, int):
            raise exceptions.ConfigurationError(
                "FunctionPointerValue set to non-integer value"
            )

        self.__handle_args(emulator, args)

    def get_return_value(self, emulator: emulators.Emulator):
        # TODO: handle ret value extraction

        if self.return_type in self.arch_model._four_byte_types:
            ret = emulator.read_register("r0")
            if (
                self.return_type in signed_int_types
                and (ret & self.arch_model._int_sign_mask) != 0
            ):
                ret = (ret ^ self.arch_model._int_inv_mask) + 1
                ret *= -1
        elif self.return_type == ArgumentType.VOID:
            ret = None
        else:
            raise NotImplementedError(
                f"No support for deserializing return type {self.return_type} in a function pointer model"
            )

        return ret
