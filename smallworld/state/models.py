import abc
import logging
import typing

from .. import emulators, platform, state, utils

logger = logging.getLogger(__name__)


class Hook(state.Stateful):
    def __init__(
        self, address: int, function: typing.Callable[[emulators.Emulator], None]
    ) -> None:
        self._address = address
        self._function = function

    def extract(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError("extracting hooks is not possible")

    def apply(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError("applying hooks is not yet implemented")


class Model(Hook):
    def __init__(
        self, address: int, function: typing.Callable[[emulators.Emulator], None]
    ) -> None:
        raise NotImplementedError("you should call `lookup()` instead")

    @classmethod
    @abc.abstractmethod
    def get_platform(cls) -> platform.Platform:
        pass

    @classmethod
    @abc.abstractmethod
    def get_name() -> str:
        pass

    @classmethod
    @abc.abstractmethod
    def get_abi() -> platform.ABI:
        pass

    @classmethod
    def lookup(cls, name: str, platform: platform.Platform, abi: platform.ABI):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.get_name() == name
                and x.get_platform() == platform
                and x.get_abi() == abi,
            )
        except ValueError:
            raise ValueError(f"no model for '{name}' on {platform} with ABI '{abi}'")


__all__ = ["Hook", "Model"]
