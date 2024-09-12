import abc
import logging
import typing

from smallworld.emulators.emulator import Emulator
from smallworld.platform import ABI, Platform
from smallworld.state.state import Stateful
from .. import utils

logger = logging.getLogger(__name__)

class Hook(Stateful):
    def __init__(self, address: int, function: typing.Callable[[Emulator], None]) -> None:
        self._address = address
        self._function = function


class Model(Hook):
    def __init__(self, address: int, function: typing.Callable[[Emulator], None]) -> None:
        raise NotImplemented("You should call lookup() instead")

    @classmethod
    @abc.abstractmethod
    def get_platform(cls) -> Platform:
        pass

    @classmethod
    @abc.abstractmethod
    def get_name() -> str:
        pass

    @classmethod
    @abc.abstractmethod
    def get_abi() -> ABI:
        pass

    @classmethod
    def lookup(cls, name: str, platform: Platform, abi: ABI):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.get_name() == name
                and x.get_platform() == platform
                and x.get_abi() == abi,
            )
        except ValueError:
            raise ValueError(
                f"No model for {name} on platform {platform.architecture}:{platform.byteorder} and abi {abi}"
            )
