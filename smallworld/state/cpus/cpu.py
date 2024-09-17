import abc
import typing

from ... import platforms, utils
from .. import state


class CPU(state.StatefulSet):
    @property
    @abc.abstractmethod
    def platform(self) -> platforms.Platform:
        pass

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.get_platform().architecture == platform.architecture
                and x.get_platform().byteorder == platform.byteorder,
            )
        except ValueError:
            raise ValueError(f"No CPU model for {platform}")

    @abc.abstractmethod
    def get_general_purpose_registers(self) -> typing.List[str]:
        pass

    def __repr__(self) -> str:
        return f"{self.platform}"


__all__ = ["CPU"]
