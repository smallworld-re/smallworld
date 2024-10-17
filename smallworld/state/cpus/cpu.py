import abc
import typing

from ... import platforms, utils
from .. import state


class CPU(state.StatefulSet):
    """A CPU state object."""

    def __deepcopy__(self, memo):
        new_cpu = (type(self))()
        for x in self.__dict__:
            a = self.__getattribute__(x)
            if type(a) is state.Register:
                new_cpu.__getattribute__(x).set(self.__getattribute__(x).get())
                new_cpu.__getattribute__(x).set_label(
                    self.__getattribute__(x).get_label()
                )
                new_cpu.__getattribute__(x).set_type(
                    self.__getattribute__(x).get_type()
                )
        return new_cpu

    @property
    @abc.abstractmethod
    def platform(self) -> platforms.Platform:
        pass

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        """Get the platform object for this CPU.

        Returns:
            The platform object for this CPU.
        """
        if not isinstance(cls.platform, platforms.Platform):
            raise TypeError(f"{cls.__name__}.platform is not a Platform object")
        return cls.platform

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        """Get a CPU object for a given platform specifier.

        Arguments:
            platform: The platform specificer for the desired CPU object.

        Returns:
            An instance of the desired CPU.
        """

        try:
            return utils.find_subclass(cls, lambda x: x.get_platform() == platform)
        except ValueError:
            raise ValueError(f"no model for {platform}")

    @abc.abstractmethod
    def get_general_purpose_registers(self) -> typing.List[str]:
        """Get a list of general purpose register names.

        Returns:
            A list of the general purpose register names for this CPU.
        """

        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.platform})"


__all__ = ["CPU"]
