import abc
import typing

from ... import platforms, utils
from .. import state


class CPU(state.StatefulSet):
    """A CPU state object."""

    @property
    @abc.abstractmethod
    def platform(self) -> platforms.Platform:
        pass

    def get_platform(self) -> platforms.Platform:
        """Get the platform object for this CPU.

        Returns:
            The platform object for this CPU.
        """
        return self.platform

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        """Get a CPU object for a given platform specifier.

        Arguments:
            platform: The platform specificer for the desired CPU object.

        Returns:
            An instance of the desired CPU.
        """

        try:
            return utils.find_subclass(
                cls,
                lambda x: x.get_platform().architecture == platform.architecture
                and x.get_platform().byteorder == platform.byteorder,
            )()
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
        return f"{self.platform}"


__all__ = ["CPU"]
