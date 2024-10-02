import abc
import typing

from ... import platforms, utils
from .. import state


class CPU(state.StatefulSet):
    """A CPU state object."""

    def __init__(self):

        # uses cpu-specific arch info
        # to add all registers and register aliases to the cpu
        # and to the stateful set

        def add_base_reg(base_reg_name, size):
            val = state.Register(base_reg_name, size)
            # only add the base name reg to this set
            setattr(self, base_reg_name, val)
            attr = self.__getattribute__(base_reg_name)
            self.add(attr)
            return attr

        for (reg_name, info) in self.arch_info.items(): # amd64_arch.info.items():
            (base_reg_name,(start,end)) = info
            size = end-start
            if reg_name == base_reg_name:
                _ = add_base_reg(reg_name, size)
            else:
                if not hasattr(self, base_reg_name):
                    #(base_reg_name,(start,end)) = amd64_arch.info[base_reg_name]            
                    (base_reg_name,(start,end)) = self.arch_info[base_reg_name]            
                    size = end-start
                    reference = add_base_reg(base_reg_name, size)
                else:
                    reference = self.__getattribute__(base_reg_name)
                val = state.RegisterAlias(reg_name, reference, \
                                          size, start)
                setattr(self, reg_name, val)

    def __deepcopy__(self, memo):
        new_cpu = (type(self))()
        for x in self.__dict__:
            a = self.__getattribute__(x)
            if type(a) is state.Register:
                new_cpu.__getattribute__(x).set(self.__getattribute__(x).get())
                new_cpu.__getattribute__(x).set_label(self.__getattribute__(x).get_label())
                new_cpu.__getattribute__(x).set_type(self.__getattribute__(x).get_type())                
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
