import abc
import inspect
import typing


class UnicornMachineDef(metaclass=abc.ABCMeta):
    """Container class for Unicorn architecture-specific definitions"""

    @property
    @abc.abstractmethod
    def arch(self) -> str:
        """The architecture ID string"""
        return ""

    @property
    @abc.abstractmethod
    def mode(self) -> str:
        """The mode ID string"""
        return ""

    @property
    @abc.abstractmethod
    def byteorder(self) -> str:
        """The byte order"""
        return ""

    @property
    @abc.abstractmethod
    def uc_arch(self) -> int:
        """The Unicorn architecture ID"""
        return 0

    @property
    @abc.abstractmethod
    def uc_mode(self) -> int:
        """The unicorn mode ID

        This must include an byteorder flag
        """
        return 0

    @property
    @abc.abstractmethod
    def cs_arch(self) -> int:
        """The capstone arch ID"""
        return 0

    @property
    @abc.abstractmethod
    def cs_mode(self) -> int:
        """The capstone mode ID

        This must include an byteorder flag
        """
        return 0

    @property
    @abc.abstractmethod
    def pc_reg(self) -> str:
        """The name of the Program Counter register for this machine"""
        return ""

    _registers: typing.Dict[str, int] = {}

    def uc_reg(self, name: str) -> int:
        """Convert a register name to unicorn constant

        This must cover all names defined in the CPU state model
        for this arch/mode/byteorder, or return 0,
        which always indicates an invalid register
        """
        if name in self._registers:
            return self._registers[name]
        else:
            raise ValueError(
                f"Unknown register for {self.arch}:{self.mode}:{self.byteorder}: {name}"
            )

    @classmethod
    def for_arch(cls, arch: str, mode: str, byteorder: str):
        """Find the appropriate MachineDef for your architecture

        Arguments:
            arch: The architecture ID you want
            mode: The mode ID you want
            byteorder: The byteorderness you want

        Returns:
            An instance of the appropriate MachineDef

        Raises:
            ValueError: If no MachineDef subclass matches your request
        """
        class_stack: typing.List[typing.Type[UnicornMachineDef]] = list(
            UnicornMachineDef.__subclasses__()
        )
        while len(class_stack) > 0:
            impl: typing.Type[UnicornMachineDef] = class_stack.pop(-1)
            if not inspect.isabstract(impl):
                if (
                    impl.arch == arch
                    and impl.mode == mode
                    and impl.byteorder == byteorder
                ):
                    return impl()
            # __subclasses__ is not transitive.
            # Need to do a full traversal.
            class_stack.extend(impl.__subclasses__())
        raise ValueError(f"No machine model for {arch}:{mode}:{byteorder}")
