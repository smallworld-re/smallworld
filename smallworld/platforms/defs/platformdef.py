import abc
import typing
from dataclasses import dataclass

from ... import utils
from ..platforms import Architecture, Byteorder, Platform


@dataclass(frozen=True)
class RegisterDef:
    name: str
    size: int


@dataclass(frozen=True)
class RegisterAliasDef(RegisterDef):
    parent: str
    offset: int


class PlatformDef(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def architecture(self) -> Architecture:
        """Architecture ID for this platform"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def byteorder(self) -> Byteorder:
        """Byteorder for this platform"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def address_size(self) -> int:
        """Address size in bytes"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def capstone_arch(self) -> int:
        """Capstone Architecture ID"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def capstone_mode(self) -> int:
        """Capstone Mode ID"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def conditional_branch_mnemonics(self) -> typing.Set[str]:
        """Set of conditional branch mnemonics"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def compare_mnemonics(self) -> typing.Set[str]:
        """Set of comparison mnemonics"""
        raise NotImplementedError()

    delay_slot_mnemonics: typing.Set[str] = set()
    """Set of delay slot mnemonics"""

    implicit_dereference_mnemonics: typing.Set[str] = set()
    """Set of mnemonics for instructions that implicitly dereference a register"""

    @property
    @abc.abstractmethod
    def pc_register(self) -> str:
        """Program Counter register name"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def sp_register(self) -> str:
        """Stack Pointer register name"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def general_purpose_registers(self) -> typing.List[str]:
        """List of general-purpose register names"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def registers(self) -> typing.Dict[str, RegisterDef]:
        """Mapping from canonical register names to register definitions"""
        raise NotImplementedError()

    @classmethod
    def for_platform(cls, platform: Platform):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.architecture == platform.architecture
                and x.byteorder == platform.byteorder,
            )
        except:
            raise ValueError(f"No platform definition for {platform}")
