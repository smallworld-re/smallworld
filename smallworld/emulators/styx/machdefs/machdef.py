from __future__ import annotations

import abc
import typing

from .... import exceptions, platforms, utils


class StyxMachineDef(metaclass=abc.ABCMeta):
    """Container class for Styx architecture-specific definitions.

    Styx is firmware-oriented: each concrete subclass binds a SmallWorld
    `Architecture` + `Byteorder` to a specific Styx `Target` enum value
    (e.g. `Target.Kinetis21`) and a register-name map onto the Styx register
    enum for that architecture family.
    """

    @property
    @abc.abstractmethod
    def arch(self) -> platforms.Architecture:
        raise NotImplementedError("Abstract styx machine def has no architecture")

    @property
    @abc.abstractmethod
    def byteorder(self) -> platforms.Byteorder:
        raise NotImplementedError("Abstract styx machine def has no byteorder")

    @property
    @abc.abstractmethod
    def target(self) -> typing.Any:
        """The Styx `Target` enum value to build a Processor for."""
        raise NotImplementedError("Abstract styx machine def has no target")

    @property
    @abc.abstractmethod
    def backend(self) -> typing.Any:
        """The Styx `Backend` enum value (Unicorn or Pcode)."""
        raise NotImplementedError("Abstract styx machine def has no backend")

    _registers: typing.Dict[str, typing.Any] = {}
    """Map from SmallWorld register name (lowercase) to the Styx register enum."""

    pc_register: str = "pc"
    """Name of the program counter register in this architecture."""

    lr_register: typing.Optional[str] = None
    """Name of the link register (for function return), if applicable."""

    address_size: int = 4
    """Address size in bytes (4 for 32-bit ARM)."""

    def styx_register(self, name: str) -> typing.Any:
        """Translate a SmallWorld register name into a Styx register enum value."""
        key = name.lower()
        if key not in self._registers:
            raise exceptions.UnsupportedRegisterError(
                f"Styx machine def for {self.arch}:{self.byteorder} has no register '{name}'"
            )
        return self._registers[key]

    def has_register(self, name: str) -> bool:
        return name.lower() in self._registers

    @classmethod
    def for_platform(cls, platform: platforms.Platform) -> "StyxMachineDef":
        """Find the StyxMachineDef subclass that matches the requested platform.

        Raises `ConfigurationError` if Styx has no target for that architecture
        (e.g. aarch64 or x86_64), so callers get a clear message instead of
        an opaque register-mapping failure later on.
        """
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.arch == platform.architecture
                and x.byteorder == platform.byteorder,
            )
        except Exception as e:
            raise exceptions.ConfigurationError(
                f"Styx has no target for {platform.architecture}:{platform.byteorder}. "
                f"32-bit ARM (armhf/armel) is the only supported family at this time; "
                f"use UnicornEmulator or GhidraEmulator for other architectures."
            ) from e
