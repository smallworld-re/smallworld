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

    cpu_models: typing.Dict[str, typing.Tuple[typing.Any, typing.Any]] = {}
    """Optional map: ``cpu_model`` name (lowercase) -> ``(Target, Backend)``.

    Families with more than one selectable core (e.g. PowerPC: ppc405 on Pcode,
    mpc860 on Unicorn) populate this; single-core machdefs leave it empty and
    always use the default ``target``/``backend``.
    """

    pc_register: str = "pc"
    """Name of the program counter register in this architecture."""

    lr_register: typing.Optional[str] = None
    """Name of the link register (for function return), if applicable."""

    address_size: int = 4
    """Address size in bytes (4 for 32-bit ARM)."""

    interworking: bool = False
    """Does bit 0 of an address written to pc select the instruction set?

    True for ARM with both ARM and Thumb (A- and R-profile, v4T and later):
    an odd address runs Thumb, an even one ARM, as ``bx`` does.
    """

    hook_registers: typing.Optional[typing.Mapping[str, str]] = None
    """Map from SmallWorld register name (lowercase) to the name a hook's CPU
    knows it by, if that differs from the Styx register enum's name.

    A hook can't use the Processor, so it reaches registers through the CPU
    it's handed, which takes a name and knows fewer registers. A register
    missing from this map can't be reached from a hook. ``None`` means every
    register goes by its enum's name.
    """

    def styx_register(self, name: str) -> typing.Any:
        """Translate a SmallWorld register name into a Styx register enum value."""
        key = name.lower()
        if key not in self._registers:
            raise exceptions.UnsupportedRegisterError(
                f"Styx machine def for {self.arch}:{self.byteorder} has no register '{name}'"
            )
        return self._registers[key]

    def hook_register(self, name: str) -> str:
        """Translate a SmallWorld register name into the name a hook's CPU uses."""
        enum = self.styx_register(name)
        if self.hook_registers is None:
            # The CPU names registers as the enum does, as a string.
            return str(enum).rsplit(".", 1)[-1]
        key = name.lower()
        if key not in self.hook_registers:
            raise exceptions.UnsupportedRegisterError(
                f"Styx hooks can't reach register '{name}' on "
                f"{self.arch}:{self.byteorder}"
            )
        return self.hook_registers[key]

    def _resolve_cpu_model(
        self, cpu_model: typing.Optional[str]
    ) -> typing.Tuple[typing.Any, typing.Any]:
        """Map an optional CPU model to its ``(Target, Backend)`` pair.

        ``None`` selects this machdef's default ``target``/``backend``. A
        non-``None`` ``cpu_model`` is looked up (case-insensitively) in
        :attr:`cpu_models`; an unknown model raises ``ConfigurationError``.
        """
        if cpu_model is None:
            return self.target, self.backend
        key = cpu_model.lower()
        if key not in self.cpu_models:
            available = ", ".join(sorted(self.cpu_models)) or "none"
            raise exceptions.ConfigurationError(
                f"Styx machine def for {self.arch}:{self.byteorder} has no CPU "
                f"model '{cpu_model}' (available: {available})"
            )
        return self.cpu_models[key]

    def styx_target(self, cpu_model: typing.Optional[str] = None) -> typing.Any:
        """Resolve the Styx ``Target`` to build for an optional CPU model."""
        return self._resolve_cpu_model(cpu_model)[0]

    def styx_backend(self, cpu_model: typing.Optional[str] = None) -> typing.Any:
        """Resolve the Styx ``Backend`` to use for an optional CPU model."""
        return self._resolve_cpu_model(cpu_model)[1]

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
                f"32-bit ARM (except ARMv7-R and ARMv8), 32-bit PowerPC (ppc, big-endian only - "
                f"Styx has no 64-bit PowerPC core) and SH-2A-FPU (big-endian only, "
                f"as that is the only SH-2A model Ghidra's sleigh provides) are the "
                f"supported families at this time. SH-4 (both endiannesses) is also "
                f"supported, but only against a Styx build carrying "
                f"nix/patches/styx-superh4-target.patch - see "
                f"machdefs/superh4.STYX_SUPPORTS_SUPERH4. Use GhidraEmulator or "
                f"PandaEmulator for other architectures (UnicornEmulator has no "
                f"SuperH support)."
            ) from e
