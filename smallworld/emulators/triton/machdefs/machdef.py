"""Architecture definitions for the Triton emulator backend.

Each concrete :class:`TritonMachineDef` subclass binds a SmallWorld
``Architecture`` + ``Byteorder`` to a Triton ``ARCH`` value and a register-name
map from SmallWorld's canonical register names onto Triton's register names.

Triton exposes registers by lowercase name (``ctx.getRegister("rax")``), which
match SmallWorld's canonical names in almost every case, so most entries in the
``_registers`` map are identities; the map exists to (a) give a precise,
per-architecture set of supported registers so unknown names raise
``UnsupportedRegisterError`` and (b) encode the handful of names that differ
(e.g. ARM32 ``lr`` is Triton ``r14``).
"""

from __future__ import annotations

import abc
import typing

from .... import exceptions, platforms, utils


class TritonMachineDef(metaclass=abc.ABCMeta):
    """Container for Triton architecture-specific definitions."""

    @property
    @abc.abstractmethod
    def arch(self) -> platforms.Architecture:
        raise NotImplementedError("Abstract triton machine def has no architecture")

    @property
    @abc.abstractmethod
    def byteorder(self) -> platforms.Byteorder:
        raise NotImplementedError("Abstract triton machine def has no byteorder")

    triton_arch_name: str = ""
    """Name of the Triton ``ARCH`` member this architecture maps to.

    Held as a *name* rather than the enum value so that importing the machdefs
    never touches Triton: the whole backend is optional, and a build missing one
    architecture (Triton's RISC-V support postdates its PyPI releases) must fail
    only when that architecture is requested.
    """

    @property
    def triton_arch(self) -> typing.Any:
        """The Triton ``ARCH`` enum value to configure a ``TritonContext`` with."""
        from triton import ARCH

        value = getattr(ARCH, self.triton_arch_name, None)
        if value is None:
            raise exceptions.ConfigurationError(
                f"The installed Triton build has no ARCH.{self.triton_arch_name}, "
                f"so it cannot emulate {self.arch}:{self.byteorder}. Rebuild "
                f"Triton with that architecture enabled (RISC-V, for instance, "
                f"needs a revision newer than 2024-07)."
            )
        return value

    _registers: typing.Dict[str, str] = {}
    """Map from SmallWorld register name (lowercase) to the Triton register name."""

    pc_register: str = "pc"
    """SmallWorld name of the program counter register for this architecture."""

    sp_register: str = "sp"
    """SmallWorld name of the stack pointer register for this architecture."""

    lr_register: typing.Optional[str] = None
    """SmallWorld name of the link register, where the ABI has one.

    ``None`` on the architectures that return through the stack (x86); the
    register's name (ARM/AArch64/RISC-V) otherwise.
    """

    is_thumb: bool = False
    """Whether the Triton context should start in Thumb mode (ARM Cortex-M)."""

    address_size: int = 8
    """Address/pointer size in bytes."""

    interrupt_mnemonics: typing.Set[str] = set()
    """Instruction mnemonics that raise an interrupt/syscall on this arch.

    Used by the emulator's run loop to dispatch interrupt hooks. Empty when the
    architecture has no relevant software-interrupt instruction.
    """

    halt_mnemonics: typing.Set[str] = set()
    """Instruction mnemonics that stop the machine on this arch.

    Triton implements no semantics for these and reports them as undefined
    instructions, so the run loop matches on the mnemonic and treats them as a
    clean stop rather than an execution fault.
    """

    syscall_mnemonics: typing.Set[str] = set()
    """Instruction mnemonics that request a system call on this architecture.

    A subset of ``interrupt_mnemonics``: on the architectures where the same
    instruction serves both purposes, the run loop offers it to the syscall
    hooks first and falls back to the interrupt hooks.
    """

    syscall_interrupt: typing.Optional[int] = None
    """Software-interrupt number that requests a system call, if any.

    Set on i386, where Linux syscalls arrive as ``int 0x80`` rather than a
    dedicated instruction. ``None`` everywhere else.
    """

    syscall_number_register: typing.Optional[str] = None
    """SmallWorld name of the register holding the system-call number.

    Follows the Linux ABI for each architecture (``rax``/``eax`` on x86,
    ``x8`` on AArch64, ``r7`` on ARM32 EABI, ``a7`` on RISC-V).
    """

    def triton_register(self, name: str) -> str:
        """Translate a SmallWorld register name into a Triton register name.

        The generic name ``"pc"`` is redirected to this architecture's concrete
        program-counter register first.
        """
        key = name.lower()
        if key == "pc":
            key = self.pc_register
        if key not in self._registers:
            raise exceptions.UnsupportedRegisterError(
                f"Triton machine def for {self.arch}:{self.byteorder} "
                f"has no register '{name}'"
            )
        return self._registers[key]

    def has_register(self, name: str) -> bool:
        key = name.lower()
        if key == "pc":
            key = self.pc_register
        return key in self._registers

    @classmethod
    def for_platform(cls, platform: platforms.Platform) -> "TritonMachineDef":
        """Find the ``TritonMachineDef`` subclass matching ``platform``.

        Raises ``ConfigurationError`` if Triton has no support for the requested
        architecture/byteorder, so callers get a clear message instead of an
        opaque register-mapping failure later on.
        """
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.arch == platform.architecture
                and x.byteorder == platform.byteorder,
            )
        except Exception as e:
            raise exceptions.ConfigurationError(
                f"Triton has no support for {platform.architecture}:{platform.byteorder}. "
                f"Supported families are x86 (32/64-bit), ARM (32-bit), AArch64, and "
                f"RISC-V 64-bit (all little-endian); use UnicornEmulator or "
                f"GhidraEmulator for other architectures."
            ) from e
