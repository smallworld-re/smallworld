import abc
import typing

import angr
import archinfo
import claripy

from .... import exceptions, platforms, utils


class AngrMachineDef:
    """Container class for angr architecture-specific definitions"""

    @property
    @abc.abstractmethod
    def arch(self) -> platforms.Architecture:
        """The architecture ID"""
        raise NotImplementedError("This is an abstract method.")

    @property
    @abc.abstractmethod
    def byteorder(self) -> platforms.Byteorder:
        """The byte order"""
        raise NotImplementedError("This is an abstract method.")

    @property
    @abc.abstractmethod
    def angr_arch(self) -> archinfo.arch.Arch:
        """The angr architecture to use"""
        raise NotImplementedError("This is an abstract method.")

    # Is this Thumb-only (M-profile)?
    # Almost always no, but angr needs to ask.
    is_thumb: bool = False

    # Is bit 0 of pc the Thumb bit, as on every 32-bit ARM?
    # angr addresses Thumb code with it set.
    thumb_bit_in_pc: bool = False

    # Does this machine build a cpsr angr has no register for?
    # See read_cpsr() and write_cpsr().
    has_cpsr: bool = False

    # The angr execution engine.
    # Setting this to "none" uses the default Vex engine.
    # This only needs to be overridden if you're a pcode machine, or a VEX
    # machine whose lifting needs fixing up (see be8.py and v8m.py).
    angr_engine: typing.Optional[typing.Type[angr.engines.SimEngine]] = None

    # Does angr support single-instruction stepping for this ISA.
    #
    # Instructions with delay slots cannot be lifted into VEX
    # without also lifting the instruction in the delay slot.
    #
    # This flag indicates that this machine uses such instructions,
    # and is not safe to step in this manner.
    supports_single_step: bool = True

    #: SmallWorld register name -> angr register name, or (angr register
    #: name, size) for a register angr lacks that starts at that one and spans
    #: `size` bytes (e.g. an ARM NEON q register over two d registers).
    _registers: typing.Dict[str, typing.Union[str, typing.Tuple[str, int]]]

    def angr_reg(self, name: str) -> typing.Tuple[int, int]:
        """Find the offset and size of a register in the angr state's register file."""
        if name not in self._registers:
            raise KeyError(f"Unknown register for {self.arch}:{self.byteorder}: {name}")
        angr_name = self._registers[name]
        size = None
        if isinstance(angr_name, tuple):
            angr_name, size = angr_name

        if angr_name not in self.angr_arch.registers:
            raise exceptions.UnsupportedRegisterError(
                f"Register {name} not recognized by angr for {self.arch}:{self.byteorder}"
            )
        offset, angr_size = self.angr_arch.registers[angr_name]
        return offset, angr_size if size is None else size

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        """Compute successor states for this architecture

        This allows a particular machine definition
        to compensate for cases where the default
        successor computation produces inaccurate results.

        For the overwhelming majority of machine models,
        the default should be sufficient.

        The biggest case to date is to handle
        user-defined operations in pcode.
        These are treated as illegal ops by angr,
        and there is currently no way to intercept their processing.

        Arguments:
            state: The angr state for which to compute successors
            kwargs: See AngrObjectFactory.successors()

        Returns:
            The successor states of `state`.
        """
        if state.project is None:
            raise exceptions.ConfigurationError("Angr state had no project.")

        assert hasattr(state.scratch, "exit_points")

        # Inject exit points here.
        if "extra_stop_points" in kwargs:
            exit_points = state.scratch.exit_points | set(kwargs["extra_stop_points"])
            del kwargs["extra_stop_points"]
        else:
            exit_points = state.scratch.exit_points

        if self.thumb_bit_in_pc:
            # angr addresses Thumb code with the Thumb bit set.
            exit_points = exit_points | {p | 1 for p in exit_points}

        return state.project.factory.successors(
            state, extra_stop_points=exit_points, **kwargs
        )

    def read_cpsr(self, state: angr.SimState) -> claripy.ast.bv.BV:
        """Build cpsr from angr's state"""
        raise exceptions.UnsupportedRegisterError(f"No cpsr for {self.arch}")

    def write_cpsr(self, state: angr.SimState, value: claripy.ast.bv.BV) -> None:
        """Write cpsr's bits to where angr's state keeps them"""
        raise exceptions.UnsupportedRegisterError(f"No cpsr for {self.arch}")

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        """Find the appropriate MachineDef for your architecture

        Arguments:
            arch: The architecture ID you want
            byteorder: The byteorderness you want

        Returns:
            An instance of the appropriate MachineDef

        Raises:
            ValueError: If no MachineDef subclass matches your request
        """
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.arch == platform.architecture
                and x.byteorder == platform.byteorder,
            )
        except ValueError as e:
            # find_subclass raises ValueError when nothing matches; narrow to
            # that so an unexpected error (e.g. a subclass missing arch/byteorder)
            # surfaces with its real traceback instead of being masked as
            # "no machine model".
            raise ValueError(f"No machine model for {platform}") from e


class GhidraMachineDef(AngrMachineDef):
    """Container class for pcode-dependent angr architecture-specific definitions"""

    @property
    @abc.abstractmethod
    def pcode_language(self) -> str:
        """The pcode language ID string"""
        return ""

    @property
    def angr_arch(self) -> archinfo.arch.Arch:
        return self._angr_arch

    angr_engine: typing.Optional[typing.Type[angr.engines.SimEngine]] = (
        angr.engines.UberEnginePcode
    )

    def __init__(self):
        self._angr_arch = archinfo.ArchPcode(self.pcode_language)
