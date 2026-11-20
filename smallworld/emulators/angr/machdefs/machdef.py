import abc
import typing

import angr
import archinfo

from .... import exceptions, platforms, utils
from .pcode_float import FloatPcodeEngine
from .pcode_rewrite import find_pcode_relative_branch, lift_for_rewrite


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

    # Is this thumb?
    # Almost always no, but angr needs to ask.
    is_thumb: bool = False

    # The angr execution engine.
    # Setting this to "none" uses the default Vex engine.
    # This only needs to be overridden if you're a pcode machine.
    angr_engine: typing.Optional[typing.Type[angr.engines.SimEngine]] = None

    # Does angr support single-instruction stepping for this ISA.
    #
    # Instructions with delay slots cannot be lifted into VEX
    # without also lifting the instruction in the delay slot.
    #
    # This flag indicates that this machine uses such instructions,
    # and is not safe to step in this manner.
    supports_single_step: bool = True

    _registers: typing.Dict[str, str]

    def angr_reg(self, name: str) -> typing.Tuple[int, int]:
        """Find the offset and size of a register in the angr state's register file."""
        if name not in self._registers:
            raise KeyError(f"Unknown register for {self.arch}:{self.byteorder}: {name}")
        angr_name = self._registers[name]

        if angr_name not in self.angr_arch.registers:
            raise exceptions.UnsupportedRegisterError(
                f"Register {name} not recognized by angr for {self.arch}:{self.byteorder}"
            )
        return self.angr_arch.registers[angr_name]

    def pc_to_engine(self, state: typing.Optional[angr.SimState], pc: int) -> int:
        """Convert SmallWorld's pc to the value angr stores in its pc register.

        The pc as written is not always the address to run from: a microMIPS
        pc's low bit selects the encoding, not a byte. The default stores the
        value unchanged.

        Arguments:
            state: The emulator's angr state, or None before it has one
            pc: The address of the next instruction, with any ISA bit

        Returns:
            The value to store in the pc register
        """
        return pc

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        """Compute successor states for this architecture

        This allows a particular machine definition
        to compensate for cases where the default
        successor computation produces inaccurate results.

        For the overwhelming majority of machine models,
        the default should be sufficient.

        The biggest case to date is to handle
        user-defined operations (CALLOTHER) in pcode,
        which angr's p-code engine refuses to run.
        An op that ends the block, such as a syscall or a trap,
        is handled here by rewriting the lifted block;
        see the helpers in ``pcode_rewrite.py``.
        An op that only computes a value or does nothing
        is better handled by an ``angr_engine`` subclass
        that overrides ``_execute_callother``.

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

        return state.project.factory.successors(
            state, extra_stop_points=exit_points, **kwargs
        )

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


class PcodeEngine(FloatPcodeEngine):
    """angr's p-code engine, with floating-point operations, reading and
    writing parts of registers correctly.

    The floating-point operations come from :class:`FloatPcodeEngine`.
    angr resolves a register varnode by the name of the register it lies in,
    which loses where in that register the varnode starts. A varnode for the
    low half of a big-endian register (`mulu.w r4,r4` reads r4's bytes 2-3)
    was read from the start of the register, i.e. its high half. archinfo's
    ArchPcode lays out the register file at sleigh's own offsets, so the
    varnode's offset within its named register carries over unchanged, and
    the result is the varnode's own sleigh offset.
    """

    def _map_register_name(self, varnode) -> int:
        offset = super()._map_register_name(varnode)
        assert self.state.project is not None
        try:
            base = self.state.project.arch.get_register_offset(
                varnode.getRegisterName().lower()
            )
        except ValueError:
            # angr already mapped an unknown register to its scratch area.
            return offset
        return offset + (varnode.offset - base)


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

    # angr's own p-code engine, with floating-point operations and
    # partial-register varnodes fixed.
    angr_engine: typing.Optional[typing.Type[angr.engines.SimEngine]] = PcodeEngine

    # Refuse a block containing an instruction that branches within its own
    # p-code, which angr's p-code engine runs wrongly; see
    # `find_pcode_relative_branch`. Set by machine definitions whose
    # languages have such instructions.
    refuse_pcode_relative_branches: bool = False

    def __init__(self):
        self._angr_arch = archinfo.ArchPcode(self.pcode_language)

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        if self.refuse_pcode_relative_branches:
            kwargs["irsb"] = lift_for_rewrite(state, kwargs)
            address = find_pcode_relative_branch(kwargs["irsb"])
            if address is not None:
                raise exceptions.EmulationExecFailure(
                    "angr can't run this instruction: it branches within its "
                    "own p-code",
                    address,
                )
        return super().successors(state, **kwargs)
