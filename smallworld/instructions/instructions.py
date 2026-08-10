import abc
import logging
import typing

import capstone

from smallworld.platforms import Platform, PlatformDef

from .. import emulators, utils

logger = logging.getLogger(__name__)


class Operand(metaclass=abc.ABCMeta):
    """An operand from an instruction."""

    @abc.abstractmethod
    def key(self, emulator: emulators.Emulator):
        """Provide a unique key for this reference.

        Arguments:
            emulator: An emulator from which to fetch a value.

        Returns:
            A key value used to reference this operand.
        """

        pass

    @abc.abstractmethod
    def concretize(
        self, emulator: emulators.Emulator
    ) -> typing.Optional[typing.Union[int, bytes]]:
        """Compute a concrete value for this operand, using an emulator.

        Arguments:
            emulator: An emulator from which to fetch a value.

        Returns:
            The concrete value of this operand.
        """

        pass


class RegisterOperand(Operand):
    """An operand from an instruction that is simply a register."""

    def __init__(self, name: str):
        self.name = name

    def key(self, emulator: emulators.Emulator):
        return self.name

    def __eq__(self, other) -> bool:
        return hash(self) == hash(other)

    def __hash__(self) -> int:
        return hash(self.__repr__())

    def concretize(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register(self.name)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"


class MemoryReferenceOperand(Operand):
    """An operand from an instruction which reads or writes memory."""

    def __init__(self, size: int = 4):
        self.size = size

    @abc.abstractmethod
    def address(self, emulator: emulators.Emulator) -> int:
        """Compute a concrete value for this operand.

        Arguments:
            emulator: An emulator from which to fetch a value.

        Returns:
            The concrete value of this operand.
        """

    def key(self, emulator: emulators.Emulator) -> int:
        return self.address(emulator)

    def __eq__(self, other):
        return self.__repr__() == other.__repr__()

    def __hash__(self):
        return hash(self.__repr__())

    def concretize(self, emulator: emulators.Emulator) -> typing.Optional[bytes]:
        return emulator.read_memory(self.address(emulator), self.size)


class Instruction(metaclass=abc.ABCMeta):
    """An instruction storage and semantic metadata class."""

    def __init__(
        self,
        instruction: bytes,
        address: int,
        _instruction: typing.Optional[capstone.CsInsn] = None,
    ):
        self.instruction = instruction
        self.address = address

        if _instruction is None:
            md = capstone.Cs(self.cs_arch, self.cs_mode)
            md.detail = True

            _instruction = md.disasm(instruction, address).__next__()

        self._instruction = _instruction
        self.disasm = f"{self._instruction.address:x} {self._instruction.mnemonic} {self._instruction.op_str}"

    @property
    @abc.abstractmethod
    def angr_arch(self) -> str:
        """angr architecture ID"""
        return ""

    @property
    @abc.abstractmethod
    def cs_arch(self) -> int:
        """Capstone architecture ID"""
        return 0

    @property
    @abc.abstractmethod
    def cs_mode(self) -> int:
        """Capstone mode ID"""
        return 0

    @property
    @abc.abstractmethod
    def platform(self) -> Platform:
        """Platform"""
        raise NotImplementedError()

    @classmethod
    def from_capstone(cls, instruction: capstone.CsInsn):
        """Construct from an existing Capstone instruction.

        Arguments:
            instruction: An existing Capstone instruction.
        """
        try:
            return utils.find_subclass(
                cls,
                check=lambda x: x.cs_arch == instruction._cs.arch
                and x.cs_mode == instruction._cs.mode,
                instruction=instruction.bytes,
                address=instruction.address,
                _instruction=instruction,
            )
        except ValueError:
            raise ValueError(
                f"No instruction format for {instruction._cs.arch}:{instruction._cs.mode}"
            )

    @classmethod
    def from_angr(cls, instruction, block, arch: str):
        """Construct from an angr disassembler instruction.

        Arguments:
            instruction: An existing angr disassembler instruction
            arch: angr architecture string
        """
        # angr's instructions don't include raw bytes.
        off = instruction.address - block.addr
        raw = block.bytes[off : off + instruction.size]
        try:
            return utils.find_subclass(
                cls,
                check=lambda x: x.angr_arch == arch,
                instruction=raw,
                address=instruction.address,
            )
        except ValueError:
            raise ValueError(f"No instruction format for {arch}")

    @classmethod
    def from_bytes(cls, raw: bytes, address: int, platform: Platform):
        """Construct from a byte string."""
        try:
            return utils.find_subclass(
                cls,
                check=lambda x: x.platform == platform,
                instruction=raw,
                address=address,
            )
        except ValueError:
            raise ValueError(f"No instruction format for {platform}")

    @abc.abstractmethod
    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        pass

    def _register_dereference(self, operand) -> MemoryReferenceOperand:
        """Build a memory reference for an implicitly-dereferenced register operand.

        Some instructions use a register operand's *value* directly as an
        address rather than as data (e.g., MIPS ``jr``, where ``$ra`` holds the
        jump target).  Unlike a normal memory operand, Capstone reports this as
        a bare register, so we synthesize the reference ``[reg]`` -- the
        register's contents with no offset -- sized to the platform's address
        width.
        """
        from .bsid import BSIDMemoryReferenceOperand

        platdef = PlatformDef.for_platform(self.platform)
        return BSIDMemoryReferenceOperand(
            base=self._instruction.reg_name(operand.reg),
            offset=0,
            size=platdef.address_size,
        )

    def _immediate_fetch(self, address: int) -> MemoryReferenceOperand:
        """Build a memory reference for a direct branch's constant target.

        For a branch to a label, Capstone resolves the immediate operand to an
        absolute target address; we wrap it as a base-less reference whose
        address is that constant, sized to the platform's address width.
        """
        from .bsid import BSIDMemoryReferenceOperand

        platdef = PlatformDef.for_platform(self.platform)
        return BSIDMemoryReferenceOperand(
            offset=address,
            size=platdef.address_size,
        )

    @property
    def reads(self) -> typing.Set[Operand]:
        """Registers and memory references read by this instruction.

        This is a list of string register names and dictionary memory reference
        specifications (i.e., in the form `base + scale * index + offset`).
        """

        platdef = PlatformDef.for_platform(self.platform)
        read: typing.Set[Operand] = set()

        for operand in self._instruction.operands:
            if operand.type == capstone.CS_OP_MEM and (
                not hasattr(operand, "access") or operand.access & capstone.CS_AC_READ
            ):
                # This is a memory operand.
                # Handling is architecture-specific
                read.add(self._memory_reference(operand))
            elif operand.type == capstone.CS_OP_REG and (
                not hasattr(operand, "access") or operand.access & capstone.CS_AC_READ
            ):
                if self._instruction.mnemonic in platdef.implicit_read_mnemonics:
                    # This is a register operand whose value is implicitly
                    # dereferenced as an address to read data from.
                    # Handle as a memory operand.
                    read.add(self._register_dereference(operand))
                else:
                    # This is a register reference that's used for its value.
                    read.add(RegisterOperand(self._instruction.reg_name(operand.reg)))

        return read

    @property
    def fetches(self) -> typing.Set[Operand]:
        """Memory references fetched (executed) by this instruction.

        These are the control-flow targets an instruction transfers to: the
        addresses the CPU will fetch instructions from.  Targets come in two
        forms:

        * **Direct** -- a branch/call to a label, whose (absolute) target
          Capstone exposes as an immediate operand (e.g., ``b 0x1000``).
        * **Register-indirect** -- a branch whose target is the *value* of a
          register operand, listed in the platform's
          :attr:`~PlatformDef.implicit_fetch_mnemonics` (e.g., MIPS ``jr $ra``).

        Both are returned as :class:`MemoryReferenceOperand` objects describing
        the fetched address, mirroring how :attr:`reads` and :attr:`writes`
        describe data addresses.

        Not covered: memory-indirect / load-to-PC fetches such as ARM
        ``ldr pc, [..]`` or ``pop {pc}`` (the target is the *contents* of
        memory, a second dereference), and instructions whose target register
        is implicit and thus absent from the operand list (e.g., a bare
        AArch64 ``ret``, which uses ``x30``).
        """

        platdef = PlatformDef.for_platform(self.platform)
        fetch: typing.Set[Operand] = set()

        mnemonic = self._instruction.mnemonic
        # Capstone's generic JUMP/CALL groups identify most control transfers
        # across architectures; the mnemonic-set fallback catches the few it
        # omits (notably MIPS `jal`, which carries only an arch-specific group).
        is_control_transfer = (
            self._instruction.group(capstone.CS_GRP_JUMP)
            or self._instruction.group(capstone.CS_GRP_CALL)
            or mnemonic in platdef.conditional_branch_mnemonics
            or mnemonic in platdef.delay_slot_mnemonics
            or mnemonic in platdef.implicit_fetch_mnemonics
        )
        if not is_control_transfer:
            return fetch

        for operand in self._instruction.operands:
            if operand.type == capstone.CS_OP_IMM:
                # Direct branch: the immediate is the absolute target address.
                fetch.add(self._immediate_fetch(operand.imm))
            elif (
                operand.type == capstone.CS_OP_REG
                and mnemonic in platdef.implicit_fetch_mnemonics
            ):
                # Register-indirect branch: the register value is the target.
                # (Register operands of other branches -- e.g., the compared
                # registers of `beq` -- are data reads, handled by `reads`.)
                fetch.add(self._register_dereference(operand))

        return fetch

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """

        write: typing.Set[Operand] = set()

        for operand in self._instruction.operands:
            if operand.type == capstone.CS_OP_MEM and (
                not hasattr(operand, "access") or operand.access & capstone.CS_AC_WRITE
            ):
                write.add(self._memory_reference(operand))
            elif operand.type == capstone.CS_OP_REG and (
                not hasattr(operand, "access") or operand.access & capstone.CS_AC_WRITE
            ):
                write.add(RegisterOperand(self._instruction.reg_name(operand.reg)))

        return write

    # def to_json(self) -> dict:
    #     return {
    #         "instruction": base64.b64encode(self.instruction).decode(),
    #         "disasm": self.disasm,
    #         "address": self.address,
    #         "arch": self.arch,
    #         "mode": self.mode,
    #     }

    # @classmethod
    # def from_json(cls, dict):
    #     if "instruction" not in dict:
    #         raise ValueError(f"malformed {cls.__name__}: {dict!r}")

    #     dict["instruction"] = base64.b64decode(dict["instruction"])

    #     return cls(**dict)

    def __repr__(self) -> str:
        string = f"{self._instruction.mnemonic} {self._instruction.op_str}".strip()

        return f"{self.__class__.__name__}(0x{self.address:x}: {string})"
