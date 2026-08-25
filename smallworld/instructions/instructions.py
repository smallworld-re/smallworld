import abc
import logging
import typing

import capstone

from smallworld.platforms import Platform, PlatformDef

from .. import emulators, utils

logger = logging.getLogger(__name__)

# Which implementation backs Instruction.reads / .writes. Chosen per
# instruction via the `use_def_backend` constructor argument.
#
#   capstone (default) the Capstone-based implementation.
#   pcode    the Ghidra-pcode analysis, on platforms that define a
#            ghidra_language_id. pyghidra lives under the optional
#            'emu-ghidra' extra, so this raises downstream if pyghidra or
#            a Ghidra install is genuinely missing.
#
# The pcode analysis is opt-in for now; a later change makes it the
# default once every reads/writes consumer has been adapted.
USE_DEF_BACKEND_CAPSTONE = "capstone"
USE_DEF_BACKEND_PCODE = "pcode"
USE_DEF_BACKENDS = (USE_DEF_BACKEND_CAPSTONE, USE_DEF_BACKEND_PCODE)
DEFAULT_USE_DEF_BACKEND = USE_DEF_BACKEND_CAPSTONE


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
        use_def_backend: str = DEFAULT_USE_DEF_BACKEND,
    ):
        if use_def_backend not in USE_DEF_BACKENDS:
            raise ValueError(
                f"unknown use/def backend {use_def_backend!r}; "
                f"expected one of {', '.join(USE_DEF_BACKENDS)}"
            )
        #: Which implementation backs reads/writes for this instruction.
        self.use_def_backend = use_def_backend
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
    def from_capstone(
        cls,
        instruction: capstone.CsInsn,
        use_def_backend: str = DEFAULT_USE_DEF_BACKEND,
    ):
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
                use_def_backend=use_def_backend,
            )
        except ValueError:
            raise ValueError(
                f"No instruction format for {instruction._cs.arch}:{instruction._cs.mode}"
            )

    @classmethod
    def from_angr(
        cls,
        instruction,
        block,
        arch: str,
        use_def_backend: str = DEFAULT_USE_DEF_BACKEND,
    ):
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
                use_def_backend=use_def_backend,
            )
        except ValueError:
            raise ValueError(f"No instruction format for {arch}")

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        address: int,
        platform: Platform,
        use_def_backend: str = DEFAULT_USE_DEF_BACKEND,
    ):
        """Construct from a byte string."""
        try:
            return utils.find_subclass(
                cls,
                check=lambda x: x.platform == platform,
                instruction=raw,
                address=address,
                use_def_backend=use_def_backend,
            )
        except ValueError:
            raise ValueError(f"No instruction format for {platform}")

    @abc.abstractmethod
    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        pass

    def _pcode_use_def(self, kind: str) -> typing.Set[Operand]:
        """Registers and memory references read ('use') or written
        ('def') by this instruction, per the Ghidra-pcode analysis."""
        # Deferred imports: pcode_use_def pulls in pyghidra, and
        # pcode_naming imports this module (as bsid does).
        from .pcode_naming import canonicalize_operand, collapse_widened_defs
        from .pcode_use_def import UseDefError, analyze

        platdef = PlatformDef.for_platform(self.platform)
        try:
            result = analyze(self.instruction, platdef.ghidra_language_id, self.address)
        except UseDefError as e:
            # The analysis met something it cannot express -- an address
            # shape with no base/scale/index form, or an instruction Ghidra
            # has no semantics for. reads/writes is a property, and its
            # callers include Unicorn's fault handler (which is already
            # handling an emulation failure) and the colorizer's
            # per-instruction callbacks; the Capstone backend never raised
            # at them, so neither may this one. Same degradation as the
            # no-decode case below.
            logger.warning(
                f"pcode analysis failed for {self.instruction.hex()} on "
                f"{platdef.ghidra_language_id}: {e}; {kind} set is empty"
            )
            return set()
        if result is None:
            # Ghidra decoded no instruction from bytes Capstone accepted
            # (the two disassemblers can disagree on rare encodings).
            # Degrade to an empty set rather than raising IndexError into
            # the colorizer/trace analyses -- with a warning, since it
            # means this instruction's data flow is unknown, not absent.
            logger.warning(
                f"pcode analysis produced no instruction for "
                f"{self.instruction.hex()} on {platdef.ghidra_language_id}; "
                f"{kind} set is empty"
            )
            return set()
        operands: typing.Set[Operand] = set()
        for op in result.uses if kind == "use" else result.defs:
            canon = canonicalize_operand(op, platdef)
            if canon is not None:
                operands.add(canon)
        if (
            kind == "use"
            and self._instruction.mnemonic in platdef.implicit_dereference_mnemonics
        ):
            # This ISA dereferences a register operand implicitly (MIPS
            # jr/jalr transfer control through a register). Both facts
            # are true -- the register is read to form the address, and
            # the location at that address is accessed -- so report
            # both. The Capstone-based path replaced the register with
            # the memory reference and lost the register read.
            #
            # Reads only, deliberately: for jalr, writes name the link
            # register, and dereferencing those would fabricate memory
            # writes at 'ra' and 'pc'.
            from .bsid import BSIDMemoryReferenceOperand

            operands |= {
                BSIDMemoryReferenceOperand(base=op.name, size=platdef.address_size)
                for op in operands
                if isinstance(op, RegisterOperand)
            }
        if kind == "def":
            operands = collapse_widened_defs(operands, platdef)
        return operands

    def _use_pcode(self) -> bool:
        """Whether reads/writes should use the Ghidra-pcode analysis
        rather than the Capstone implementation, per this instruction's
        `use_def_backend` (see the module comment)."""
        if self.use_def_backend != USE_DEF_BACKEND_PCODE:
            return False
        platdef = PlatformDef.for_platform(self.platform)
        if platdef.ghidra_language_id is None:
            # No Ghidra language for this platform, so there is no pcode
            # implementation to use; fall back rather than fail.
            logger.warning(
                f"pcode use/def requested but {self.platform} defines no "
                f"ghidra_language_id; using Capstone"
            )
            return False
        return True

    def _capstone_use_def(self, kind: str) -> typing.Set[Operand]:
        """Capstone-based use ('use') / def ('def') set.

        The fallback used when the pcode backend is unavailable or
        disabled. Architectures whose _memory_reference does not take a
        single Capstone operand (x86) override this.
        """
        # Resolved lazily, and only for "use": PlatformDef.for_platform walks
        # every PlatformDef subclass with no cache, which costs 10-100x the
        # rest of this method. Hoisting it here made the DEFAULT (Capstone)
        # writes path pay for something only the reads path reads -- measured
        # at 17x on MIPS32 and ~48x on PowerPC32 per .writes access, on a
        # property the colorizer and Unicorn hit once per instruction. It
        # also turned "no PlatformDef for this platform" from working into
        # a ValueError on the writes path.
        implicit_deref: typing.Set[str] = set()
        if kind == "use":
            implicit_deref = PlatformDef.for_platform(
                self.platform
            ).implicit_dereference_mnemonics
        access = capstone.CS_AC_READ if kind == "use" else capstone.CS_AC_WRITE
        operands: typing.Set[Operand] = set()
        for operand in self._instruction.operands:
            if operand.type == capstone.CS_OP_MEM and (
                not hasattr(operand, "access") or operand.access & access
            ):
                # Memory operand; handling is architecture-specific.
                operands.add(self._memory_reference(operand))
            elif operand.type == capstone.CS_OP_REG and (
                not hasattr(operand, "access") or operand.access & access
            ):
                if self._instruction.mnemonic in implicit_deref:
                    # A register the instruction dereferences implicitly;
                    # treat as a memory reference.
                    operands.add(self._memory_reference(operand))
                else:
                    operands.add(
                        RegisterOperand(self._instruction.reg_name(operand.reg))
                    )
        return operands

    @property
    def reads(self) -> typing.Set[Operand]:
        """Registers and memory references read by this instruction.

        A set of Operand objects: RegisterOperand for registers and
        MemoryReferenceOperand for memory (in the form
        `base + scale * index + offset`).
        """
        if self._use_pcode():
            return self._pcode_use_def("use")
        return self._capstone_use_def("use")

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """
        if self._use_pcode():
            return self._pcode_use_def("def")
        return self._capstone_use_def("def")

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
