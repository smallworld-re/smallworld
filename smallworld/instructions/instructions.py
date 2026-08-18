import abc
import logging
import re
import typing

import capstone

from smallworld.platforms import Architecture, Platform, PlatformDef

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


# --------------------------------------------------------------------------- #
# Mapping Ghidra register names into SmallWorld's register namespace
# --------------------------------------------------------------------------- #
#
# The pcode-based use/def analysis (pcode_use_def) reports operands using
# Ghidra's register naming, which mostly matches SmallWorld's platform
# definitions but differs in a few places (flag bits vs. a flags register,
# vector-lane pseudo-registers, hi/lo accumulator naming). Consumers
# concretize operands against emulators via PlatformDef names, so every
# reported register must exist there; names with no platform equivalent
# even after aliasing (e.g. AArch64 condition flags today) are dropped.

_X86_FLAG_BITS = frozenset(
    ("cf", "pf", "af", "zf", "sf", "of", "df", "tf", "if", "ac", "id")
)
# Ghidra models SSE/AVX lanes as pseudo-registers: xmm0_qa, xmm0_da, ...
_X86_VECTOR_LANE_RE = re.compile(r"([xyz]mm\d+)_\w+")
_AARCH64_FLAG_BITS = frozenset(("ng", "zr", "cy", "ov", "nzcv"))
_AARCH64_ZREG_RE = re.compile(r"z(\d+)")


def _pcode_register_alias(name: str, platform: Platform) -> str:
    arch = platform.architecture
    if arch == Architecture.X86_64:
        if name in _X86_FLAG_BITS:
            return "rflags"
        m = _X86_VECTOR_LANE_RE.fullmatch(name)
        if m:
            return m.group(1)
    elif arch == Architecture.X86_32:
        if name in _X86_FLAG_BITS:
            return "eflags"
        m = _X86_VECTOR_LANE_RE.fullmatch(name)
        if m:
            return m.group(1)
    elif arch == Architecture.AARCH64:
        # no PlatformDef register models the flags today; alias to nzcv
        # so they all drop as one name (and start flowing through the
        # moment the platform definition gains it)
        if name in _AARCH64_FLAG_BITS:
            return "nzcv"
        # zN is Ghidra's full vector register; qN is the widest lane
        # SmallWorld models
        m = _AARCH64_ZREG_RE.fullmatch(name)
        if m:
            return f"q{m.group(1)}"
    elif arch == Architecture.POWERPC32:
        if name.startswith("xer_"):
            return "xer"
        if name.startswith("fp_"):
            return "fpscr"
    elif arch == Architecture.MIPS32:
        if name == "hi":
            return "hi0"
        if name == "lo":
            return "lo0"
    return name


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

    def _canonicalize_pcode_operand(
        self, operand: Operand, platdef
    ) -> typing.Optional[Operand]:
        """Map one operand from the pcode analysis into this platform's
        register namespace so consumers can concretize it against an
        emulator. Returns None for operands naming state the platform
        definition doesn't model."""
        if isinstance(operand, RegisterOperand):
            name = _pcode_register_alias(operand.name, self.platform)
            if name not in platdef.registers:
                logger.debug(
                    f"dropping pcode operand {operand.name!r}: "
                    f"no such register on {self.platform}"
                )
                return None
            if name != operand.name:
                return RegisterOperand(name)
        return operand

    @staticmethod
    def _collapse_widened_defs(
        operands: typing.Set[Operand], platdef
    ) -> typing.Set[Operand]:
        """Drop a register def that is redundant given a def of one of
        its own sub-registers.

        Ghidra models a 32-bit x86-64 write as zero-extending, so
        `mov ecx, eax` reports defs of both ECX and RCX. Both are
        true, but consumers key on the architectural destination, so
        keep the narrower name the instruction actually names and drop
        the widened parent.

        Applied to defs only: for a def the parent is the strictly
        larger effect and is safe to summarize by its part, whereas
        dropping a parent *read* would understate what was consumed.
        """
        names = {op.name for op in operands if isinstance(op, RegisterOperand)}
        redundant = set()
        for name in names:
            parent = getattr(platdef.registers.get(name), "parent", None)
            if parent is not None and parent in names:
                redundant.add(parent)
        if not redundant:
            return operands
        return {
            op
            for op in operands
            if not (isinstance(op, RegisterOperand) and op.name in redundant)
        }

    def _pcode_use_def(self, kind: str) -> typing.Set[Operand]:
        """Registers and memory references read ('use') or written
        ('def') by this instruction, per the Ghidra-pcode analysis."""
        # Deferred import: pcode_use_def pulls in pyghidra.
        from .pcode_use_def import analyze

        platdef = PlatformDef.for_platform(self.platform)
        results = analyze(self.instruction, platdef.ghidra_language_id, self.address)
        if not results:
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
        for op in results[0][kind]:
            canon = self._canonicalize_pcode_operand(op, platdef)
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
            operands = self._collapse_widened_defs(operands, platdef)
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
        platdef = PlatformDef.for_platform(self.platform)
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
                if (
                    kind == "use"
                    and self._instruction.mnemonic
                    in platdef.implicit_dereference_mnemonics
                ):
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
