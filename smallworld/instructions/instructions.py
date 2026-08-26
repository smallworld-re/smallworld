import abc
import functools
import importlib.util
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
# The pcode analysis is the default; Capstone remains available per
# instruction for callers that need it (and is what platforms without a
# ghidra_language_id, or without pyghidra installed, fall back to).
USE_DEF_BACKEND_CAPSTONE = "capstone"
USE_DEF_BACKEND_PCODE = "pcode"
USE_DEF_BACKENDS = (USE_DEF_BACKEND_CAPSTONE, USE_DEF_BACKEND_PCODE)
DEFAULT_USE_DEF_BACKEND = USE_DEF_BACKEND_PCODE


@functools.lru_cache(maxsize=1)
def _pyghidra_available() -> bool:
    """Whether the optional pyghidra extra is installed. A spec probe, not
    an import: importing pyghidra pulls in jpype, and this runs on the
    first reads/writes access of instructions that may never need it."""
    return importlib.util.find_spec("pyghidra") is not None


_logged_fallbacks: typing.Set[str] = set()


def _log_fallback_once(reason: str) -> None:
    """Warn about a pcode->Capstone fallback once per distinct reason.

    reads/writes are properties hit once per instruction by the colorizer
    and Unicorn; with pcode as the default, a per-access warning for a
    permanent condition (no pyghidra, a Thumb platform) is pure noise.
    """
    if reason not in _logged_fallbacks:
        _logged_fallbacks.add(reason)
        logger.warning(reason)


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

    # Size is part of identity but deliberately not of __repr__, whose
    # spelling the colorizer truth files and trace harness depend on.
    # Comparing reprs alone made a 1-byte and an 8-byte access to one
    # address equal, so a set kept whichever arrived first and concretize()
    # then read the wrong width.
    def __eq__(self, other):
        if not isinstance(other, MemoryReferenceOperand):
            return NotImplemented
        return (repr(self), self.size) == (repr(other), other.size)

    def __hash__(self):
        return hash((repr(self), self.size))

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

    #: Whether the Ghidra-pcode backend can analyze this instruction format.
    #: False where the platform's SLEIGH language needs a non-default
    #: context register the analysis does not set (ARMV6MThumbInstruction).
    #: Such a platform still has a ghidra_language_id for its emulator.
    supports_pcode_use_def: bool = True

    @abc.abstractmethod
    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        pass

    def _memory_reference_operand(self, operand) -> MemoryReferenceOperand:
        """Memory operand built from a single Capstone operand.

        Same thing as `_memory_reference` for every architecture but x86,
        whose `_memory_reference` takes six separate components instead and
        which therefore overrides both. This exists so callers holding one
        Capstone operand -- analyses/trace_execution.py's get_cmp_info -- can
        name one method rather than the x86-only one, which raised
        AttributeError on any other platform the moment a compare took a
        memory operand.
        """
        return self._memory_reference(operand)

    def _pcode_result(self, purpose: str, platdef: PlatformDef):
        """Run the p-code analysis for this instruction and validate the
        answer, or None with a warning when there is no trustworthy one.

        `purpose` names what the caller wanted ("use", "def", "fetch") in
        the warnings. Every degrade returns None rather than raising:
        callers are properties and methods reached from Unicorn's fault
        handler and the colorizer's per-instruction callbacks, and the
        Capstone backend never raised at them. The catch is broader than
        UseDefError on purpose -- a missing optional pyghidra, a JPype
        exception and an out-of-range address are none of them UseDefError,
        and all used to escape.
        """
        from .pcode_use_def import analyze

        language_id = platdef.ghidra_language_id
        if language_id is None:
            # Only reachable when a caller bypasses _pcode_platdef, which
            # screens the None out.
            logger.warning(
                f"{self.platform} defines no ghidra_language_id; "
                f"{purpose} set is empty"
            )
            return None
        try:
            # Truncated to what Capstone decoded: analyze wants trailing
            # bytes to be padding, not the real successor. Ghidra folds a
            # delay slot into the branch's own p-code, and the length check
            # below cannot see it -- the reported length is still the
            # branch's.
            raw = self.instruction[: self._instruction.size]
            result = analyze(raw, language_id, self.address)
        except Exception as e:
            logger.warning(
                f"pcode analysis failed for {self.instruction.hex()} on "
                f"{language_id}: {e!r}; {purpose} set is empty"
            )
            return None
        if result is None:
            # Ghidra decoded no instruction from bytes Capstone accepted
            # (the two disassemblers can disagree on rare encodings).
            logger.warning(
                f"pcode analysis produced no instruction for "
                f"{self.instruction.hex()} on {language_id}; "
                f"{purpose} set is empty"
            )
            return None
        if result.size != self._instruction.size:
            # Different lengths means they did not decode the same
            # instruction, so these operands describe the wrong one. Thumb
            # is the reachable case -- its language id is the ARM-mode one,
            # so Thumb bytes decode as a valid, unrelated ARM instruction.
            logger.warning(
                f"pcode decoded {result.size} bytes ({result.disassembly}) "
                f"where Capstone decoded {self._instruction.size} for "
                f"{self.instruction.hex()} on {language_id}; "
                f"{purpose} set is empty"
            )
            return None
        return result

    def _pcode_use_def(
        self, kind: str, platdef: typing.Optional[PlatformDef] = None
    ) -> typing.Set[Operand]:
        """Registers and memory references read ('use') or written
        ('def') by this instruction, per the Ghidra-pcode analysis.

        `platdef` is the already-resolved platform definition, which
        `_use_pcode` had to look up anyway. PlatformDef.for_platform walks
        every subclass uncached AND constructs the definition (measured at
        15 us on x86-64 and 280 us on PowerPC32), so resolving it here as
        well made every .reads/.writes pay for two -- four per instruction
        across both properties -- on the path the colorizer and Unicorn hit
        once per instruction. That is the cost the Capstone path goes out of
        its way to avoid; see _capstone_use_def.
        """
        # Deferred import: pcode_naming imports this module (as bsid does).
        from .pcode_naming import canonicalize_operand, collapse_widened_defs

        if platdef is None:
            platdef = PlatformDef.for_platform(self.platform)
        result = self._pcode_result(kind, platdef)
        if result is None:
            return set()
        operands: typing.Set[Operand] = set()
        for op in result.uses if kind == "use" else result.defs:
            canon = canonicalize_operand(op, platdef)
            if canon is not None:
                operands.add(canon)
        if kind == "def":
            operands = collapse_widened_defs(operands, platdef)
        return operands

    def _pcode_platdef(self) -> typing.Optional[PlatformDef]:
        """The platform definition to run the Ghidra-pcode analysis against,
        or None if reads/writes should use the Capstone implementation
        instead (per this instruction's `use_def_backend`; see the module
        comment).

        Returns the resolved definition rather than a bool so the caller does
        not have to resolve it a second time -- see _pcode_use_def.
        """
        if self.use_def_backend != USE_DEF_BACKEND_PCODE:
            return None
        if not self.supports_pcode_use_def:
            _log_fallback_once(
                f"{type(self).__name__} cannot use the pcode backend "
                f"(see supports_pcode_use_def); using Capstone"
            )
            return None
        if not _pyghidra_available():
            # pyghidra lives behind the optional 'emu-ghidra' extra. With
            # pcode as the default backend, a base install must quietly get
            # the Capstone implementation, not a warning and an empty set
            # per property access.
            _log_fallback_once(
                "pyghidra is not installed; using the Capstone use/def "
                "backend (install the 'emu-ghidra' extra for the pcode one)"
            )
            return None
        platdef = PlatformDef.for_platform(self.platform)
        if platdef.ghidra_language_id is None:
            # No Ghidra language for this platform, so there is no pcode
            # implementation to use; fall back rather than fail.
            _log_fallback_once(
                f"{self.platform} defines no ghidra_language_id; " f"using Capstone"
            )
            return None
        return platdef

    def _use_pcode(self) -> bool:
        """Whether reads/writes use the Ghidra-pcode analysis."""
        return self._pcode_platdef() is not None

    def _capstone_use_def(self, kind: str) -> typing.Set[Operand]:
        """Capstone-based use ('use') / def ('def') set.

        The fallback used when the pcode backend is unavailable or
        disabled. Architectures whose _memory_reference does not take a
        single Capstone operand (x86) override this.
        """
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
                # Registers an indirect branch dereferences (MIPS jr's t9)
                # are reported as the register they are: the location the
                # transfer will FETCH from is fetches()'s answer, not a
                # data read. This path used to substitute the memory
                # reference for the register, losing the register read.
                operands.add(RegisterOperand(self._instruction.reg_name(operand.reg)))
        return operands

    @property
    def reads(self) -> typing.Set[Operand]:
        """Registers and memory references read by this instruction.

        A set of Operand objects: RegisterOperand for registers and
        MemoryReferenceOperand for memory (in the form
        `base + scale * index + offset`).
        """
        platdef = self._pcode_platdef()
        if platdef is not None:
            return self._pcode_use_def("use", platdef)
        return self._capstone_use_def("use")

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """
        platdef = self._pcode_platdef()
        if platdef is not None:
            return self._pcode_use_def("def", platdef)
        return self._capstone_use_def("def")

    def fetches(self) -> typing.Set[Operand]:
        """Memory locations control transfer will FETCH from: the
        dereference of an indirect branch target's value -- `jr $t9`
        fetches at [t9], `jmp rax` at [rax].

        Not reads. `jr $t9` reads t9 (that is in `reads`) but reads no
        data memory at [t9]; the *next instruction fetch* does. Keeping
        the two apart matters to fault attribution: a triage consumer
        seeing an unmapped [t9] here knows execution was about to leave
        the map, not that the instruction loaded from it. Genuine data
        dereferences are unaffected and stay in `reads` -- `jmp qword ptr
        [0x1234]` really does load its pointer from memory, and that load
        stays a read; what this method would name is where the *value*
        of that pointer sends the fetch, which is not statically
        expressible, so such an instruction reports no fetch operand.
        Empty for anything that is not an indirect transfer, and for
        indirect transfers whose target is not a single register's value
        (`ret`'s target comes off the stack -- the pop is already a read).

        The p-code backend identifies indirect transfers structurally
        (BRANCHIND/CALLIND/RETURN), so this works on every platform with
        a Ghidra language; the Capstone fallback knows only the
        instructions listed in the platform's
        implicit_dereference_mnemonics.
        """
        from .bsid import BSIDMemoryReferenceOperand

        platdef = self._pcode_platdef()
        if platdef is not None:
            from .pcode_naming import canonicalize_register

            result = self._pcode_result("fetch", platdef)
            if result is None:
                return set()
            return {
                BSIDMemoryReferenceOperand(base=name, size=platdef.address_size)
                for name in (
                    canonicalize_register(t, platdef) for t in result.indirect_targets
                )
                if name is not None
            }
        platdef = PlatformDef.for_platform(self.platform)
        if self._instruction.mnemonic not in platdef.implicit_dereference_mnemonics:
            return set()
        return {
            BSIDMemoryReferenceOperand(
                base=self._instruction.reg_name(operand.value.reg),
                size=platdef.address_size,
            )
            for operand in self._instruction.operands
            if operand.type == capstone.CS_OP_REG
            and (not hasattr(operand, "access") or operand.access & capstone.CS_AC_READ)
        }

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
