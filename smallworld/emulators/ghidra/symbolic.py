"""Z3-backed symbolic emulator wrapping Ghidra's SymbolicSummaryZ3 extension.

This module is loaded lazily (only after ``symz3_loader.ensure_loaded()`` has
started the JVM and added the SymbolicSummaryZ3 jars to the classpath), so
top-level imports of Ghidra Java packages are safe here.
"""

from __future__ import annotations

import logging
import typing

import claripy
import jpype
import z3
from com.microsoft.z3 import Context as Z3Context  # type: ignore[import-not-found]
from ghidra.pcode.emu.symz3.state import SymZ3PcodeEmulator  # type: ignore[import-not-found]
from ghidra.pcode.exec import PcodeExecutorStatePiece  # type: ignore[import-not-found]
from ghidra.program.model.pcode import Varnode  # type: ignore[import-not-found]
from ghidra.symz3.model import SymValueZ3  # type: ignore[import-not-found]
from java.lang import String as JString  # type: ignore[import-not-found]
from org.apache.commons.lang3.tuple import Pair as JPair  # type: ignore[import-not-found]

from ... import exceptions, platforms, utils
from ..emulator import Emulator
from . import z3bridge
from .machdefs import GhidraMachineDef
from .typing import AbstractGhidraSymbolicEmulator

log = logging.getLogger(__name__)

# Concrete memory writes are chunked into pieces small enough that the matching
# symbolic-side bitvector fits comfortably in a Z3 numeral. Using a String
# overload of ``Context.mkBV`` (rather than long) avoids signed-64 overflow,
# but tighter chunks also reduce the size of individual Z3 expressions.
_WRITE_CHUNK_BYTES = 8


class GhidraSymbolicEmulator(AbstractGhidraSymbolicEmulator):
    """Z3-backed symbolic emulator using Ghidra's SymZ3PcodeEmulator.

    Linear, single-path execution: the concrete byte side of the paired state
    drives every branch and the symbolic side accumulates path preconditions
    (recorded by Ghidra as SMT-LIB-serialized Z3 boolean expressions). Multi-
    state branching is not supported — ``enable_branching()`` raises.
    """

    name = "pcode-symbolic-emulator"
    description = (
        "Emulator based on pyghidra and Ghidra's SymbolicSummaryZ3 extension"
    )
    version = "0.0.1"

    bytes_py_to_java = jpype.JByte[:]

    @staticmethod
    def bytes_java_to_py(val) -> bytes:
        return bytes(((b.numerator if b.numerator >= 0 else 256 + b.numerator) for b in val))

    def __init__(self, platform: platforms.Platform):
        super().__init__(platform)
        self.platform: platforms.Platform = platform
        self.platdef: platforms.PlatformDef = platforms.PlatformDef.for_platform(platform)
        self.machdef: GhidraMachineDef = GhidraMachineDef.for_platform(platform)

        self._jctx: Z3Context = Z3Context()
        self._emu = SymZ3PcodeEmulator(self.machdef.language)
        # Context configuration isn't auto-propagated to the thread.
        self._thread.overrideContextWithDefault()

        self._memory_map = utils.RangeCollection()

        # Maps a label name (passed to write_register_label /
        # write_memory_label) to the claripy BVS we minted for it. Used by
        # read_register_content to distinguish "genuinely user-symbolic"
        # values (raise SymbolicValueError) from SymZ3-internal fresh BVS
        # placeholders for uninitialized state (treat as concrete zero).
        self._symbolic_inputs: typing.Dict[str, claripy.ast.bv.BV] = {}

        # User-supplied constraints (claripy boolean expressions).
        self._user_constraints: typing.List[claripy.ast.bool.Bool] = []

        # Cached lift of Ghidra's path preconditions once run() finishes.
        self._cached_preconditions: typing.Optional[
            typing.List[claripy.ast.bool.Bool]
        ] = None

        # Hook tables (same shape as concrete GhidraEmulator).
        self._instructions_hook: typing.Optional[
            typing.Callable[[Emulator], None]
        ] = None
        self._instruction_hooks: typing.Dict[
            int, typing.Callable[[Emulator], None]
        ] = {}
        self._function_hooks: typing.Dict[
            int, typing.Callable[[Emulator], None]
        ] = {}

        # Memory hooks: concrete and symbolic variants are kept separate; an
        # access fires both if both are registered.
        self._mem_reads_hook: typing.Optional[
            typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]]
        ] = None
        self._mem_read_hooks: typing.Dict[
            typing.Tuple[int, int],
            typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
        ] = {}
        self._mem_reads_symbolic_hook: typing.Optional[
            typing.Callable[
                [Emulator, int, int, claripy.ast.bv.BV],
                typing.Optional[claripy.ast.bv.BV],
            ]
        ] = None
        self._mem_read_symbolic_hooks: typing.Dict[
            typing.Tuple[int, int],
            typing.Callable[
                [Emulator, int, int, claripy.ast.bv.BV],
                typing.Optional[claripy.ast.bv.BV],
            ],
        ] = {}

        self._mem_writes_hook: typing.Optional[
            typing.Callable[[Emulator, int, int, bytes], None]
        ] = None
        self._mem_write_hooks: typing.Dict[
            typing.Tuple[int, int],
            typing.Callable[[Emulator, int, int, bytes], None],
        ] = {}
        self._mem_writes_symbolic_hook: typing.Optional[
            typing.Callable[[Emulator, int, int, claripy.ast.bv.BV], None]
        ] = None
        self._mem_write_symbolic_hooks: typing.Dict[
            typing.Tuple[int, int],
            typing.Callable[[Emulator, int, int, claripy.ast.bv.BV], None],
        ] = {}

    # ------------------------------------------------------------------
    # JVM-side helpers
    # ------------------------------------------------------------------

    @property
    def _thread(self):
        return self._emu.getThread("main", True)

    def _addr_bytes(self, address: int) -> typing.Any:
        size = self.platdef.address_size
        if self.platform.byteorder is platforms.Byteorder.LITTLE:
            return self.bytes_py_to_java(address.to_bytes(size, "little"))
        return self.bytes_py_to_java(address.to_bytes(size, "big"))

    def _addr_pair(self, address: int) -> typing.Any:
        """Build a Pair<byte[], SymValueZ3> for an address offset.

        The paired (independent) state used by SymZ3 indexes both the
        concrete-byte side and the symbolic side via the same Pair-typed
        offset, so we materialize a concrete-only address as a pair where the
        symbolic side is a numeric SymValueZ3 of the same bitwidth.
        """
        size_bits = self.platdef.address_size * 8
        addr_bytes = self._addr_bytes(address)
        addr_sym = self._make_sym_value(address, size_bits)
        return JPair.of(addr_bytes, addr_sym)

    def _int_from_bytes(self, raw: typing.Any) -> int:
        if self.platform.byteorder is platforms.Byteorder.LITTLE:
            return int.from_bytes(raw, "little")
        return int.from_bytes(raw, "big")

    def _make_sym_value(
        self, value: typing.Union[int, claripy.ast.bv.BV], size_bits: int
    ) -> typing.Any:
        if isinstance(value, claripy.ast.bv.BV):
            jbv = z3bridge.claripy_to_java_bv(self._jctx, value)
        elif isinstance(value, int):
            # Java Z3's mkBV(long, int) is signed-64; route the value through
            # the (String, int) overload so any bitwidth (including unsigned
            # 64-bit) works uniformly.
            jbv = self._jctx.mkBV(JString(str(value & ((1 << size_bits) - 1))), size_bits)
        else:
            raise TypeError(f"Cannot convert {type(value).__name__} to SymValueZ3")
        return SymValueZ3(self._jctx, jbv)

    # ------------------------------------------------------------------
    # Register I/O
    # ------------------------------------------------------------------

    def _expected_register_size(self, name: str) -> int:
        """Return the size (in bytes) smallworld's platdef expects for ``name``."""
        reg_def = self.platdef.registers.get(name)
        if reg_def is None:
            return self.machdef.pcode_reg(name).getMinimumByteSize()
        size = getattr(reg_def, "size", None)
        if size is None:
            return self.machdef.pcode_reg(name).getMinimumByteSize()
        return int(size)

    def _references_symbolic_input(self, bv: claripy.ast.bv.BV) -> bool:
        """True if ``bv`` references any of the user's labeled symbolic inputs."""
        if not bv.symbolic:
            return False
        names = set(bv.variables)
        return any(label in names for label in self._symbolic_inputs)

    def read_register_content(self, name: str) -> int:
        if name == "pc":
            name = self.platdef.pc_register
        reg = self.machdef.pcode_reg(name)
        state = self._thread.getState()
        pair = state.getVar(reg, PcodeExecutorStatePiece.Reason.INSPECT)
        concrete = pair.getLeft()
        sym = pair.getRight()
        if sym is not None:
            big_int = sym.toBigInteger()
            if big_int is None:
                # Non-numeral symbolic side. Distinguish a genuinely user-
                # supplied symbolic value (raise; the caller should switch to
                # read_register_symbolic) from SymZ3's default fresh BVS for
                # an uninitialized register (treat as zero, matching the
                # concrete GhidraEmulator).
                if self._references_symbolic_input(self._sym_to_claripy(sym)):
                    raise exceptions.SymbolicValueError(
                        f"Register {name} contains a symbolic value"
                    )
        return self._int_from_bytes(concrete)

    def read_register_symbolic(self, name: str) -> claripy.ast.bv.BV:
        if name == "pc":
            name = self.platdef.pc_register
        reg = self.machdef.pcode_reg(name)
        state = self._thread.getState()
        pair = state.getVar(reg, PcodeExecutorStatePiece.Reason.INSPECT)
        sym = pair.getRight()
        ghidra_bits = reg.getMinimumByteSize() * 8
        expected_bits = self._expected_register_size(name) * 8
        if sym is None:
            bv = claripy.BVV(self._int_from_bytes(pair.getLeft()), ghidra_bits)
        else:
            bv = self._sym_to_claripy(sym)
        if bv.size() < expected_bits:
            bv = claripy.ZeroExt(expected_bits - bv.size(), bv)
        elif bv.size() > expected_bits:
            bv = bv[expected_bits - 1 : 0]
        return bv

    def write_register_content(
        self,
        name: str,
        value: typing.Union[None, int, claripy.ast.bv.BV],
    ) -> None:
        if value is None:
            return
        if name == "pc":
            name = self.platdef.pc_register
        reg = self.machdef.pcode_reg(name)
        size_bytes = reg.getMinimumByteSize()
        size_bits = size_bytes * 8

        if isinstance(value, int):
            concrete = value
            sym_value = self._make_sym_value(value, size_bits)
        elif isinstance(value, claripy.ast.bv.BV):
            if value.symbolic:
                concrete = 0
            else:
                concrete = value.concrete_value
            sym_value = self._make_sym_value(value, size_bits)
        else:
            raise TypeError(
                f"write_register_content does not accept {type(value).__name__}"
            )

        # Mask to handle negative ints via two's-complement wraparound.
        concrete_unsigned = concrete & ((1 << size_bits) - 1)
        if self.platform.byteorder is platforms.Byteorder.LITTLE:
            concrete_bytes = concrete_unsigned.to_bytes(size_bytes, "little")
        else:
            concrete_bytes = concrete_unsigned.to_bytes(size_bytes, "big")

        state = self._thread.getState()
        pair = JPair.of(self.bytes_py_to_java(concrete_bytes), sym_value)
        state.setVar(reg, pair)

    def write_register_label(
        self, name: str, label: typing.Optional[str] = None
    ) -> None:
        if label is None:
            return
        if name == "pc":
            name = self.platdef.pc_register
        reg = self.machdef.pcode_reg(name)
        size_bits = reg.getMinimumByteSize() * 8
        bv = claripy.BVS(label, size_bits, explicit_name=True)
        self._symbolic_inputs[label] = bv
        self.write_register_content(name, bv)

    # ------------------------------------------------------------------
    # Memory I/O
    # ------------------------------------------------------------------

    def _read_memory_pair(self, address: int, size: int):
        """Return the raw ``Pair<byte[], SymValueZ3>`` for memory at ``address``."""
        return self._emu.getSharedState().getVar(
            self.machdef.language.getDefaultSpace(),
            self._addr_pair(address),
            size,
            False,
            PcodeExecutorStatePiece.Reason.INSPECT,
        )

    def read_memory_content(self, address: int, size: int) -> bytes:
        pair = self._read_memory_pair(address, size)
        sym = pair.getRight()
        if sym is not None and sym.toBigInteger() is None:
            bv = self._sym_to_claripy(sym)
            if bv.symbolic:
                raise exceptions.SymbolicValueError(
                    f"Memory at {hex(address)} (size {size}) is symbolic"
                )
        return self.bytes_java_to_py(pair.getLeft())

    def read_memory_symbolic(self, address: int, size: int) -> claripy.ast.bv.BV:
        pair = self._read_memory_pair(address, size)
        sym = pair.getRight()
        if sym is not None:
            return self._sym_to_claripy(sym)
        return claripy.BVV(self.bytes_java_to_py(pair.getLeft()))

    def _sym_to_claripy(self, sym) -> claripy.ast.bv.BV:
        """Lift a Java ``SymValueZ3`` into a claripy bitvector via SMT-LIB."""
        smt = str(SymValueZ3.serialize(self._jctx, sym.getBitVecExpr(self._jctx)))
        return z3bridge.smt2_to_claripy_bv(smt)

    def map_memory(self, address: int, size: int) -> None:
        self._memory_map.add_range((address, address + size))

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        return list(self._memory_map.ranges)

    def write_memory_content(
        self,
        address: int,
        content: typing.Union[bytes, claripy.ast.bv.BV],
    ) -> None:
        if isinstance(content, claripy.ast.bv.BV):
            size_bits = len(content)
            if size_bits % 8 != 0:
                raise ValueError(
                    f"Symbolic memory write of {size_bits} bits is not a whole-byte size"
                )
            size = size_bits // 8
            if content.symbolic:
                concrete_bytes = bytes(size)
            else:
                concrete_bytes = int(content.concrete_value).to_bytes(size, "big")
            sym_value = self._make_sym_value(content, size_bits)
            self._setvar_memory(address, size, concrete_bytes, sym_value)
        else:
            self._write_concrete_bytes(address, bytes(content))

    def _write_concrete_bytes(self, address: int, content: bytes) -> None:
        """Chunk a concrete-bytes write so the symbolic-side bitvector stays
        small. See ``_WRITE_CHUNK_BYTES`` for the rationale."""
        for offset in range(0, len(content), _WRITE_CHUNK_BYTES):
            piece = content[offset : offset + _WRITE_CHUNK_BYTES]
            size = len(piece)
            value = int.from_bytes(piece, "big")
            sym_value = self._make_sym_value(value, size * 8)
            self._setvar_memory(address + offset, size, piece, sym_value)

    def _setvar_memory(
        self,
        address: int,
        size: int,
        concrete_bytes: bytes,
        sym_value: typing.Any,
    ) -> None:
        shared = self._emu.getSharedState()
        pair = JPair.of(self.bytes_py_to_java(concrete_bytes), sym_value)
        shared.setVar(
            self.machdef.language.getDefaultSpace(),
            self._addr_pair(address),
            size,
            False,
            pair,
        )

    def write_memory_label(
        self,
        address: int,
        size: int,
        label: typing.Optional[str] = None,
    ) -> None:
        if label is None:
            return
        bv = claripy.BVS(label, size * 8, explicit_name=True)
        self._symbolic_inputs[label] = bv
        self.write_memory_content(address, bv)

    # ------------------------------------------------------------------
    # Stepping / running (per-pcode-op pattern from concrete GhidraEmulator)
    # ------------------------------------------------------------------

    def step_instruction(self) -> None:
        if not self.machdef.supports_single_step:
            raise exceptions.ConfigurationError(
                f"SymZ3PcodeEmulator does not support single-instruction stepping "
                f"for {self.platform}"
            )

        pc = self.read_register_content(self.platdef.pc_register)
        log.debug("Stepping at %#x", pc)
        if not self._memory_map.contains_value(pc):
            raise exceptions.EmulationFetchUnmappedFailure(
                "Fetched unmapped memory", pc, address=pc
            )

        pc_addr = self.machdef.language.getDefaultSpace().getAddress(pc)
        self._thread.overrideCounter(pc_addr)

        if self._instructions_hook is not None:
            self._instructions_hook(self)
        if pc in self._instruction_hooks:
            self._instruction_hooks[pc](self)

        if pc in self._function_hooks:
            self._function_hooks[pc](self)
        else:
            self._step_pcode_ops()

        # Cache invalidation: anything we ran may have changed preconditions.
        self._cached_preconditions = None

        pc_after = self.read_register_content(self.platdef.pc_register)
        if pc_after in self._exit_points:
            raise exceptions.EmulationExitpoint()
        if not self._bounds.is_empty() and not self._bounds.contains_value(pc_after):
            raise exceptions.EmulationBounds()

    def _step_pcode_ops(self) -> None:
        """Per-pcode-op step loop with LOAD/STORE/COPY interception for hooks."""
        skip = False
        default_space = self.machdef.language.getDefaultSpace()
        default_space_id = default_space.getSpaceID()
        while True:
            if skip:
                skip = False
                self._thread.skipPcodeOp()
            else:
                self._thread.stepPcodeOp()

            frame = self._thread.getFrame()
            if frame is None:
                break
            if frame.isFinished():
                self._thread.finishInstruction()
                break

            code = frame.getCode()
            op = code[frame.index()]
            opcode = op.getOpcode()

            if opcode == op.STORE:
                _, addr_var, data_var = op.getInputs()
                self._process_write_breakpoint(addr_var, data_var)
            elif opcode == op.LOAD:
                space_var, addr_var = op.getInputs()
                out_var = op.getOutput()
                if space_var.getAddress().getOffset() == default_space_id:
                    self._process_read_breakpoint(addr_var, out_var)
                    skip = True
            elif opcode == op.COPY:
                in_var = op.getInputs()[0]
                out_var = op.getOutput()
                in_space = in_var.getAddress().getAddressSpace()
                out_space = out_var.getAddress().getAddressSpace()
                if in_space == default_space and out_space == default_space:
                    raise NotImplementedError(
                        f"RAM-to-RAM copy from {in_var} to {out_var}"
                    )
                if in_space == default_space:
                    self._process_read_breakpoint(in_var, out_var, direct=True)
                    skip = True
                elif out_space == default_space:
                    self._process_write_breakpoint(out_var, in_var, direct=True)
                    skip = True

    def step_block(self) -> None:
        raise NotImplementedError("Block stepping not supported for symbolic emulator")

    def run(self) -> None:
        try:
            while True:
                self.step_instruction()
        except exceptions.EmulationStop:
            pass

    # ------------------------------------------------------------------
    # Memory hook plumbing
    # ------------------------------------------------------------------

    def _resolve_address(self, addr_var: Varnode, direct: bool) -> int:
        if direct:
            return int(addr_var.getAddress().getOffset())
        state = self._thread.getState()
        addr_pair = state.getVar(addr_var, PcodeExecutorStatePiece.Reason.INSPECT)
        return self._int_from_bytes(addr_pair.getLeft())

    def _process_read_breakpoint(
        self,
        addr_var: Varnode,
        out_var: Varnode,
        direct: bool = False,
    ) -> None:
        addr = self._resolve_address(addr_var, direct)
        if not self._memory_map.contains_value(addr):
            raise exceptions.EmulationReadUnmappedFailure(
                "Read of unmapped data",
                self.read_register("pc"),
                address=addr,
            )

        state = self._thread.getState()
        addr_space = self.machdef.language.getDefaultSpace()
        addr_addr = addr_space.getAddress(addr)
        size = out_var.getSize()
        data_var = Varnode(addr_addr, size)
        pair = state.getVar(data_var, PcodeExecutorStatePiece.Reason.INSPECT)
        concrete = self.bytes_java_to_py(pair.getLeft())
        sym = pair.getRight()
        end_addr = addr + size

        # Concrete read hooks
        new_concrete = concrete
        if self._mem_reads_hook is not None:
            replacement = self._mem_reads_hook(self, addr, size, new_concrete)
            if replacement is not None:
                new_concrete = replacement
        for (start, end), hook in self._mem_read_hooks.items():
            if not _overlap(start, end, addr, end_addr):
                continue
            replacement = hook(self, addr, size, new_concrete)
            if replacement is not None:
                new_concrete = replacement

        # Symbolic read hooks
        new_sym = self._sym_to_claripy(sym) if sym is not None else claripy.BVV(new_concrete)
        if self._mem_reads_symbolic_hook is not None:
            replacement = self._mem_reads_symbolic_hook(self, addr, size, new_sym)
            if replacement is not None:
                new_sym = replacement
        for (start, end), hook in self._mem_read_symbolic_hooks.items():
            if not _overlap(start, end, addr, end_addr):
                continue
            replacement = hook(self, addr, size, new_sym)
            if replacement is not None:
                new_sym = replacement

        sym_value = self._make_sym_value(new_sym, size * 8)
        state.setVar(out_var, JPair.of(self.bytes_py_to_java(bytes(new_concrete)), sym_value))

    def _process_write_breakpoint(
        self,
        addr_var: Varnode,
        data_var: Varnode,
        direct: bool = False,
    ) -> None:
        addr = self._resolve_address(addr_var, direct)
        if not self._memory_map.contains_value(addr):
            raise exceptions.EmulationWriteUnmappedFailure(
                "Write of unmapped data",
                self.read_register("pc"),
                address=addr,
            )

        state = self._thread.getState()
        pair = state.getVar(data_var, PcodeExecutorStatePiece.Reason.INSPECT)
        concrete = self.bytes_java_to_py(pair.getLeft())
        size = len(concrete)
        end_addr = addr + size

        if self._mem_writes_hook is not None:
            self._mem_writes_hook(self, addr, size, concrete)
        for (start, end), hook in self._mem_write_hooks.items():
            if _overlap(start, end, addr, end_addr):
                hook(self, addr, size, concrete)

        sym = pair.getRight()
        sym_claripy = self._sym_to_claripy(sym) if sym is not None else claripy.BVV(concrete)
        if self._mem_writes_symbolic_hook is not None:
            self._mem_writes_symbolic_hook(self, addr, size, sym_claripy)
        for (start, end), hook in self._mem_write_symbolic_hooks.items():
            if _overlap(start, end, addr, end_addr):
                hook(self, addr, size, sym_claripy)

    # ------------------------------------------------------------------
    # Hook registration (InstructionHookable / FunctionHookable / Memory*)
    # ------------------------------------------------------------------

    def hook_instruction(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        self._instruction_hooks[address] = function

    def unhook_instruction(self, address: int) -> None:
        self._instruction_hooks.pop(address, None)

    def hook_instructions(self, function: typing.Callable[[Emulator], None]) -> None:
        self._instructions_hook = function

    def unhook_instructions(self) -> None:
        self._instructions_hook = None

    def hook_function(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        self._function_hooks[address] = function

    def unhook_function(self, address: int) -> None:
        self._function_hooks.pop(address, None)

    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[
            [Emulator, int, int, bytes], typing.Optional[bytes]
        ],
    ) -> None:
        self._mem_read_hooks[(start, end)] = function

    def unhook_memory_read(self, start: int, end: int) -> None:
        self._mem_read_hooks.pop((start, end), None)

    def hook_memory_reads(
        self,
        function: typing.Callable[
            [Emulator, int, int, bytes], typing.Optional[bytes]
        ],
    ) -> None:
        self._mem_reads_hook = function

    def unhook_memory_reads(self) -> None:
        self._mem_reads_hook = None

    def hook_memory_read_symbolic(
        self,
        start: int,
        end: int,
        function: typing.Callable[
            [Emulator, int, int, claripy.ast.bv.BV],
            typing.Optional[claripy.ast.bv.BV],
        ],
    ) -> None:
        self._mem_read_symbolic_hooks[(start, end)] = function

    def hook_memory_reads_symbolic(
        self,
        function: typing.Callable[
            [Emulator, int, int, claripy.ast.bv.BV],
            typing.Optional[claripy.ast.bv.BV],
        ],
    ) -> None:
        self._mem_reads_symbolic_hook = function

    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes], None],
    ) -> None:
        self._mem_write_hooks[(start, end)] = function

    def unhook_memory_write(self, start: int, end: int) -> None:
        self._mem_write_hooks.pop((start, end), None)

    def hook_memory_writes(
        self,
        function: typing.Callable[[Emulator, int, int, bytes], None],
    ) -> None:
        self._mem_writes_hook = function

    def unhook_memory_writes(self) -> None:
        self._mem_writes_hook = None

    def hook_memory_write_symbolic(
        self,
        start: int,
        end: int,
        function: typing.Callable[
            [Emulator, int, int, claripy.ast.bv.BV], None
        ],
    ) -> None:
        self._mem_write_symbolic_hooks[(start, end)] = function

    def hook_memory_writes_symbolic(
        self,
        function: typing.Callable[
            [Emulator, int, int, claripy.ast.bv.BV], None
        ],
    ) -> None:
        self._mem_writes_symbolic_hook = function

    # ------------------------------------------------------------------
    # ConstrainedEmulator
    # ------------------------------------------------------------------

    def add_constraint(self, expr: claripy.ast.bool.Bool) -> None:
        self._user_constraints.append(expr)

    def get_constraints(self) -> typing.List[claripy.ast.bool.Bool]:
        # Mirror angr's behavior: surface both user-added constraints and the
        # path preconditions accumulated by the symbolic engine, so a
        # ``Machine.get_constraints()`` after ``machine.emulate(emulator)``
        # exposes the path conditions.
        return list(self._user_constraints) + list(self._path_preconditions())

    def _path_preconditions(self) -> typing.List[claripy.ast.bool.Bool]:
        if self._cached_preconditions is not None:
            return self._cached_preconditions
        result: typing.List[claripy.ast.bool.Bool] = []
        # SymZ3 thread accumulates preconditions; lift each SMT-LIB serialization.
        try:
            preconds = list(self._thread.getPreconditions())
        except Exception as exc:  # noqa: BLE001
            log.debug("getPreconditions failed (%s); assuming empty.", exc)
            preconds = []
        # Also collect shared-state preconditions if any.
        try:
            shared_preconds = list(
                self._emu.getSharedState().getRight().getPreconditions()
            )
            preconds.extend(shared_preconds)
        except Exception:  # noqa: BLE001
            pass
        for smt in preconds:
            try:
                result.append(z3bridge.smt2_to_claripy_bool(str(smt)))
            except Exception as exc:  # noqa: BLE001
                log.warning("Failed to lift precondition %r: %s", smt, exc)
        self._cached_preconditions = result
        return result

    def _solver(self, extras: typing.Sequence[claripy.ast.bool.Bool] = ()) -> z3.Solver:
        """Build a z3 Solver loaded with user constraints + path preconditions."""
        backend = claripy.backends.z3
        solver = z3.Solver()
        for expr in self._user_constraints:
            solver.add(backend.convert(expr))
        for expr in self._path_preconditions():
            solver.add(backend.convert(expr))
        for expr in extras:
            solver.add(backend.convert(expr))
        return solver

    def satisfiable(
        self,
        extra_constraints: typing.List[claripy.ast.bool.Bool] = [],
    ) -> bool:
        return self._solver(extra_constraints).check() == z3.sat

    def eval_atmost(
        self, expr: claripy.ast.bv.BV, most: int
    ) -> typing.List[int]:
        solver = self._solver()
        z3_expr = claripy.backends.z3.convert(expr)
        results: typing.List[int] = []
        for _ in range(most + 1):
            if solver.check() != z3.sat:
                break
            val = solver.model().evaluate(z3_expr, model_completion=True)
            results.append(val.as_long())
            solver.add(z3_expr != val)
        if not results:
            raise exceptions.UnsatError(
                "No satisfying assignment for expression given constraints"
            )
        if len(results) > most:
            raise exceptions.SymbolicValueError(
                f"More than {most} solutions for expression"
            )
        return results

    def eval_atleast(
        self, expr: claripy.ast.bv.BV, least: int
    ) -> typing.List[int]:
        solver = self._solver()
        z3_expr = claripy.backends.z3.convert(expr)
        results: typing.List[int] = []
        for _ in range(least):
            if solver.check() != z3.sat:
                raise exceptions.SymbolicValueError(
                    f"Fewer than {least} solutions for expression"
                )
            val = solver.model().evaluate(z3_expr, model_completion=True)
            results.append(val.as_long())
            solver.add(z3_expr != val)
        return results

    # ------------------------------------------------------------------
    # SymbolicEmulator
    # ------------------------------------------------------------------

    def enable_branching(self) -> None:
        raise NotImplementedError(
            "GhidraSymbolicEmulator only supports linear execution; "
            "multi-state branching is not implemented."
        )

    def get_active_states(self) -> typing.Generator[Emulator, None, None]:
        """Yield the single linear state (which is ``self``).

        The :class:`SymbolicEmulator` contract permits multiple frontier
        states; we only ever have one because branching is disabled.
        """
        yield self

    def get_deadended_states(self) -> typing.Generator[Emulator, None, None]:
        """No-op for the linear emulator — the active state covers inspection."""
        return iter(())

    # ------------------------------------------------------------------
    # __repr__
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"GhidraSymbolicEmulator(platform={self.platform!r}, "
            f"constraints={len(self._user_constraints)})"
        )


def _overlap(start: int, end: int, lo: int, hi: int) -> bool:
    """True if the half-open ranges [start, end) and [lo, hi) overlap."""
    return start < hi and lo < end
