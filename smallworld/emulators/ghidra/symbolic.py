"""Z3-backed symbolic emulator wrapping Ghidra's SymbolicSummaryZ3 extension.

This module is loaded lazily (only after ``symz3_loader.ensure_loaded()`` has
started the JVM and added the SymbolicSummaryZ3 jars to the classpath), so
top-level imports of Ghidra Java packages are safe here.
"""

from __future__ import annotations

import logging
import re
import typing

import claripy
import jpype
from com.microsoft.z3 import Context as Z3Context  # type: ignore[import-not-found]
from ghidra.pcode.emu.symz3.state import (
    SymZ3PcodeEmulator,  # type: ignore[import-not-found]
)
from ghidra.pcode.exec import PcodeExecutorStatePiece  # type: ignore[import-not-found]
from ghidra.program.model.pcode import Varnode  # type: ignore[import-not-found]
from ghidra.symz3.model import SymValueZ3  # type: ignore[import-not-found]
from java.lang import String as JString  # type: ignore[import-not-found]
from org.apache.commons.lang3.tuple import (
    Pair as JPair,  # type: ignore[import-not-found]
)

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

    Linear execution by default: the concrete byte side of the paired state
    drives every branch and the symbolic side accumulates path preconditions
    (recorded by Ghidra as SMT-LIB-serialized Z3 boolean expressions).

    When ``_step_pcode_ops`` encounters a CBRANCH whose condition depends on
    a user-labeled symbolic input and both directions are satisfiable under
    the current constraints, execution halts at the divergence and the two
    directional predicates are recorded in ``_fork_constraints``.
    ``get_active_states`` then yields ``self`` once per direction (binding
    ``_active_fork_constraint`` between yields), so
    ``Machine.symbolic_emulate`` extracts two Machines whose
    ``get_constraints()`` differ only by the branch-direction predicate.
    This matches ``AngrEmulator``'s default linear-mode behavior of stopping
    at the first divergence and surfacing both successor states.

    Continuing past the first divergence (multi-step branching) is not
    supported — ``enable_branching()`` raises.
    """

    name = "pcode-symbolic-emulator"
    description = "Emulator based on pyghidra and Ghidra's SymbolicSummaryZ3 extension"
    version = "0.0.1"

    bytes_py_to_java = jpype.JByte[:]

    @staticmethod
    def bytes_java_to_py(val) -> bytes:
        return bytes(
            ((b.numerator if b.numerator >= 0 else 256 + b.numerator) for b in val)
        )

    def __init__(
        self,
        platform: platforms.Platform,
        taint: bool = False,
        taint_addresses: bool = False,
    ):
        super().__init__(platform)
        # Dynamic taint tracking. Labels already become named symbolic
        # variables (tracked in self._symbolic_inputs); when enabled, taint is
        # surfaced by intersecting a value's symbolic variables with those
        # source labels.
        self._taint = taint
        self._taint_addresses = taint_addresses
        self.platform: platforms.Platform = platform
        self.platdef: platforms.PlatformDef = platforms.PlatformDef.for_platform(
            platform
        )
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
        self._user_input_pattern_cache: typing.Optional[
            typing.Tuple[int, typing.Optional["re.Pattern[str]"]]
        ] = None

        # Half-open ``[start, end)`` ranges that have been labelled by a
        # ``write_memory_label`` call. Used as a fast filter in
        # ``read_memory_content`` so it can skip building SymZ3's per-byte
        # ``Concat`` for ranges that we know contain no user-symbolic data.
        self._labeled_memory_ranges: typing.List[typing.Tuple[int, int]] = []

        # Half-open ``[start, end)`` ranges that received a user-symbolic
        # value via a STORE during execution (Ghidra writes the symbolic
        # side natively, and those addresses are not in
        # ``_labeled_memory_ranges``). Included in ``read_memory_content``'s
        # fast filter so a later read of such an address still materializes
        # the symbolic side and raises ``SymbolicValueError`` rather than
        # silently returning the concrete byte side.
        self._symbolic_store_ranges: typing.List[typing.Tuple[int, int]] = []

        # User-supplied constraints (claripy boolean expressions).
        self._user_constraints: typing.List[claripy.ast.bool.Bool] = []

        # Cached lift of Ghidra's path preconditions once run() finishes.
        self._cached_preconditions: typing.Optional[
            typing.List[claripy.ast.bool.Bool]
        ] = None

        # When _step_pcode_ops intercepts a CBRANCH whose condition is
        # user-symbolic and both directions are SAT, it stores the two
        # directional predicates here ([taken, not_taken]) and raises
        # EmulationStop. get_active_states then yields self once per entry,
        # binding _active_fork_constraint so get_constraints appends the
        # right predicate for each Machine extraction.
        self._fork_constraints: typing.Optional[typing.List[claripy.ast.bool.Bool]] = (
            None
        )
        self._active_fork_constraint: typing.Optional[claripy.ast.bool.Bool] = None

        # Hook tables (same shape as concrete GhidraEmulator).
        self._instructions_hook: typing.Optional[typing.Callable[[Emulator], None]] = (
            None
        )
        self._instruction_hooks: typing.Dict[int, typing.Callable[[Emulator], None]] = (
            {}
        )
        self._function_hooks: typing.Dict[int, typing.Callable[[Emulator], None]] = {}

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
        return self.bytes_py_to_java(
            address.to_bytes(self.platdef.address_size, self._byteorder_str())
        )

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

    def _byteorder_str(self) -> typing.Literal["little", "big"]:
        return (
            "little" if self.platform.byteorder is platforms.Byteorder.LITTLE else "big"
        )

    def _int_from_bytes(self, raw: typing.Any) -> int:
        return int.from_bytes(raw, self._byteorder_str())

    def _make_sym_value(
        self, value: typing.Union[int, claripy.ast.bv.BV], size_bits: int
    ) -> typing.Any:
        if isinstance(value, claripy.ast.bv.BV):
            jbv = z3bridge.claripy_to_java_bv(self._jctx, value)
        elif isinstance(value, int):
            # Java Z3's mkBV(long, int) is signed-64; route the value through
            # the (String, int) overload so any bitwidth (including unsigned
            # 64-bit) works uniformly.
            jbv = self._jctx.mkBV(
                JString(str(value & ((1 << size_bits) - 1))), size_bits
            )
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

    def _sym_references_user_input(self, sym) -> bool:
        """Cheap check: does this ``SymValueZ3`` mention any user label?

        SymValueZ3 carries its SMT-LIB serialization eagerly in
        ``bitVecExprString``; user labels appear in that string only if they
        are part of the expression. Matching at word boundaries avoids
        accidental hits inside numeric literals (``#x0000`` contains an
        ``x``) and inside register names (``rax`` ends in ``x``).

        Skipping the full SMT-LIB → claripy round-trip on the (overwhelmingly
        common) negative case avoids a proportional native Z3 ``Context``
        allocation per register/memory check, which matters when
        ``machine.extract`` reads ~100 registers.
        """
        if not self._symbolic_inputs:
            return False
        if sym.bitVecExprString is None:
            return False
        pattern = self._user_input_pattern()
        if pattern is None:
            return False
        return bool(pattern.search(str(sym.bitVecExprString)))

    def _user_input_pattern(self) -> typing.Optional["re.Pattern[str]"]:
        """Cached whole-word regex over the currently-known user labels."""
        labels = self._symbolic_inputs
        cached = self._user_input_pattern_cache
        if cached is not None and cached[0] == len(labels):
            return cached[1]
        if not labels:
            self._user_input_pattern_cache = (len(labels), None)
            return None
        pattern = re.compile(
            r"\b(?:" + "|".join(re.escape(label) for label in labels) + r")\b"
        )
        self._user_input_pattern_cache = (len(labels), pattern)
        return pattern

    def read_register_content(self, name: str) -> int:
        if name == "pc":
            name = self.platdef.pc_register
        reg = self.machdef.pcode_reg(name)
        state = self._thread.getState()
        pair = state.getVar(reg, PcodeExecutorStatePiece.Reason.INSPECT)
        concrete = pair.getLeft()
        sym = pair.getRight()
        if sym is not None and self._sym_references_user_input(sym):
            # The symbolic side mentions a user-supplied label, so the value
            # is genuinely symbolic — caller should switch to
            # read_register_symbolic. ``SymValueZ3.toBigInteger`` is not a
            # useful check here: SymZ3 stores non-simplified expressions
            # (e.g. ``BVSub(BVV(n), BVV(8))``) even when the value is
            # arithmetically concrete, so ``toBigInteger`` returns null for
            # plenty of values whose concrete byte side is perfectly fine.
            raise exceptions.SymbolicValueError(
                f"Register {name} contains a symbolic value"
            )
        return self._int_from_bytes(concrete)

    def read_register_taint(self, name: str) -> typing.Set[str]:
        if not self._taint:
            return set()
        try:
            out = self.read_register_symbolic(name)
        except Exception:
            return set()
        if out is None:
            return set()
        return self._taint_of(out)

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
        concrete_bytes = concrete_unsigned.to_bytes(size_bytes, self._byteorder_str())

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
        prev = _collapse_to_concrete(self._read_register_ghidra_sized(name))
        bv = claripy.BVS(label, size_bits, explicit_name=True)
        # Bind the new label to whatever the register held before. Mirrors
        # angr's write_register_label: the label takes on the prior value,
        # so labelling an unset register leaves it unconstrained while
        # labelling a concretely-written register pins the label to that
        # value. Skip the binding entirely when the prior value was itself
        # an unconstrained fresh BVS (typical for a register that was never
        # written before this label call) — adding ``BVS_fresh == BVS_label``
        # only inflates the constraint set without telling the solver
        # anything useful.
        if not (prev.symbolic and prev.op == "BVS"):
            self._user_constraints.append(prev == bv)
        self._symbolic_inputs[label] = bv
        self.write_register_content(name, bv)

    def _read_register_ghidra_sized(self, name: str) -> claripy.ast.bv.BV:
        """Return the current register value as a claripy BV at Ghidra's
        native register size (smaller than smallworld's for x86 segment
        registers etc.). Used to size-match the binding constraint built
        in :meth:`write_register_label`."""
        reg = self.machdef.pcode_reg(name)
        ghidra_bits = reg.getMinimumByteSize() * 8
        pair = self._thread.getState().getVar(
            reg, PcodeExecutorStatePiece.Reason.INSPECT
        )
        sym = pair.getRight()
        if sym is None:
            return claripy.BVV(self._int_from_bytes(pair.getLeft()), ghidra_bits)
        return self._sym_to_claripy(sym)

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
        # Probe whether this range overlaps a user-labeled memory region; if
        # so, raise so the caller can switch to read_memory_symbolic. We do
        # the cheap "is there overlap?" check first and only materialize the
        # symbolic side when there is a labeled region nearby — otherwise
        # large concrete reads (e.g. Stack.extract reading 16 KB) would
        # force SymZ3 to build an enormous byte-wise ``Concat`` SymValueZ3
        # just to confirm "no, not symbolic".
        end = address + size
        candidate_ranges = self._labeled_memory_ranges + self._symbolic_store_ranges
        if any(not (e <= address or end <= s) for s, e in candidate_ranges):
            pair = self._read_memory_pair(address, size)
            sym = pair.getRight()
            if sym is not None and self._sym_references_user_input(sym):
                raise exceptions.SymbolicValueError(
                    f"Memory at {hex(address)} (size {size}) is symbolic"
                )
            return self.bytes_java_to_py(pair.getLeft())
        return self._read_concrete_bytes_at(address, size)

    def read_memory_taint(self, address: int, size: int) -> typing.Set[str]:
        if not self._taint:
            return set()
        try:
            out = self.read_memory_symbolic(address, size)
        except Exception:
            return set()
        if out is None:
            return set()
        return self._taint_of(out)

    def _taint_of(self, expr: claripy.ast.bv.BV) -> typing.Set[str]:
        # Simplify first: SymZ3 keeps unsimplified expressions, so a value like
        # ``x ^ x`` still textually references ``x``. Simplification reduces it
        # to a constant, correctly dropping sources the value no longer depends
        # on (e.g. a register cleared by ``xor r, r``).
        try:
            expr = claripy.simplify(expr)
        except Exception:
            pass
        return set(expr.variables) & set(self._symbolic_inputs.keys())

    def read_memory_symbolic(self, address: int, size: int) -> claripy.ast.bv.BV:
        pair = self._read_memory_pair(address, size)
        sym = pair.getRight()
        if sym is not None:
            return self._sym_to_claripy(sym)
        return claripy.BVV(self._int_from_bytes(pair.getLeft()), size * 8)

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
                # Preserve any concrete bytes already present at this
                # address. write_memory_label calls this method to overlay
                # a label BVS onto memory that was just written concretely;
                # if we zeroed the byte side, the concrete-driven execution
                # path would read zeros instead of the originally written
                # value (e.g. a fake return address would dispatch to 0).
                concrete_bytes = self._read_concrete_bytes_at(address, size)
            else:
                concrete_bytes = int(content.concrete_value).to_bytes(
                    size, self._byteorder_str()
                )
            sym_value = self._make_sym_value(content, size_bits)
            self._setvar_memory(address, size, concrete_bytes, sym_value)
        else:
            self._write_concrete_bytes(address, bytes(content))

    def _read_concrete_bytes_at(self, address: int, size: int) -> bytes:
        """Read ``size`` bytes at ``address`` from the concrete byte side only.

        Unlike :meth:`read_memory_content`, never raises
        ``SymbolicValueError`` — even when the symbolic side is genuinely
        symbolic, the concrete byte piece always has a defined value (zero
        for never-written addresses, the most-recent write otherwise).
        """
        raw = (
            self._emu.getSharedState()
            .getLeft()
            .getVar(
                self.machdef.language.getDefaultSpace(),
                self._addr_bytes(address),
                size,
                False,
                PcodeExecutorStatePiece.Reason.INSPECT,
            )
        )
        return self.bytes_java_to_py(raw)

    def _write_concrete_bytes(self, address: int, content: bytes) -> None:
        """Chunk a concrete-bytes write so the symbolic-side bitvector stays
        small. See ``_WRITE_CHUNK_BYTES`` for the rationale. The chunk's
        byte order must match the platform — SymZ3's storage splits the
        symbolic value into per-byte ``Extract`` slices using the language
        endianness, so feeding a value built with the wrong byte order
        produces reversed bytes on the symbolic side.
        """
        bo = self._byteorder_str()
        for offset in range(0, len(content), _WRITE_CHUNK_BYTES):
            piece = content[offset : offset + _WRITE_CHUNK_BYTES]
            size = len(piece)
            value = int.from_bytes(piece, bo)
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
        prev = _collapse_to_concrete(self.read_memory_symbolic(address, size))
        bv = claripy.BVS(label, size * 8, explicit_name=True)
        # Same binding contract as write_register_label: the new label takes
        # on the value previously held at this address, so labelling memory
        # that was just written concretely pins the label to those bytes.
        # We collapse ``prev`` first because SymZ3 returns memory as a
        # byte-level ``Concat`` of ``Extract`` slices; passing that raw to
        # the solver makes Z3 enumerate the structure instead of using the
        # cheap underlying value.
        if not (prev.symbolic and prev.op == "BVS"):
            self._user_constraints.append(prev == bv)
        self._symbolic_inputs[label] = bv
        self._labeled_memory_ranges.append((address, address + size))
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
        if pc_after == pc:
            # The instruction did not advance the program counter. The most
            # common cause is an unhandled CALLOTHER userop (e.g. ``hlt`` on
            # amd64): Ghidra's executor silently marks the frame as not
            # fall-through, the parent thread leaves the counter where it is,
            # and our loop would re-enter the same instruction forever.
            # Treat this as a halt instead.
            log.info("PC did not advance past %#x; halting emulation.", pc)
            raise exceptions.EmulationExitpoint()

    def _maybe_fork_on_symbolic_cbranch(self, op) -> None:
        """Detect a symbolic CBRANCH and fork into two paths.

        Examines the condition varnode of a CBRANCH op. If its symbolic side
        references a user-labeled input and the lifted claripy expression is
        not concretely determined, prove both ``cond != 0`` (taken) and
        ``cond == 0`` (not-taken) are satisfiable against the current path
        constraints, set ``self._fork_constraints``, and raise EmulationStop
        so ``Machine.symbolic_emulate`` can yield one Machine per direction.

        Any failure (lift error, no symbolic side, concrete condition, or
        one direction UNSAT) falls through silently so Ghidra's executor
        runs the CBRANCH normally on the concrete-byte side. We do not
        invalidate ``_cached_preconditions`` here — when we raise out, the
        CBRANCH was never executed, so Ghidra's per-thread precondition
        list is unchanged from the previous instruction's end.
        """
        try:
            inputs = op.getInputs()
            if len(inputs) < 2:
                return
            cond_var = inputs[1]
            state = self._thread.getState()
            pair = state.getVar(cond_var, PcodeExecutorStatePiece.Reason.INSPECT)
            sym = pair.getRight()
            if sym is None:
                return
            # Cheap pre-filter: skip CBRANCHes whose symbolic side cannot
            # reach a user label — the concrete side fully determines them
            # and the linear path is already correct.
            if not self._sym_references_user_input(sym):
                return
            cond_bv = self._sym_to_claripy(sym)
            if not cond_bv.symbolic:
                return
            zero = claripy.BVV(0, cond_bv.size())
            taken = cond_bv != zero
            not_taken = cond_bv == zero
            base = self._solver()
            taken_solver = base.branch()
            taken_solver.add(taken)
            if not taken_solver.satisfiable():
                log.debug(
                    "Symbolic CBRANCH: taken direction UNSAT; "
                    "letting concrete side drive."
                )
                return
            not_taken_solver = base.branch()
            not_taken_solver.add(not_taken)
            if not not_taken_solver.satisfiable():
                log.debug(
                    "Symbolic CBRANCH: not-taken direction UNSAT; "
                    "letting concrete side drive."
                )
                return
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "CBRANCH fork inspection failed (%s); "
                "falling back to linear execution.",
                exc,
            )
            return

        self._fork_constraints = [taken, not_taken]
        raise exceptions.EmulationStop("Path diverged at symbolic CBRANCH")

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
            elif opcode == op.CBRANCH:
                # Inspect the condition for a user-symbolic value. If both
                # directions are SAT, this raises EmulationStop after
                # setting self._fork_constraints; otherwise it returns
                # and the next iteration's stepPcodeOp() executes the
                # CBRANCH normally on the concrete side.
                self._maybe_fork_on_symbolic_cbranch(op)

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
        new_sym = (
            self._sym_to_claripy(sym)
            if sym is not None
            else claripy.BVV(self._int_from_bytes(bytes(new_concrete)), size * 8)
        )
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
        state.setVar(
            out_var, JPair.of(self.bytes_py_to_java(bytes(new_concrete)), sym_value)
        )

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
        # Track stores of user-symbolic values to (possibly unlabeled)
        # memory so a later read_memory_content of this range still runs the
        # precise symbolic check. Uses the cheap word-boundary string probe,
        # so it does not force a per-byte Concat materialization.
        if sym is not None and self._sym_references_user_input(sym):
            self._symbolic_store_ranges.append((addr, addr + size))
        sym_claripy = (
            self._sym_to_claripy(sym)
            if sym is not None
            else claripy.BVV(self._int_from_bytes(concrete), size * 8)
        )
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
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
    ) -> None:
        self._mem_read_hooks[(start, end)] = function

    def unhook_memory_read(self, start: int, end: int) -> None:
        self._mem_read_hooks.pop((start, end), None)

    def hook_memory_reads(
        self,
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
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
        function: typing.Callable[[Emulator, int, int, claripy.ast.bv.BV], None],
    ) -> None:
        self._mem_write_symbolic_hooks[(start, end)] = function

    def hook_memory_writes_symbolic(
        self,
        function: typing.Callable[[Emulator, int, int, claripy.ast.bv.BV], None],
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
        # exposes the path conditions. Also append the active fork
        # constraint (if any) when ``get_active_states`` is mid-iteration
        # over a CBRANCH fork — that constraint is what distinguishes the
        # two extracted Machines from each other.
        out = list(self._user_constraints) + list(self._path_preconditions())
        if self._active_fork_constraint is not None:
            out.append(self._active_fork_constraint)
        return out

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

    def _solver(
        self, extras: typing.Sequence[claripy.ast.bool.Bool] = ()
    ) -> "claripy.Solver":
        """Build a claripy solver loaded with user constraints + path preconditions.

        Routing through claripy (rather than building a raw ``z3.Solver``)
        gives us claripy-side constraint simplification before any solver
        backend sees them.
        """
        solver = claripy.Solver()
        for expr in self._user_constraints:
            solver.add(expr)
        for expr in self._path_preconditions():
            solver.add(expr)
        for expr in extras:
            solver.add(expr)
        return solver

    def satisfiable(
        self,
        extra_constraints: typing.List[claripy.ast.bool.Bool] = [],
    ) -> bool:
        return self._solver(extra_constraints).satisfiable()

    def eval_atmost(self, expr: claripy.ast.bv.BV, most: int) -> typing.List[int]:
        solver = self._solver()
        try:
            results = list(solver.eval(expr, most + 1))
        except claripy.errors.UnsatError as exc:
            raise exceptions.UnsatError(
                "No satisfying assignment for expression given constraints"
            ) from exc
        if not results:
            raise exceptions.UnsatError(
                "No satisfying assignment for expression given constraints"
            )
        if len(results) > most:
            raise exceptions.SymbolicValueError(
                f"More than {most} solutions for expression"
            )
        return results

    def eval_atleast(self, expr: claripy.ast.bv.BV, least: int) -> typing.List[int]:
        solver = self._solver()
        try:
            results = list(solver.eval(expr, least))
        except claripy.errors.UnsatError as exc:
            raise exceptions.SymbolicValueError(
                f"Fewer than {least} solutions for expression"
            ) from exc
        if len(results) < least:
            raise exceptions.SymbolicValueError(
                f"Fewer than {least} solutions for expression"
            )
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
        """Yield one view per active path.

        Linear case: one yield of ``self`` (no fork constraints recorded).

        Fork case: ``_step_pcode_ops`` stopped at a symbolic CBRANCH and
        populated ``_fork_constraints`` with ``[taken, not_taken]``. We
        yield ``self`` once per direction, binding
        ``_active_fork_constraint`` first so ``get_constraints`` appends
        the right predicate for the extraction that follows. The harness
        (``Machine.symbolic_emulate``) deepcopies+extracts immediately
        after each yield, so rebinding on the next iteration does not
        clobber the previously-extracted Machine.
        """
        if not self._fork_constraints:
            yield self
            return
        for c in self._fork_constraints:
            self._active_fork_constraint = c
            yield self
        self._active_fork_constraint = None

    def get_deadended_states(self) -> typing.Generator[Emulator, None, None]:
        """No-op for the linear emulator — the active state covers inspection."""
        return
        yield  # pragma: no cover - turns this into a generator

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


def _collapse_to_concrete(bv: claripy.ast.bv.BV) -> claripy.ast.bv.BV:
    """Reduce ``bv`` to a single ``BVV`` when its value is concretely known.

    SymZ3 represents whole-buffer reads as a deep ``Concat`` of ``Extract``
    slices of constant chunks. Z3 can solve such constraints, but at high
    cost when they appear in user-constraint sets. If the expression is in
    fact concretely determined, collapse it once here so downstream solver
    passes operate on a single ``BVV`` instead.
    """
    if bv.symbolic:
        return bv
    try:
        return claripy.BVV(bv.concrete_value, bv.size())
    except Exception:  # noqa: BLE001
        return bv
