"""SmallWorld emulator backend backed by the Triton DBA framework.

Triton (https://github.com/JonathanSalwan/Triton) is a dynamic binary analysis
library exposing concrete emulation, symbolic execution, and taint analysis over
x86, x86-64, ARM32, AArch64, and RISC-V through a single ``TritonContext``
object (PyPI ``triton-library``, import name ``triton``).

This module provides the *concrete* :class:`TritonEmulator`. The symbolic
:class:`~smallworld.emulators.triton.symbolic.TritonSymbolicEmulator` subclasses
it (see ``symbolic.py``).

Notable design points:

- **Flat, lazy memory**: Triton has no explicit memory map — any address can be
  read or written, and unwritten cells read back as zero. ``map_memory`` is
  therefore bookkeeping only (tracked in a ``RangeCollection`` so
  ``get_memory_map`` stays coherent), mirroring the Styx backend.
- **Self-driven execution**: Triton exposes single-instruction ``processing()``
  rather than a run-to-completion primitive, so :meth:`run` drives its own
  fetch/decode/execute loop and is responsible for exit-point/bounds checks and
  hook dispatch (like the Unicorn code callback).
- **Memory read/write hooks** are backed by Triton's
  ``GET_CONCRETE_MEMORY_VALUE`` / ``SET_CONCRETE_MEMORY_VALUE`` callbacks;
  instruction/function/interrupt hooks are dispatched directly in the run loop.
- **Taint** is exposed through backend-specific ``*_tainted`` escape-hatch
  methods (not part of the SmallWorld ``Emulator`` contract).
"""

from __future__ import annotations

import contextlib
import logging
import typing

import claripy

from ... import exceptions, platforms, utils
from .. import emulator, hookable
from .machdefs import TritonMachineDef

logger = logging.getLogger(__name__)

# Triton is an optional dependency (the [emu-triton] extra). When absent,
# importing this module raises ImportError, which the parent
# ``emulators/__init__.py`` swallows so ``import smallworld`` still works.
try:
    from triton import (  # noqa: F401
        ARCH,
        CALLBACK,
        EXCEPTION,
        MODE,
        PREFIX,
        Instruction,
        MemoryAccess,
        TritonContext,
    )

    _TRITON_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on installed extras
    _TRITON_AVAILABLE = False


# Mnemonic prefixes of ARM32 instructions that write memory without reading it.
# Triton implements every ARM32 store as ``mem = cond ? value : mem`` -- the
# conditional-execution model needs the old contents to fall back on -- so a
# plain ``str``/``stm`` reports a *read* of its own destination through the
# GET_CONCRETE_MEMORY_VALUE callback. ARM32 is a load/store architecture, so a
# store-only instruction never reads memory architecturally; the backend uses
# this set to tell that artifact apart from a real load. ``swp`` is deliberately
# absent: it genuinely does read and write the same location.
_ARM32_STORE_ONLY_PREFIXES = ("str", "stm", "stl", "stc", "push")

# ARM32 condition-code suffixes. Triton has no semantics for the trap and
# wait-for-event instructions, so the run loop recognises them by mnemonic --
# but Capstone renders a predicated form with its condition glued on
# (``svcne``), which no plain mnemonic set can match. ``_canonical_mnemonic``
# strips the suffix when doing so names an instruction the machdef knows, and
# ``_arm32_condition_holds`` decides whether the instruction actually executes.
_ARM32_CONDITION_CODES = {
    "eq": ("z",),
    "ne": ("z",),
    "cs": ("c",),
    "hs": ("c",),
    "cc": ("c",),
    "lo": ("c",),
    "mi": ("n",),
    "pl": ("n",),
    "vs": ("v",),
    "vc": ("v",),
    "hi": ("c", "z"),
    "ls": ("c", "z"),
    "ge": ("n", "v"),
    "lt": ("n", "v"),
    "gt": ("z", "n", "v"),
    "le": ("z", "n", "v"),
    "al": (),
}

# SmallWorld architectures that use Triton's ARM32 target (all little-endian).
_ARM32_ARCHITECTURES = frozenset(
    {
        platforms.Architecture.ARM_V5T,
        platforms.Architecture.ARM_V6M,
        platforms.Architecture.ARM_V6M_THUMB,
        platforms.Architecture.ARM_V7M,
        platforms.Architecture.ARM_V7R,
        platforms.Architecture.ARM_V7A,
    }
)


class TritonEmulationError(exceptions.EmulationError):
    """Raised for Triton-specific failures that don't map cleanly to an existing
    SmallWorld emulation exception."""


class TritonEmulator(
    emulator.Emulator,
    hookable.QInstructionHookable,
    hookable.QFunctionHookable,
    hookable.QMemoryReadHookable,
    hookable.QMemoryWriteHookable,
    hookable.QInterruptHookable,
    emulator.SyscallHookable,
):
    """Concrete emulator backend for SmallWorld based on Triton."""

    name = "triton"
    description = (
        "concrete emulator based on the Triton dynamic binary analysis framework"
    )
    version = "0.1.0"

    # Upper bound on x86 instruction length; a safe fetch window for all ISAs.
    _MAX_INSN_BYTES = 16

    def __init__(self, platform: platforms.Platform):
        if not _TRITON_AVAILABLE:
            raise exceptions.ConfigurationError(
                "triton is not installed; install smallworld with the "
                "[emu-triton] extra (built from source via the nix flake)."
            )
        super().__init__(platform)
        self.platform: platforms.Platform = platform
        self.platdef: platforms.PlatformDef = platforms.PlatformDef.for_platform(
            platform
        )
        self.machdef: TritonMachineDef = TritonMachineDef.for_platform(platform)

        self.ctx = TritonContext(self.machdef.triton_arch)
        # ALIGNED_MEMORY keeps symbolic memory tractable and is harmless for
        # concrete execution; it's the mode every Triton emulation example sets.
        self.ctx.setMode(MODE.ALIGNED_MEMORY, True)
        if self.machdef.is_thumb:
            self.ctx.setThumb(True)

        self._memory_map: utils.RangeCollection = utils.RangeCollection()
        # The most recently processed instruction, used by step_block to detect
        # the end of a basic block.
        self._last_instruction: typing.Optional[typing.Any] = None
        # Set while executing an ARM32 store-only instruction; see
        # ``_ARM32_STORE_ONLY_PREFIXES`` and ``_on_memory_read``.
        self._in_arm32_store: bool = False
        # Set while the backend itself is driving Triton's memory (symbolizing
        # a buffer, reading an AST back out). Triton fires the same concrete
        # memory callbacks for those internal accesses as it does for the
        # emulated program's, and the hook contract says hooks fire only for
        # the program's own accesses -- see ``_direct_access``.
        self._in_direct_access: bool = False
        # An exception raised by a memory callback (a user hook, or the mapping
        # check) while Triton was executing an instruction. Triton lets it
        # propagate out of ``processing``/``buildSemantics``, where it is
        # indistinguishable from a decode failure -- see ``_decode_failure``.
        self._callback_error: typing.Optional[BaseException] = None

        # Syscall hooks, dispatched from the run loop alongside interrupts.
        self._syscall_hooks: typing.Dict[
            int, typing.Callable[[emulator.Emulator], None]
        ] = {}
        self._all_syscalls_hook: typing.Optional[
            typing.Callable[[emulator.Emulator, int], None]
        ] = None

        # Memory read/write hooks are dispatched through Triton callbacks. They
        # are registered once and fall through immediately when no hook matches.
        self.ctx.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, self._on_memory_read)
        self.ctx.addCallback(CALLBACK.SET_CONCRETE_MEMORY_VALUE, self._on_memory_write)

    # ----------------------------------------------------------------- helpers

    def _is_arm32(self) -> bool:
        return self.platform.architecture in _ARM32_ARCHITECTURES

    def _reg(self, name: str) -> typing.Any:
        """Resolve a SmallWorld register name to a Triton ``Register`` object."""
        return self.ctx.getRegister(self.machdef.triton_register(name))

    def _byteorder(self) -> typing.Literal["little", "big"]:
        return "big" if self.platform.byteorder == platforms.Byteorder.BIG else "little"

    def _concrete_pc(self) -> int:
        """The concrete program counter, straight out of Triton.

        The run loop must never route this through ``read_register_content``:
        the symbolic subclass overrides that to reject a symbolized register,
        and Triton symbolizes PC as soon as a branch depends on symbolic data
        -- which is exactly the case linear symbolic execution has to survive.
        """
        return int(self.ctx.getConcreteRegisterValue(self._reg("pc")))

    @contextlib.contextmanager
    def _direct_access(self) -> typing.Iterator[None]:
        """Suppress hook dispatch and the mapping check for a backend access.

        Triton runs the concrete memory callbacks for *any* access, including
        the ones this backend makes on the harness's behalf (``symbolizeMemory``
        reads the cell it is about to symbolize, ``getMemoryAst`` reads the cell
        it is describing). Those are API calls, not instruction accesses, so
        they must not fire the user's memory hooks.
        """
        previous = self._in_direct_access
        self._in_direct_access = True
        try:
            yield
        finally:
            self._in_direct_access = previous

    # --------------------------------------------------------------- registers

    def read_register_content(self, name: str) -> int:
        reg = self._reg(name)
        return int(self.ctx.getConcreteRegisterValue(reg))

    def write_register_content(
        self, name: str, content: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        if content is None:
            return
        if isinstance(content, claripy.ast.bv.BV):
            raise exceptions.SymbolicValueError(
                "TritonEmulator is a concrete emulator; use TritonSymbolicEmulator "
                "for symbolic values"
            )
        if not isinstance(content, int):
            raise TypeError(f"Cannot write register '{name}' with non-int value")
        value = int(content)
        # On ARM32 the low bit of a written PC selects Thumb mode; honor it and
        # clear the bit so the concrete PC stays aligned.
        if self._is_arm32() and name.lower() in ("pc", self.machdef.pc_register):
            if value & 1:
                self.ctx.setThumb(True)
                value &= ~1
        self.ctx.setConcreteRegisterValue(self._reg(name), value)

    # ------------------------------------------------------------------ memory

    def read_memory_content(self, address: int, size: int) -> bytes:
        # Direct API reads bypass hook callbacks; hooks fire only for the
        # emulated instructions' own accesses (during ``processing``).
        return bytes(self.ctx.getConcreteMemoryAreaValue(address, size, False))

    def write_memory_content(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ) -> None:
        if isinstance(content, claripy.ast.bv.BV):
            raise exceptions.SymbolicValueError(
                "TritonEmulator is a concrete emulator; use TritonSymbolicEmulator "
                "for symbolic values"
            )
        data = bytes(content)
        self.ctx.setConcreteMemoryAreaValue(address, data, False)
        self._memory_map.add_range((address, address + len(data)))

    def write_code(self, address: int, content: bytes) -> None:
        data = bytes(content)
        self.ctx.setConcreteMemoryAreaValue(address, data, False)
        self._memory_map.add_range((address, address + len(data)))

    def map_memory(self, address: int, size: int) -> None:
        # Triton memory is flat/lazy, so this only records the intent so that
        # ``get_memory_map`` reports a consistent view to the rest of SmallWorld.
        self._memory_map.add_range((address, address + size))

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        return list(self._memory_map.ranges)

    def _check_mapped(self, address: int, size: int, kind: str) -> None:
        """Raise if no part of ``[address, address + size)`` was ever mapped.

        Triton's own memory is flat and lazy: every address is readable,
        writable and executable, and unwritten cells read back as zero. Without
        this check the backend would silently succeed where every other one
        faults -- and, worse, a wild jump would grind through gigabytes of
        zero-filled "instructions" instead of stopping. The bookkeeping
        ``map_memory``/``write_memory_content`` already keep in ``_memory_map``
        is exactly the mapping SmallWorld asked for, so enforce against it here.

        The test is overlap rather than containment: an access that runs off the
        end of a mapped region is let through, because SmallWorld's own map is
        sometimes coarser than the real one (a ``Model`` reserves 16 bytes at its
        address, say), and a false fault there would be worse than a missed one.
        Wholly-unmapped accesses -- the ones this exists to catch -- are still
        reported.
        """
        if self._memory_map.contains((address, address + size)):
            return
        message = f"{kind} of {size} byte(s) at {hex(address)} is outside mapped memory"
        pc = self._concrete_pc()
        if kind == "fetch":
            raise exceptions.EmulationFetchUnmappedFailure(message, pc, address=address)
        if kind == "write":
            raise exceptions.EmulationWriteUnmappedFailure(message, pc, address=address)
        raise exceptions.EmulationReadUnmappedFailure(message, pc, address=address)

    # -------------------------------------------------------------- execution

    def _handle_fault(self, rc: typing.Any, pc: int, inst: typing.Any) -> None:
        """Deal with a ``processing`` result that reported a fault.

        Triton reports anything it has no semantics for as an undefined
        instruction, which lumps genuinely invalid encodings together with
        perfectly valid instructions it simply does not model (``hlt``, and the
        trap instructions on every target except x86-64 and AArch64). Recognise
        the latter by mnemonic and give them their architectural meaning; only
        what is left over is reported as an execution failure.
        """
        mnemonic = self._canonical_mnemonic(self._mnemonic(inst))
        if mnemonic in self.machdef.halt_mnemonics:
            if not self._arm32_condition_holds(self._mnemonic(inst)):
                # A predicated halt whose condition is false: a no-op.
                self.write_register_content("pc", pc + inst.getSize())
                return
            # A valid instruction that stops the machine: a clean stop, not a
            # failure to execute.
            raise exceptions.EmulationExitpoint(
                f"execution halted at pc={hex(pc)} ({mnemonic})"
            )
        if mnemonic in self.machdef.interrupt_mnemonics:
            # A valid trap instruction Triton does not model. Run the hooks and
            # resume at the next instruction, which is what the architecture
            # does once the handler returns -- unless a hook redirected control
            # flow itself, which the SyscallHookable/InterruptHookable contract
            # explicitly allows.
            self._dispatch_trap(inst)
            if self._concrete_pc() == pc:
                self.write_register_content("pc", pc + inst.getSize())
            return
        disasm = ""
        try:
            disasm = inst.getDisassembly()
        except Exception:
            pass
        raise exceptions.EmulationExecInvalidFailure(
            f"triton failed to process instruction at {hex(pc)}: {disasm} (rc={rc})",
            pc,
            None,
        )

    def _canonical_mnemonic(self, mnemonic: str) -> str:
        """``mnemonic`` with an ARM32 condition suffix removed, where it has one.

        Only strips when the stem is a mnemonic this architecture actually
        cares about, so ordinary predicated instructions (``ble``, ``movne``)
        keep their spelling and cannot be mistaken for a trap.
        """
        if not self._is_arm32() or len(mnemonic) <= 2:
            return mnemonic
        if mnemonic[-2:] not in _ARM32_CONDITION_CODES:
            return mnemonic
        stem = mnemonic[:-2]
        machdef = self.machdef
        if (
            stem in machdef.interrupt_mnemonics
            or stem in machdef.halt_mnemonics
            or stem in machdef.syscall_mnemonics
        ):
            return stem
        return mnemonic

    def _arm32_condition_holds(self, mnemonic: str) -> bool:
        """Whether a predicated ARM32 ``mnemonic`` executes in the current state.

        Triton has no semantics for the instructions this matters for, so it
        never evaluates their condition; the backend has to, or a ``svcne``
        whose condition is false would still fire the syscall hooks.
        """
        if self._canonical_mnemonic(mnemonic) == mnemonic:
            return True
        condition = mnemonic[-2:]
        flags = {
            name: bool(self.ctx.getConcreteRegisterValue(self.ctx.getRegister(name)))
            for name in _ARM32_CONDITION_CODES[condition]
        }
        n = flags.get("n", False)
        z = flags.get("z", False)
        c = flags.get("c", False)
        v = flags.get("v", False)
        if condition == "eq":
            return z
        if condition == "ne":
            return not z
        if condition in ("cs", "hs"):
            return c
        if condition in ("cc", "lo"):
            return not c
        if condition == "mi":
            return n
        if condition == "pl":
            return not n
        if condition == "vs":
            return v
        if condition == "vc":
            return not v
        if condition == "hi":
            return c and not z
        if condition == "ls":
            return (not c) or z
        if condition == "ge":
            return n == v
        if condition == "lt":
            return n != v
        if condition == "gt":
            return (not z) and n == v
        if condition == "le":
            return z or n != v
        return True  # "al"

    def _interrupt_number(self, mnemonic: str, inst: typing.Any) -> int:
        """The software-interrupt number for x86 ``int N``/``int3``; 0 otherwise."""
        if mnemonic == "int3":
            return 3
        if mnemonic == "int":
            try:
                return int(inst.getOperands()[0].getValue())
            except Exception:
                return 0
        return 0

    def _is_syscall(self, mnemonic: str, intno: int) -> bool:
        if mnemonic in self.machdef.syscall_mnemonics:
            return True
        return (
            self.machdef.syscall_interrupt is not None
            and mnemonic == "int"
            and intno == self.machdef.syscall_interrupt
        )

    def _dispatch_trap(self, inst: typing.Any) -> None:
        """Dispatch syscall then interrupt hooks for a trap instruction.

        On most architectures one instruction serves both purposes (``svc``,
        ``ecall``, ``int 0x80``), so a syscall hook gets first refusal and the
        interrupt hooks see anything it did not claim.
        """
        if self.machdef.interrupt_mnemonics and (
            self.all_interrupts_hook is not None
            or self.interrupt_hooks
            or self._all_syscalls_hook is not None
            or self._syscall_hooks
        ):
            raw = self._mnemonic(inst)
        else:
            # Nothing to dispatch to. Skip the disassembly this would otherwise
            # format for every instruction the run loop executes.
            return
        mnemonic = self._canonical_mnemonic(raw)
        if mnemonic not in self.machdef.interrupt_mnemonics:
            return
        if not self._arm32_condition_holds(raw):
            return
        intno = self._interrupt_number(mnemonic, inst)
        if self._dispatch_syscall(mnemonic, intno):
            return
        # Both the global and the numbered hook run, as they do on Unicorn and
        # as they do for syscalls just below; a numbered hook does not suppress
        # the global one.
        if self.all_interrupts_hook is not None:
            self.all_interrupts_hook(self, intno)
        handler = self.is_interrupt_hooked(intno)
        if handler is not None:
            handler(self)

    def _dispatch_syscall(self, mnemonic: str, intno: int) -> bool:
        """Run the syscall hooks for this instruction; report whether any fired."""
        if not self._is_syscall(mnemonic, intno):
            return False
        if self._all_syscalls_hook is None and not self._syscall_hooks:
            return False
        register = self.machdef.syscall_number_register
        if register is None:
            raise exceptions.ConfigurationError(
                f"Triton has no syscall-number register for {self.platform}"
            )
        # Concretely, not through read_register_content: the symbolic subclass
        # rejects a symbolized register, and a linear engine follows whatever
        # number the concrete state holds.
        number = int(self.ctx.getConcreteRegisterValue(self._reg(register)))
        fired = False
        if self._all_syscalls_hook is not None:
            self._all_syscalls_hook(self, number)
            fired = True
        hook = self._syscall_hooks.get(number)
        if hook is not None:
            hook(self)
            fired = True
        return fired

    def _check_pc(self, pc: int) -> None:
        """Raise if ``pc`` is an exit point or outside configured bounds."""
        if pc in self._exit_points:
            raise exceptions.EmulationExitpoint(f"exit point reached at pc={hex(pc)}")
        if not self._bounds.is_empty() and not self._bounds.contains_value(pc):
            raise exceptions.EmulationBounds(
                f"pc={hex(pc)} is outside the configured execution bounds"
            )

    def step_instruction(self) -> None:
        pc = self._concrete_pc()
        self._check_pc(pc)

        # Instruction hooks (global, then address-specific). A hook may
        # redirect control flow; if it does, the instruction it jumped away
        # from must not run, so hand the new PC back to the next step.
        if self.all_instructions_hook is not None:
            self.all_instructions_hook(self)
        insn_hook = self.is_instruction_hooked(pc)
        if insn_hook is not None:
            insn_hook(self)
        if self._concrete_pc() != pc:
            self._last_instruction = None
            return

        # Function hooks replace the body: the hook runs in place of the call,
        # and — as with every other backend — the hook itself is responsible for
        # returning to the caller (``Model.run`` pops the return address and
        # writes PC). Returning here as well would pop a second frame.
        fn_hook = self.is_function_hooked(pc)
        if fn_hook is not None:
            fn_hook(self)
            if self._concrete_pc() != pc:
                self._last_instruction = None
                return
            # The hook left PC where it was. Returning here would re-enter it
            # forever, so fall through and execute the instruction, which is
            # what Unicorn's code callback does.

        # One byte is enough to decide the fetch is legal; the window below may
        # legitimately run past the end of the mapped region for a short final
        # instruction, exactly as it does on the other backends.
        self._check_mapped(pc, 1, "fetch")
        opcode = bytes(
            self.ctx.getConcreteMemoryAreaValue(pc, self._MAX_INSN_BYTES, False)
        )
        inst = Instruction(pc, opcode)
        rc = self._execute(inst)
        if rc == EXCEPTION.NO_FAULT:
            self._dispatch_trap(inst)
        else:
            self._handle_fault(rc, pc, inst)
        self._last_instruction = inst

        new_pc = self._concrete_pc()
        if new_pc == pc and not inst.isControlFlow() and not self._repeats(inst):
            # A non-branch instruction that executed without advancing PC means
            # execution can make no further progress. The named halt
            # instructions are caught earlier, in _handle_fault; this is the
            # backstop for anything else that wedges the same way.
            raise exceptions.EmulationExitpoint(
                f"execution halted at pc={hex(pc)} (pc did not advance)"
            )

    def _repeats(self, inst: typing.Any) -> bool:
        """Whether ``inst`` is a string operation that re-executes in place.

        Triton implements the x86 ``rep``/``repe``/``repne`` prefixes by leaving
        PC on the instruction until the counter drains, and Capstone does not
        report the string ops as control flow -- so without this the
        "pc did not advance" backstop would call the *first* iteration of an
        inlined ``memcpy``/``memset`` a clean halt and silently truncate it.
        """
        try:
            prefix = inst.getPrefix()
        except Exception:
            return False
        return prefix in (PREFIX.X86.REP, PREFIX.X86.REPE, PREFIX.X86.REPNE)

    def _mnemonic(self, inst: typing.Any) -> str:
        """The instruction's mnemonic, lowercased, or ``""`` if unavailable."""
        try:
            return inst.getDisassembly().split(None, 1)[0].lower()
        except Exception:
            return ""

    def _execute(self, inst: typing.Any) -> typing.Any:
        """Run one decoded instruction, flagging ARM32 stores while they run.

        ``ctx.processing`` is ``disassembly`` followed by ``buildSemantics``.
        Splitting it on ARM32 costs nothing and lets the backend know the
        mnemonic *before* the semantics fire their memory callbacks, which is
        what ``_on_memory_read`` needs to recognise a store's phantom read.

        Note that ``disassembly`` *raises* on an encoding Capstone cannot decode
        rather than returning a fault code, so both paths have to translate that
        into SmallWorld's own "invalid instruction" failure; only instructions
        Triton decodes but has no semantics for come back as a fault code.
        """
        pc = inst.getAddress()
        self._callback_error = None
        if not self._is_arm32():
            try:
                return self.ctx.processing(inst)
            except Exception as e:
                raise self._decode_failure(pc, e) from e
        try:
            self.ctx.disassembly(inst)
        except Exception as e:
            raise self._decode_failure(pc, e) from e
        self._in_arm32_store = self._mnemonic(inst).startswith(
            _ARM32_STORE_ONLY_PREFIXES
        )
        try:
            return self.ctx.buildSemantics(inst)
        except Exception as e:
            raise self._decode_failure(pc, e) from e
        finally:
            self._in_arm32_store = False

    def _decode_failure(self, pc: int, cause: BaseException) -> BaseException:
        """Translate a raised Triton decode error into a SmallWorld failure.

        The memory callbacks run inside ``processing``/``buildSemantics``, so an
        exception raised by a user hook or by ``_check_mapped`` surfaces through
        the very same ``except`` as a bad encoding does. ``_callback_error``
        tells the two apart, so a model's own ``ValueError`` reaches its caller
        unchanged instead of being relabelled an invalid instruction.
        """
        if self._callback_error is not None:
            return self._callback_error
        return exceptions.EmulationExecInvalidFailure(
            f"triton could not decode the instruction at {hex(pc)}: {cause}",
            pc,
            None,
        )

    def step_block(self) -> None:
        while True:
            self.step_instruction()
            last = self._last_instruction
            if last is None or last.isControlFlow():
                return

    def run(self) -> None:
        if not self._exit_points and self._bounds.is_empty():
            raise exceptions.ConfigurationError(
                "TritonEmulator.run() needs at least one exit point or execution "
                "bound to know when to stop"
            )
        try:
            while True:
                self.step_instruction()
        except exceptions.EmulationStop:
            # Reaching an exit point or the end of the configured bounds is how
            # a run finishes; like the other backends, return rather than let
            # the stop escape to the caller.
            pass

    # -------------------------------------------------------- memory callbacks

    def _on_memory_read(self, ctx: typing.Any, mem: typing.Any) -> None:
        try:
            self._memory_read(ctx, mem)
        except BaseException as e:
            self._callback_error = e
            raise

    def _on_memory_write(self, ctx: typing.Any, mem: typing.Any, value: int) -> None:
        try:
            self._memory_write(ctx, mem, value)
        except BaseException as e:
            self._callback_error = e
            raise

    def _memory_read(self, ctx: typing.Any, mem: typing.Any) -> None:
        if self._in_direct_access:
            # An access this backend made itself, not one the program made.
            return
        if self._in_arm32_store:
            # Triton's ARM32 store semantics read the destination back so the
            # conditional form has an old value to keep. The program performed
            # no read, so neither the read hooks nor the unmapped check should
            # see one; the matching write callback still runs for both.
            return
        address = mem.getAddress()
        size = mem.getSize()
        self._check_mapped(address, size, "read")
        if not self.memory_read_hooks and self.all_reads_hook is None:
            return
        data = bytes(ctx.getConcreteMemoryAreaValue(address, size, False))
        replacement: typing.Optional[bytes] = None
        if self.all_reads_hook is not None:
            out = self.all_reads_hook(self, address, size, data)
            if out is not None:
                replacement = self._check_replacement(out, address, size)
                # Chain: an address-specific hook sees what the global hook
                # produced, so the two compose instead of racing.
                data = replacement
        hook = self.is_memory_read_hooked(address, size)
        if hook is not None:
            out = hook(self, address, size, data)
            if out is not None:
                replacement = self._check_replacement(out, address, size)
        if replacement is not None:
            ctx.setConcreteMemoryAreaValue(address, replacement, False)

    @staticmethod
    def _check_replacement(data: bytes, address: int, size: int) -> bytes:
        """Validate the bytes a read hook substituted for the access.

        Triton's read callback has no return channel, so a replacement has to
        be written into memory before the access completes; a wrong-length one
        would silently clobber the neighbouring bytes (or leave part of the
        access stale). Every other backend rejects it, so reject it here too.
        """
        out = bytes(data)
        if len(out) != size:
            raise exceptions.EmulationError(
                f"Read hook at {hex(address)} returned {len(out)} bytes; "
                f"need {size} bytes"
            )
        return out

    def _memory_write(self, ctx: typing.Any, mem: typing.Any, value: int) -> None:
        if self._in_direct_access:
            return
        address = mem.getAddress()
        size = mem.getSize()
        self._check_mapped(address, size, "write")
        if not self.memory_write_hooks and self.all_writes_hook is None:
            return
        data = int(value).to_bytes(size, self._byteorder())
        if self.all_writes_hook is not None:
            self.all_writes_hook(self, address, size, data)
        hook = self.is_memory_write_hooked(address, size)
        if hook is not None:
            hook(self, address, size, data)

    # ------------------------------------------------------------------ thumb

    def get_thumb(self) -> bool:
        if not self._is_arm32():
            raise exceptions.ConfigurationError(
                "get_thumb() is only meaningful on ARM32 platforms"
            )
        return bool(self.ctx.isThumb())

    def set_thumb(self, enabled: bool = True) -> None:
        if not self._is_arm32():
            raise exceptions.ConfigurationError(
                "set_thumb() is only meaningful on ARM32 platforms"
            )
        self.ctx.setThumb(bool(enabled))

    # ---------------------------------------------------------- syscall hooks

    def hook_syscall(
        self, number: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        if number in self._syscall_hooks:
            raise exceptions.ConfigurationError(
                f"Already have a syscall hook for {number}"
            )
        self._syscall_hooks[number] = function

    def unhook_syscall(self, number: int) -> None:
        if number not in self._syscall_hooks:
            raise exceptions.ConfigurationError(f"No syscall hook for {number}")
        del self._syscall_hooks[number]

    def hook_syscalls(
        self, function: typing.Callable[[emulator.Emulator, int], None]
    ) -> None:
        if self._all_syscalls_hook is not None:
            raise exceptions.ConfigurationError("Already have a global syscall hook")
        self._all_syscalls_hook = function

    def unhook_syscalls(self) -> None:
        if self._all_syscalls_hook is None:
            raise exceptions.ConfigurationError("No global syscall hook registered")
        self._all_syscalls_hook = None

    # ------------------------------------------------- taint (backend-specific)

    def taint_register(self, name: str) -> None:
        """Mark a register as tainted (Triton-specific escape hatch)."""
        self.ctx.taintRegister(self._reg(name))

    def untaint_register(self, name: str) -> None:
        """Clear taint on a register (Triton-specific escape hatch)."""
        self.ctx.untaintRegister(self._reg(name))

    def is_register_tainted(self, name: str) -> bool:
        """Report whether a register is tainted (Triton-specific escape hatch)."""
        return bool(self.ctx.isRegisterTainted(self._reg(name)))

    def taint_memory(self, address: int, size: int = 1) -> None:
        """Mark ``size`` bytes of memory as tainted (Triton-specific)."""
        for offset in range(size):
            self.ctx.taintMemory(address + offset)

    def untaint_memory(self, address: int, size: int = 1) -> None:
        """Clear taint on ``size`` bytes of memory (Triton-specific)."""
        for offset in range(size):
            self.ctx.untaintMemory(address + offset)

    def is_memory_tainted(self, address: int, size: int = 1) -> bool:
        """Report whether any of ``size`` bytes of memory is tainted (Triton-specific)."""
        return any(
            bool(self.ctx.isMemoryTainted(address + offset)) for offset in range(size)
        )

    # ------------------------------------------------------------- lifecycle

    def __repr__(self) -> str:
        return f"TritonEmulator(platform={self.platform})"


__all__ = ["TritonEmulator", "TritonEmulationError"]
