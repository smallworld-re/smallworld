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
        Instruction,
        MemoryAccess,
        TritonContext,
    )

    _TRITON_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on installed extras
    _TRITON_AVAILABLE = False


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

    # -------------------------------------------------------------- execution

    def _translate_processing(self, rc: typing.Any, pc: int, inst: typing.Any) -> None:
        """Raise a SmallWorld exception if ``processing`` reported a fault."""
        if rc == EXCEPTION.NO_FAULT:
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

    def _dispatch_interrupt(self, inst: typing.Any) -> None:
        """Best-effort interrupt/syscall hook dispatch for the current insn."""
        if self.all_interrupts_hook is None and not self.interrupt_hooks:
            return
        try:
            mnemonic = inst.getDisassembly().split(None, 1)[0].lower()
        except Exception:
            return
        if mnemonic not in self.machdef.interrupt_mnemonics:
            return
        # Recover the interrupt number for x86 ``int N``; otherwise use 0.
        intno = 0
        if mnemonic == "int3":
            intno = 3
        elif mnemonic == "int":
            try:
                intno = int(inst.getOperands()[0].getValue())
            except Exception:
                intno = 0
        handler = self.is_interrupt_hooked(intno)
        if handler is not None:
            handler(self)
        elif self.all_interrupts_hook is not None:
            self.all_interrupts_hook(self, intno)

    def _check_pc(self, pc: int) -> None:
        """Raise if ``pc`` is an exit point or outside configured bounds."""
        if pc in self._exit_points:
            raise exceptions.EmulationExitpoint(f"exit point reached at pc={hex(pc)}")
        if not self._bounds.is_empty() and not self._bounds.contains_value(pc):
            raise exceptions.EmulationBounds(
                f"pc={hex(pc)} is outside the configured execution bounds"
            )

    def step_instruction(self) -> None:
        pc = self.read_register_content("pc")
        self._check_pc(pc)

        # Instruction hooks (global, then address-specific).
        if self.all_instructions_hook is not None:
            self.all_instructions_hook(self)
        insn_hook = self.is_instruction_hooked(pc)
        if insn_hook is not None:
            insn_hook(self)

        # Function hooks replace the body: run the hook, then return to caller.
        fn_hook = self.is_function_hooked(pc)
        if fn_hook is not None:
            fn_hook(self)
            self._return_from_function()
            self._last_instruction = None
            return

        opcode = bytes(
            self.ctx.getConcreteMemoryAreaValue(pc, self._MAX_INSN_BYTES, False)
        )
        inst = Instruction(pc, opcode)
        rc = self.ctx.processing(inst)
        self._translate_processing(rc, pc, inst)
        self._dispatch_interrupt(inst)
        self._last_instruction = inst

        new_pc = self.read_register_content("pc")
        if new_pc == pc and not inst.isControlFlow():
            # A non-branch instruction that didn't advance PC means execution
            # can make no further progress (e.g. HLT); treat as a clean stop.
            raise exceptions.EmulationExitpoint(
                f"execution halted at pc={hex(pc)} (pc did not advance)"
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
        while True:
            self.step_instruction()

    def _return_from_function(self) -> None:
        """Advance PC out of a hooked function using the platform's ABI."""
        if self.machdef.lr_register is not None:
            ret = self.read_register_content(self.machdef.lr_register)
            self.write_register_content("pc", ret & ~1)
        else:
            # x86 convention: pop the return address off the stack.
            sp = self.read_register_content(self.machdef.sp_register)
            data = self.read_memory_content(sp, self.machdef.address_size)
            ret = int.from_bytes(data, self._byteorder())
            self.write_register_content(
                self.machdef.sp_register, sp + self.machdef.address_size
            )
            self.write_register_content("pc", ret)

    # -------------------------------------------------------- memory callbacks

    def _on_memory_read(self, ctx: typing.Any, mem: typing.Any) -> None:
        if not self.memory_read_hooks and self.all_reads_hook is None:
            return
        address = mem.getAddress()
        size = mem.getSize()
        data = bytes(ctx.getConcreteMemoryAreaValue(address, size, False))
        replacement: typing.Optional[bytes] = None
        if self.all_reads_hook is not None:
            out = self.all_reads_hook(self, address, size, data)
            if out is not None:
                replacement = out
        hook = self.is_memory_read_hooked(address, size)
        if hook is not None:
            out = hook(self, address, size, data)
            if out is not None:
                replacement = out
        if replacement is not None:
            ctx.setConcreteMemoryAreaValue(address, bytes(replacement), False)

    def _on_memory_write(self, ctx: typing.Any, mem: typing.Any, value: int) -> None:
        if not self.memory_write_hooks and self.all_writes_hook is None:
            return
        address = mem.getAddress()
        size = mem.getSize()
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
