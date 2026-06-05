"""SmallWorld Emulator backend backed by the Styx firmware emulator.

Styx (https://github.com/styx-emulator/styx-emulator) is a Rust framework
exposed to Python via the ``styx_emulator`` maturin wheel. It targets specific
firmware platforms (STM32F107, Kinetis21, Bf512, etc.) rather than generic
ISA emulation, so a SmallWorld harness picks the closest Styx target via the
machdef table — see ``smallworld/emulators/styx/machdefs/``.

Notable differences from the Unicorn / Ghidra backends:

- **Lazy build**: the underlying ``Processor`` is built on first step/run so
  that ``map_memory`` and pre-flight register/memory writes accumulate into
  the builder. Once built, registration order doesn't matter — hooks and
  writes are routed straight through to the live processor.
- **No symbolic values**: ``SymbolicValueError`` for any ``claripy`` input.
- **32-bit ARM only**: ``ConfigurationError`` for anything else (Styx has no
  x86 or 64-bit ARM target).
- **Function hooks short-circuit the body**: ``hook_function(addr, fn)``
  installs a code hook at ``addr`` whose callback runs the user function then
  jumps PC to the link register. This matches the Unicorn backend's semantics
  for the ``hooking`` test family but does *not* let inspection callbacks
  continue executing the original body.
"""

from __future__ import annotations

import logging
import tempfile
import typing

import claripy

from ... import exceptions, platforms, utils
from .. import emulator, hookable
from .machdefs import StyxMachineDef

logger = logging.getLogger(__name__)


# Styx Python bindings are optional — when not installed (e.g. in a slim
# devshell) importing this module would otherwise break SmallWorld entirely.
#
# Note: as of styx_emulator 1.2.0 the pyi-declared ``TargetExitReason`` enum
# is not exposed as a runtime Python class; the ``exit_reason`` attribute on
# an ``EmulationReport`` is an opaque enum object whose ``repr()`` contains
# the variant name. We translate those names to SmallWorld exceptions by
# string matching at runtime instead of importing the type.
try:
    from styx_emulator.cpu.hooks import (
        CodeHook,
        InterruptHook,
        MemoryReadHook,
        MemoryWriteHook,
    )
    from styx_emulator.executor import DefaultExecutor
    from styx_emulator.loader import RawLoader
    from styx_emulator.processor import ProcessorBuilder

    _STYX_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on which extras are installed
    _STYX_AVAILABLE = False


class StyxEmulationError(exceptions.EmulationError):
    """Raised for Styx-specific failures that don't map cleanly to an existing
    SmallWorld emulation exception."""


# Map from the string form of Styx's TargetExitReason enum variants to the
# SmallWorld exception (or ``None`` for normal stops). The string form is
# whatever ``repr(report.exit_reason)`` produces — we accept any of the
# variants we know about and fall through to a generic StyxEmulationError
# for anything unrecognised. Keeping this as a dict-of-strings means the
# module loads cleanly even when styx_emulator is absent.
_EXIT_REASON_EXCEPTIONS: typing.Dict[str, typing.Optional[type]] = {
    "InstructionCountComplete": None,
    "ExecutionTimeoutComplete": None,
    "HostStopRequest": None,
    "UnmappedMemoryFetch": exceptions.EmulationFetchUnmappedFailure,
    "UnmappedMemoryRead": exceptions.EmulationReadUnmappedFailure,
    "UnmappedMemoryWrite": exceptions.EmulationWriteUnmappedFailure,
    "ProtectedMemoryFetch": exceptions.EmulationFetchProtectedFailure,
    "ProtectedMemoryRead": exceptions.EmulationReadProtectedFailure,
    "ProtectedMemoryWrite": exceptions.EmulationWriteProtectedFailure,
    "UnalignedMemoryFetch": exceptions.EmulationFetchUnalignedFailure,
    "UnalignedMemoryRead": exceptions.EmulationReadUnalignedFailure,
    "UnalignedMemoryWrite": exceptions.EmulationWriteUnalignedFailure,
    "IllegalInstruction": exceptions.EmulationExecInvalidFailure,
    "InstructionDecodeError": exceptions.EmulationExecInvalidFailure,
}


def _exit_reason_name(reason: typing.Any) -> str:
    """Best-effort extraction of the variant name from a Styx exit_reason."""
    if reason is None:
        return ""
    text = repr(reason)
    # PyO3 enums commonly stringify as e.g. ``TargetExitReason.UnmappedMemoryRead``
    # or just ``UnmappedMemoryRead`` depending on bindings version.
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text.strip().strip("'\"")


class StyxEmulator(
    emulator.Emulator,
    hookable.QInstructionHookable,
    hookable.QFunctionHookable,
    hookable.QMemoryReadHookable,
    hookable.QMemoryWriteHookable,
    hookable.QInterruptHookable,
):
    """Concrete 32-bit-ARM Styx emulator backend for SmallWorld."""

    name = "styx-emulator"
    description = "emulator based on the styx-emulator firmware emulation framework"
    version = "0.1.0"

    # Address range used when registering a "every instruction" CodeHook with
    # Styx. Styx's hook model is range-based so we approximate by hooking the
    # full 32-bit address space.
    _GLOBAL_HOOK_END = 0xFFFFFFFF

    def __init__(self, platform: platforms.Platform):
        if not _STYX_AVAILABLE:
            raise exceptions.ConfigurationError(
                "styx_emulator is not installed; install smallworld with the "
                "[emu-styx] extra (built from source via the nix flake)."
            )
        super().__init__(platform)
        self.platform: platforms.Platform = platform
        self.machdef: StyxMachineDef = StyxMachineDef.for_platform(platform)

        # The Styx processor isn't built yet — we accumulate setup operations
        # in the builder until the first execution call.
        self._builder = ProcessorBuilder()
        self._builder.loader = RawLoader()
        self._builder.executor = DefaultExecutor()
        self._builder.backend = self.machdef.backend
        # RawLoader needs *some* program to chew on; an empty payload lets the
        # caller write code via ``write_code`` after build. We use a tempfile
        # because the binding expects a path string for ``target_program``.
        self._stub_program = tempfile.NamedTemporaryFile(
            prefix="styx_smallworld_stub_", suffix=".bin", delete=False
        )
        self._stub_program.write(b"\x00\x00\x00\x00")
        self._stub_program.flush()
        self._builder.target_program = self._stub_program.name

        self._proc: typing.Optional[typing.Any] = None
        self._memory_map: utils.RangeCollection = utils.RangeCollection()
        self._pending_writes: typing.List[typing.Tuple[int, bytes, bool]] = (
            []
        )  # (address, data, is_code)
        self._pending_register_writes: typing.List[typing.Tuple[str, int]] = []
        # Hooks queued for post-build registration. Builder-level hooks are
        # acceptable too but post-build registration via Processor.add_hook
        # works for both timings.
        self._pending_hooks: typing.List[typing.Any] = []
        # Whether the last stop was triggered by an internal exit-point hook
        # (so ``run`` knows to raise EmulationExitpoint).
        self._stopped_for_exit: bool = False
        # Tracks which exit points already have their internal CodeHook
        # installed so we don't add duplicates on subsequent runs.
        self._installed_exit_points: typing.Set[int] = set()

    # ------------------------------------------------------------------ build

    def _lazy_build(self) -> None:
        """Build the underlying Styx Processor if it hasn't been built yet,
        then replay any state that was queued while the builder was open."""
        if self._proc is not None:
            self._sync_exit_points()
            return

        self._proc = self._builder.build(self.machdef.target)

        for addr, data, is_code in self._pending_writes:
            self._do_write(addr, data, is_code=is_code)
        self._pending_writes.clear()

        for name, value in self._pending_register_writes:
            self._do_write_register(name, value)
        self._pending_register_writes.clear()

        for hook in self._pending_hooks:
            self._proc.add_hook(hook)
        self._pending_hooks.clear()

        self._sync_exit_points()

    def get_processor(self) -> typing.Any:
        """Return the underlying ``styx_emulator.Processor``, building it if needed.

        Advanced escape hatch for callers (notably the AFL fuzz bridge) that
        need a live ``Processor`` handle to pass to ``styxafl``. Triggers
        :meth:`_lazy_build` so any queued state is flushed before the handle
        is returned.
        """
        self._lazy_build()
        assert self._proc is not None  # _lazy_build set it
        return self._proc

    def _sync_exit_points(self) -> None:
        """Install internal CodeHooks at every exit point the user has added
        since the last sync. The callback flips ``_stopped_for_exit`` and asks
        the CPU to stop."""
        if self._proc is None:
            return
        for addr in self._exit_points - self._installed_exit_points:

            def _exit_cb(_cpu, _addr=addr, _self=self):
                _self._stopped_for_exit = True
                _cpu.stop()

            self._proc.add_hook(CodeHook(addr, addr, _exit_cb))
            self._installed_exit_points.add(addr)

    # ---------------------------------------------------------------- helpers

    def _do_write(self, address: int, data: bytes, *, is_code: bool) -> None:
        assert self._proc is not None
        if is_code:
            self._proc.write_code(address, data)
        else:
            self._proc.write_data(address, data)

    def _do_write_register(self, name: str, value: int) -> None:
        assert self._proc is not None
        reg = self.machdef.styx_register(name)
        # The Styx pyi names the single-register-write method ``write_registers``
        # despite operating on one register at a time.
        self._proc.write_registers(reg, int(value))

    # --------------------------------------------------------------- registers

    def read_register_content(self, name: str) -> int:
        self._lazy_build()
        reg = self.machdef.styx_register(name)
        assert self._proc is not None  # _lazy_build set it
        value = self._proc.read_register(reg)
        if value is None:
            raise exceptions.UnsupportedRegisterError(
                f"Styx returned no value for register '{name}'"
            )
        return int(value)

    def write_register_content(
        self, name: str, content: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        if content is None:
            return
        if isinstance(content, claripy.ast.bv.BV):
            raise exceptions.SymbolicValueError(
                "StyxEmulator is a concrete emulator; symbolic values are not supported"
            )
        if not isinstance(content, int):
            raise TypeError(f"Cannot write register '{name}' with non-int value")
        if self._proc is None:
            # Queue until build; we still validate the register name eagerly so
            # callers get an immediate error for typos.
            _ = self.machdef.styx_register(name)
            self._pending_register_writes.append((name, int(content)))
        else:
            self._do_write_register(name, int(content))

    # ------------------------------------------------------------------ memory

    def read_memory_content(self, address: int, size: int) -> bytes:
        self._lazy_build()
        # ``read_data`` is the primary entry point; for code regions the user
        # may have written via ``write_code`` we still expect ``read_data`` to
        # return the unified backing memory in styx's flat AS targets.
        assert self._proc is not None  # _lazy_build set it
        return bytes(self._proc.read_data(address, size))

    def write_memory_content(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ) -> None:
        if isinstance(content, claripy.ast.bv.BV):
            raise exceptions.SymbolicValueError(
                "StyxEmulator is a concrete emulator; symbolic values are not supported"
            )
        data = bytes(content)
        if self._proc is None:
            self._pending_writes.append((address, data, False))
        else:
            self._do_write(address, data, is_code=False)

    def write_code(self, address: int, content: bytes) -> None:
        data = bytes(content)
        if self._proc is None:
            self._pending_writes.append((address, data, True))
        else:
            self._do_write(address, data, is_code=True)

    def map_memory(self, address: int, size: int) -> None:
        # Styx targets pre-declare their memory layout, so map_memory becomes
        # a bookkeeping operation. We track the range so ``get_memory_map``
        # reports a consistent view to the rest of SmallWorld.
        self._memory_map.add_range((address, address + size))

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        return list(self._memory_map.ranges)

    # ------------------------------------------------------------ exit points

    def add_exit_point(self, address: int) -> None:
        super().add_exit_point(address)
        # If the processor is already built, install the hook immediately so
        # the next run/step honors the new exit point.
        if self._proc is not None:
            self._sync_exit_points()

    # -------------------------------------------------------------- execution

    def _translate_exit(self, report: typing.Any) -> None:
        """Translate a Styx ``EmulationReport`` into a SmallWorld exception
        (if applicable) and reset transient state."""
        if self._stopped_for_exit:
            self._stopped_for_exit = False
            raise exceptions.EmulationExitpoint(
                f"exit point reached at pc={hex(self._safe_pc())}"
            )

        reason = report.exit_reason
        name = _exit_reason_name(reason)
        if name in _EXIT_REASON_EXCEPTIONS:
            exc_cls = _EXIT_REASON_EXCEPTIONS[name]
            if exc_cls is None:
                return
            pc = self._safe_pc()
            if issubclass(exc_cls, exceptions.EmulationExecInvalidFailure):
                raise exc_cls(f"styx exit reason: {name}", pc, None)
            if issubclass(exc_cls, exceptions.EmulationFailure):
                raise exc_cls(f"styx exit reason: {name}", pc)
            raise StyxEmulationError(f"unhandled styx exit reason: {name}")
        # Unknown reason — if the report says it was fatal, surface a
        # generic Styx error; otherwise treat as normal stop.
        is_fatal = bool(getattr(report, "is_fatal", False))
        if is_fatal:
            raise StyxEmulationError(
                f"styx emulation failed: exit_reason={name or reason!r}"
            )

    def _safe_pc(self) -> int:
        try:
            assert self._proc is not None
            return int(self._proc.pc)
        except Exception:
            return 0

    def step_instruction(self) -> None:
        self._lazy_build()
        self._stopped_for_exit = False
        proc = self._proc
        assert proc is not None  # _lazy_build set it
        proc.start(inst=1)
        report = proc.wait_for_stop()
        self._translate_exit(report)

    def step_block(self) -> None:
        # Styx has no native "single block" step; approximate by installing a
        # one-shot BlockHook that stops the CPU on the *next* block boundary
        # after the current one.
        self._lazy_build()
        try:
            from styx_emulator.cpu.hooks import BlockHook
        except ImportError as e:
            raise exceptions.ConfigurationError(
                "styx_emulator does not expose BlockHook in this build"
            ) from e
        state = {"first_seen": False, "token": None}

        def _on_block(cpu, _addr, _size):
            if not state["first_seen"]:
                state["first_seen"] = True
                return
            cpu.stop()

        hook = BlockHook(_on_block)
        proc = self._proc
        assert proc is not None  # _lazy_build set it above
        token = proc.add_hook(hook)
        state["token"] = token
        try:
            proc.start()
            report = proc.wait_for_stop()
            self._translate_exit(report)
        finally:
            try:
                proc.delete_hook(state["token"])
            except Exception:
                pass

    def run(self) -> None:
        self._lazy_build()
        self._stopped_for_exit = False
        proc = self._proc
        assert proc is not None  # _lazy_build set it above
        proc.start()
        report = proc.wait_for_stop()
        self._translate_exit(report)

    # ----------------------------------------------------------------- hooks

    def _register_styx_hook(self, hook: typing.Any) -> typing.Any:
        if self._proc is None:
            self._pending_hooks.append(hook)
            return None
        return self._proc.add_hook(hook)

    def hook_instruction(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        super().hook_instruction(address, function)

        def _cb(_cpu, _self=self, _fn=function):
            _fn(_self)

        self._register_styx_hook(CodeHook(address, address, _cb))

    def hook_instructions(
        self, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        super().hook_instructions(function)

        def _cb(_cpu, _self=self, _fn=function):
            _fn(_self)

        self._register_styx_hook(CodeHook(0x0, self._GLOBAL_HOOK_END, _cb))

    def hook_function(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        super().hook_function(address, function)
        lr_name = self.machdef.lr_register

        def _cb(cpu, _self=self, _fn=function, _lr=lr_name):
            _fn(_self)
            if _lr is None:
                return
            # Step out of the hooked function by jumping to the link register.
            # Mask the Thumb bit if present so PC stays aligned.
            try:
                ret = cpu.read_register(_lr)
            except Exception:
                ret = None
            if ret is None:
                return
            cpu.write_register("pc", int(ret) & ~0x1)

        self._register_styx_hook(CodeHook(address, address, _cb))

    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[
            [emulator.Emulator, int, int, bytes], typing.Optional[bytes]
        ],
    ) -> None:
        super().hook_memory_read(start, end, function)

        def _cb(_cpu, addr, size, data, _self=self, _fn=function):
            # Styx's read-hook return values are ignored by the C backend; we
            # forward the call but discard any substitute the user returns.
            _fn(_self, int(addr), int(size), bytes(data))

        self._register_styx_hook(MemoryReadHook(start, end, _cb))

    def hook_memory_reads(
        self,
        function: typing.Callable[
            [emulator.Emulator, int, int, bytes], typing.Optional[bytes]
        ],
    ) -> None:
        super().hook_memory_reads(function)

        def _cb(_cpu, addr, size, data, _self=self, _fn=function):
            _fn(_self, int(addr), int(size), bytes(data))

        self._register_styx_hook(MemoryReadHook(0x0, self._GLOBAL_HOOK_END, _cb))

    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[emulator.Emulator, int, int, bytes], None],
    ) -> None:
        super().hook_memory_write(start, end, function)

        def _cb(_cpu, addr, size, data, _self=self, _fn=function):
            _fn(_self, int(addr), int(size), bytes(data))

        self._register_styx_hook(MemoryWriteHook(start, end, _cb))

    def hook_memory_writes(
        self,
        function: typing.Callable[[emulator.Emulator, int, int, bytes], None],
    ) -> None:
        super().hook_memory_writes(function)

        def _cb(_cpu, addr, size, data, _self=self, _fn=function):
            _fn(_self, int(addr), int(size), bytes(data))

        self._register_styx_hook(MemoryWriteHook(0x0, self._GLOBAL_HOOK_END, _cb))

    def hook_interrupts(
        self, function: typing.Callable[[emulator.Emulator, int], bool]
    ) -> None:
        super().hook_interrupts(function)

        def _cb(_cpu, intno, _self=self):
            handler = _self.interrupt_hooks.get(int(intno))
            if handler is not None:
                handler(_self)
                return
            if _self.all_interrupts_hook is not None:
                _self.all_interrupts_hook(_self, int(intno))

        self._register_styx_hook(InterruptHook(_cb))

    def hook_interrupt(
        self, intno: int, function: typing.Callable[[emulator.Emulator], bool]
    ) -> None:
        super().hook_interrupt(intno, function)
        # If a global interrupt hook is already installed it will dispatch into
        # ``self.interrupt_hooks``. Otherwise install one now so per-number
        # hooks fire too.
        if self.all_interrupts_hook is None and not self._has_styx_interrupt_hook():
            self._install_baseline_interrupt_hook()

    def _has_styx_interrupt_hook(self) -> bool:
        # Track once-only installation via an attribute so we don't double up
        # on processor-level interrupt hooks.
        return getattr(self, "_styx_interrupt_hook_installed", False)

    def _install_baseline_interrupt_hook(self) -> None:
        def _cb(_cpu, intno, _self=self):
            handler = _self.interrupt_hooks.get(int(intno))
            if handler is not None:
                handler(_self)

        self._register_styx_hook(InterruptHook(_cb))
        self._styx_interrupt_hook_installed = True

    # ------------------------------------------------------------- lifecycle

    def __repr__(self) -> str:
        return f"StyxEmulator(platform={self.platform})"

    def __del__(self):
        try:
            import os

            if hasattr(self, "_stub_program") and self._stub_program is not None:
                try:
                    os.unlink(self._stub_program.name)
                except OSError:
                    pass
        except Exception:
            pass


__all__ = ["StyxEmulator", "StyxEmulationError"]
