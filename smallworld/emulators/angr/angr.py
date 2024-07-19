from __future__ import annotations

import io
import logging
import typing

import angr
import claripy
import cle

from ... import exceptions, state
from .. import emulator
from .default import configure_default_plugins, configure_default_strategy
from .factory import PatchedObjectFactory
from .machdefs import AngrMachineDef

log = logging.getLogger(__name__)


class HookHandler(angr.SimProcedure):
    """SimProcedure for implementing "finish" hooks.

    This requires a callback as an extra kwarg.
    """

    def run(self, *args, callback, parent):
        emu = AngrHookEmulator(self.state, parent)
        callback(emu)
        return None


class AngrEmulator(emulator.Emulator):
    """
    Angr symbolic execution emulator

    This is primarily designed to support symbolic execution,
    although subclasses can configure angr however they like.

    One challenge with symbolic execution is that
    it doesn't work on a single machine state,
    but rather multiple machine states representing
    parallel execution paths.

    As such, this interface doesn't yet fully support
    all features of the base Emulator class;
    it's not clear what reading or writing machine state
    means when there's more than one state.
    """

    PAGE_SIZE = 4096

    def __init__(self, arch: str, mode: str, byteorder: str, preinit=None, init=None):
        # Dirty bit; tells us if we've started emulation
        self._dirty: bool = False

        # Linear mode bit; tells us if we're running in forced linear execution
        self._linear: bool = False

        # Plugin preset; tells us which plugin preset to use.
        self._plugin_preset = "default"

        # Locate the angr machine definition
        self.machdef: AngrMachineDef = AngrMachineDef.for_arch(arch, mode, byteorder)

        # Create an angr project using a blank byte stream,
        # and registered as self-modifying so we can load more code later.
        options = {"arch": self.machdef.angr_arch, "backend": "blob"}
        stream = io.BytesIO(b"")
        loader = cle.Loader(stream, main_opts=options)
        self.proj: angr.Project = angr.Project(
            loader, engine=self.machdef.angr_engine, selfmodifying_code=True
        )
        # Override the default factory
        self.proj.factory = PatchedObjectFactory(
            self.proj, type(self.proj.factory.default_engine)
        )

        # Configure default plugin preset.
        # Do this before creating the state, so the state inherits the correct preset.
        # Also do this before preinit, so that analyses can inherit from the default.
        configure_default_plugins(self)

        # If preinit is specified, run it.
        if preinit is not None:
            preinit(self)

        # Create a completely blank entry state
        self.state = self.proj.factory.blank_state(
            plugin_preset=self._plugin_preset,
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            },
            remove_options={
                angr.options.SIMPLIFY_CONSTRAINTS,
                angr.options.SIMPLIFY_EXIT_GUARD,
                angr.options.SIMPLIFY_EXIT_STATE,
                angr.options.SIMPLIFY_EXIT_TARGET,
                angr.options.SIMPLIFY_EXPRS,
                angr.options.SIMPLIFY_MEMORY_READS,
                angr.options.SIMPLIFY_MEMORY_WRITES,
                angr.options.SIMPLIFY_REGISTER_READS,
                angr.options.SIMPLIFY_REGISTER_WRITES,
            },
        )

        # Create a simulation manager for our entry state
        self.mgr = self.proj.factory.simulation_manager(self.state, save_unsat=True)

        # Configure default simulation strategy.
        configure_default_strategy(self)

        # If we have an init runner, run it.
        if init:
            init(self)

    def get_pages(self, num_pages: int) -> int:
        raise NotImplementedError("Dynamic allco not implemented for angr.")

    def read_register(self, name: str):
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Reading registers not supported once execution begins."
            )
        if name == "pc":
            name = self.machdef.pc_reg
        try:
            (off, size) = self.machdef.angr_reg(name)
            out = self.state.registers.load(off, size)
            if out.symbolic:
                log.warn(f"Register {name} is symbolic: {out}")
                return None
            else:
                return out.concrete_value
        except ValueError:
            # TODO: Handle invalid registers more gracefully
            return None

    def write_register(
        self,
        reg: str,
        value: typing.Optional[int],
        label: typing.Optional[typing.Any] = None,
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )
        if value is not None:
            if reg == "pc":
                reg = self.machdef.pc_reg
            (off, size) = self.machdef.angr_reg(reg)
            v = claripy.BVV(value, size * 8)
            self.state.registers.store(off, v)

    def read_memory(self, addr: int, size: int):
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Reading memory not supported once execution begins."
            )
        v = self.state.memory.load(addr, size)
        if v.symbolic:
            log.warn(f"Memory at {hex(addr)} ({size} bytes) is symbolic: {v}")
            return None
        # Annoyingly, there isn't an easy way to convert BVV to bytes.
        return bytes([v.get_byte(i).concrete_value for i in range(0, size)])

    def write_memory(
        self,
        addr: int,
        value: typing.Optional[bytes],
        label: typing.Optional[typing.Dict[int, typing.Tuple[int, typing.Any]]] = None,
    ):
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing memory not supported once execution begins."
            )
        prev_end = 0
        if label is None:
            label = dict()
        if value is None:
            log.warn(f"Backing memory at {hex(addr)} is not initialized")

        items = list(label.items())
        items.sort(key=lambda x: x[0])
        for off, (lab_size, name) in label.items():
            if off > prev_end and value is not None:
                # Account for any unlabeled bits.
                v = claripy.BVV(value[prev_end:off])
                self.state.memory.store(addr + off, v)
            if isinstance(name, str):
                # Store a symbol containing the label
                s = claripy.BVS(name, lab_size * 8, explicit_name=True)
                self.state.memory.store(addr + off, s)
                if value is not None:
                    # If we have a value, bind the value to the symbol
                    v = claripy.BVV(value[off : off + lab_size])
                    self.state.solver.add(v == s)
            else:
                log.warn(
                    f"Cannot handle non-string labels; not applying label for {hex(addr + off)}"
                )
                if value is not None:
                    v = claripy.BVV(value[off : off + lab_size])
                    self.state.memory.store(addr + off, v)

            if off + lab_size > prev_end:
                prev_end = off + lab_size

        if value is not None and prev_end < len(value):
            # Account for any missing bit on the tail
            v = claripy.BVV(value[prev_end:])
            self.state.memory.store(addr + prev_end, v)

    def load(self, code: state.Code) -> None:
        # Check if code matches our configuration
        if code.arch is None:
            raise ValueError(f"arch is required: {code}")
        if code.mode is None:
            raise ValueError(f"mode is required: {code}")

        if code.arch != self.machdef.arch:
            raise ValueError(f"Expected arch {self.machdef.arch}; code has {code.arch}")
        if code.mode != self.machdef.mode:
            raise ValueError(f"Expected mode {self.machdef.mode}; code has {code.mode}")

        if code.format != "blob":
            raise NotImplementedError(f"Can only handle blob code, not {code.format}")

        # Remember the code boundaries so we can stop cleanly
        self.state.scratch.bounds.extend(code.bounds)

        # Load the code into memory
        self.state.memory.store(code.base, code.image)

    def hook(
        self,
        address: int,
        callback: typing.Callable[[emulator.Emulator], None],
        finish: bool = False,
    ) -> None:
        if finish:
            # Use the power of SimProcedures to finish out the frame once we're done
            hook = HookHandler(callback=callback, parent=self)
            self.proj.hook(address, hook, 0)
        else:
            # Otherwise, hook our one instruction
            @self.proj.hook(address, length=0)
            def hook_handler(state):
                emu = AngrHookEmulator(state, self)
                callback(emu)

    def hook_memory(
        self,
        address: int,
        size: int,
        on_read: typing.Optional[
            typing.Callable[[emulator.Emulator, int, int], bytes]
        ] = None,
        on_write: typing.Optional[
            typing.Callable[[emulator.Emulator, int, int, bytes], None]
        ] = None,
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )

        if on_read is None and on_write is None:
            raise exceptions.AnalysisError(
                "Must specify at least one callback to hook_memory"
            )

        if on_read is not None:

            def read_condition(state):
                read_addr = state.inspect.mem_read_address
                if not isinstance(read_addr, int):
                    if read_addr.symbolic:
                        try:
                            values = state.solver.eval_atmost(read_addr, 1)
                            # Truly unbound address.  Assume it's not MMIO.
                            if len(values) < 1:
                                return False
                            read_addr = values[0]
                        except angr.errors.SimUnsatError:
                            return False
                        except angr.errors.SimValueError:
                            return False
                    else:
                        read_addr = read_addr.concrete_value
                read_size = state.inspect.mem_read_length

                return (
                    read_size is not None
                    and address <= read_addr
                    and address + size >= read_addr + read_size
                )

            def read_callback(state):
                addr = state.inspect.mem_read_address
                if not isinstance(addr, int):
                    addr = addr.concrete_value
                size = state.inspect.mem_read_length

                res = claripy.BVV(on_read(AngrHookEmulator(state, self), addr, size))

                if self.machdef.byteorder == "little":
                    # Fix byte order if needed.
                    # I don't know _why_ this is needed,
                    # but encoding the result as little-endian on a little-endian
                    # system produces the incorrect value in the machine state.
                    res = claripy.Reverse(res)
                state.inspect.mem_read_expr = res

            self.state.inspect.b(
                "mem_read",
                when=angr.BP_AFTER,
                condition=read_condition,
                action=read_callback,
            )

        if on_write is not None:

            def write_condition(state):
                write_addr = state.inspect.mem_write_address
                if not isinstance(write_addr, int):
                    if write_addr.symbolic:
                        # Need to use the solver to resolve this.
                        try:
                            values = state.solver.eval_atmost(write_addr, 1)
                            if len(values) < 1:
                                return False
                            write_addr = values[0]
                        except angr.errors.SimUnsatError:
                            return False
                        except angr.errors.SimValueError:
                            return False
                    else:
                        write_addr = write_addr.concrete_value
                write_size = state.inspect.mem_write_length

                return (
                    write_size is not None
                    and address <= write_addr
                    and address + size >= write_addr + write_size
                )

            def write_callback(state):
                addr = state.inspect.mem_write_address
                if not isinstance(addr, int):
                    addr = addr.concrete_value
                size = state.inspect.mem_write_length
                expr = state.inspect.mem_write_expr
                if expr.symbolic:
                    # Have the solver handle binding resolution for us.
                    try:
                        values = state.solver.eval_atmost(expr, 1)
                        if len(values) < 1:
                            raise exceptions.AnalysisError(
                                f"No possible values fpr {expr}"
                            )
                        value = values[0].to_bytes(
                            size, byteorder=self.machdef.byteorder
                        )
                        log.info("Collapsed symbolic {expr} to {values[0]:x} for MMIO")
                    except angr.errors.SimUnsatError:
                        raise exceptions.AnalysisError(f"No possible values for {expr}")
                    except angr.errors.SimValueError:
                        raise exceptions.AnalysisError(
                            f"Unbound value for MMIO write to {hex(addr)}: {expr}"
                        )
                else:
                    value = expr.concrete_value.to_bytes(
                        size, byteorder=self.machdef.byteorder
                    )

                on_write(AngrHookEmulator(state, self), addr, size, value)

            self.state.inspect.b(
                "mem_write",
                when=angr.BP_BEFORE,
                condition=write_condition,
                action=write_callback,
            )

    def step(self, single_insn: bool = False):
        # As soon as we start executing, disable value access
        self._dirty = True
        if self._linear:
            log.info(f"Stepping through {self.state.block().disassembly.insns[0]}")

        # Step execution once
        if single_insn:
            if not self.machdef.supports_single_step:
                raise exceptions.AnalysisError(
                    f"AngrEmulator does not support single-instruction stepping for {self.machdef.arch}:{self.machdef.mode}:{self.machdef.byteorder}"
                )
            num_inst = 1
        else:
            num_inst = None
        self.mgr.step(num_inst=num_inst, thumb=self.machdef.is_thumb)

        # Test for exceptional states
        if len(self.mgr.errored) > 0:
            raise exceptions.EmulationError(
                self.mgr.errored[0].error
            ) from self.mgr.errored[0].error

        # Handle linear execution mode
        if self._linear:
            if len(self.mgr.active) > 1:
                log.warn("Path diverged!  Detailes stored in simulation manager.")
                return True
            elif len(self.mgr.active) > 0:
                self.state = self.mgr.active[0]
            elif len(self.mgr.deadended) > 0:
                self.state = self.mgr.deadended[0]
            elif len(self.mgr.unconstrained) > 0:
                self.state = self.mgr.unconstrained[0]
            else:
                raise exceptions.AnalysisError(
                    "No states in expected stashes for linear execution"
                )

        # Filter out exited or invalid states
        self.mgr.move(
            from_stash="active",
            to_stash="unconstrained",
            filter_func=lambda x: (x._ip.symbolic),
        )

        def filter_func(state):
            for bound in self.state.scratch.bounds:
                if state._ip.concrete_value in bound:
                    return False
            return True

        self.mgr.move(
            from_stash="active", to_stash="deadended", filter_func=filter_func
        )

        # Stop if we're out of active states
        return len(self.mgr.active) == 0

    def run(self):
        log.info("Starting angr run")
        while len(self.mgr.active) > 0:
            # Continue stepping as long as we have steps.
            if self.step():
                break

    def enable_linear(self):
        """Enable linear execution

        This doesn't actually concretize anything;
        it just kills execution when it hits an unconstrained branch.
        """
        if self._dirty:
            raise NotImplementedError(
                "Enabling linear mode not supported once execution begins"
            )
        self._linear = True
        log.warn("Linear execution mode enabled")

    def __repr__(self):
        return f"Angr ({self.mgr})"


class AngrHookEmulator(AngrEmulator):
    """
    "Emulator" for angr state access

    The primary AngrEmulator class is designed for symbolic execution;
    it represents many states being explored in parallel.
    As such, the notion of accessing state doesn't work; which state do you want?

    For hook evaluation, we do need an emulator-like object
    that can access a single state.  Hence, this wrapper class.
    """

    @property
    def PAGE_SIZE(self):
        # Page Size should be inherited from the parent.
        return self.pagesize

    def __init__(self, state: angr.SimState, parent: AngrEmulator):
        self._dirty = False
        self.state: angr.SimState = state

        self.machdef: AngrMachineDef = parent.machdef
        self.pagesize: int = parent.PAGE_SIZE

    def get_pages(self, num_pages: int) -> int:
        raise NotImplementedError("Dynamic alloc not implemented for angr")

    def load(self, code: state.Code) -> None:
        # TODO: Look into dynamic code loading
        # I bet angr supports this, I have no idea how.
        # Before I spend time on this, what's your use case?
        raise NotImplementedError("Loading new code not implemented inside a hook.")

    def hook(
        self,
        address: int,
        callback: typing.Callable[[emulator.Emulator], None],
        finish: bool = False,
    ) -> None:
        # TODO: I'm 90% of the way to handling runtime code loading
        # The problem is capturing code bounds;
        # I currently use a global array to test code bounds.
        # I can probably tie 'bounds' to the angr state.
        raise NotImplementedError("Hooking not implemented inside a hook.")

    def run(self) -> None:
        raise NotImplementedError("Running not supported inside a hook.")

    def step(self, single_insn=False) -> bool:
        raise NotImplementedError("Stepping not supported inside a hook.")

    def __repr__(self):
        return f"Angr Hook ({self.state})"
