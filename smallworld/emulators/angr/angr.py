from __future__ import annotations

import io
import logging
import typing

import angr
import claripy
import cle

from ... import exceptions, platforms
from .. import emulator
from .default import configure_default_plugins, configure_default_strategy
from .factory import PatchedObjectFactory
from .machdefs import AngrMachineDef
from .simos import HookableSimOS

log = logging.getLogger(__name__)


class HookHandler(angr.SimProcedure):
    """SimProcedure for implementing "finish" hooks.

    This requires a callback as an extra kwarg.
    """

    def run(self, *args, callback, parent):
        emu = ConcreteAngrEmulator(self.state, parent)
        callback(emu)
        return None


class AngrEmulator(
    emulator.Emulator,
    emulator.InstructionHookable,
    emulator.FunctionHookable,
    emulator.SyscallHookable,
    emulator.MemoryReadHookable,
    emulator.MemoryWriteHookable,
):
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

    name = "angr-emulator"
    description = "an emulator using angr as its backend"
    version = "0.0"

    def __init__(self, platform: platforms.Platform, preinit=None, init=None):
        # Dirty bit; tells us if we've started emulation
        self._dirty: bool = False

        # Linear mode bit; tells us if we're running in forced linear execution
        self._linear: bool = False

        # Plugin preset; tells us which plugin preset to use.
        self._plugin_preset = "default"

        self.platform: platforms.Platform = platform

        # Locate the angr machine definition
        self.machdef: AngrMachineDef = AngrMachineDef.for_platform(platform)

        # Create an angr project using a blank byte stream,
        # and registered as self-modifying so we can load more code later.
        options = {"arch": self.machdef.angr_arch, "backend": "blob"}
        stream = io.BytesIO(b"")
        loader = cle.Loader(stream, main_opts=options)
        self.proj: angr.Project = angr.Project(
            loader,
            engine=self.machdef.angr_engine,
            selfmodifying_code=True,
            simos=HookableSimOS,
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
                # angr.options.BYPASS_UNSUPPORTED_SYSCALL,
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

    def read_register_content(self, name: str) -> int:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Reading registers not supported once execution begins."
            )
        if name == "pc":
            name = self.machdef.pc_reg
        (off, size) = self.machdef.angr_reg(name)
        out = self.state.registers.load(off, size)
        if out.symbolic:
            log.warn(f"Register {name} is symbolic: {out}")
            raise exceptions.SymbolicValueError(f"Register {name} is symbolic")
        else:
            return out.concrete_value

    def read_register_type(self, name: str) -> typing.Optional[typing.Any]:
        return None

    def read_register_label(self, name: str) -> typing.Optional[str]:
        # This considers all BVSs to be labeled values;
        # if it has a name, we're giving it to you.
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Reading register not supported once execution begins."
            )
        if name == "pc":
            name = self.machdef.pc_reg
        try:
            (off, size) = self.machdef.angr_reg(name)
            out = self.state.registers.load(off, size)
            if out.symbolic:
                if out.op == "BVS":
                    # This is a "pure" label; we can return it.
                    return out.args[0]
                else:
                    # This is a mixed expression; we can't return it
                    log.warn(f"Register {name} contains a symbolic expression: {out}")
                    raise exceptions.SymbolicValueError(
                        f"Register {name} contains a symbolic expression"
                    )
            else:
                # No propagated label
                return None
        except ValueError:
            # TODO: Handle invalid registers more gracefully
            return None

    def write_register_content(self, name: str, content: typing.Optional[int]) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )

        # This will replace any value - symbolic or otherwise - currently in the emulator.
        # Since labels are treated as symbolic values, it must be called before
        # write_register_label().
        if name == "pc":
            name = self.machdef.pc_reg
        (off, size) = self.machdef.angr_reg(name)
        if content is None:
            v = claripy.BVS("UNINITIALIZED", size * 8)
        else:
            v = claripy.BVV(content, size * 8)
        self.state.registers.store(off, v)

    def write_register_type(
        self, name: str, type: typing.Optional[typing.Any] = None
    ) -> None:
        pass

    def write_register_label(
        self, name: str, label: typing.Optional[str] = None
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )
        if label is None:
            return
        if name == "pc":
            name = self.machdef.pc_reg
        (off, size) = self.machdef.angr_reg(name)

        # This will bind whatever value is currently in the register
        # to a symbol named after the label
        # The same label will ALWAYS map to the same symbol!
        # This can introduce unintended restrictions on exploration,
        # or even a contradictory state.
        s = claripy.BVS(label, size * 8, explicit_name=True)
        v = self.state.registers.load(off, size)

        if not self.state.solver.satisfiable(extra_constraints=[v == s]):
            # Creating this binding will definitely cause a contradiction.
            # Have you already used this label somewhere else?
            raise exceptions.ConfigurationError(
                f"Contradiction binding register {name} to label {label}"
            )

        # Passing the last check doesn't guarantee you're safe.
        # There may be over-constraints.  Please be careful.
        self.state.registers.store(off, s)
        self.state.solver.add(v == s)

    def read_memory_content(self, address: int, size: int) -> bytes:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Reading memory not supported once execution begins."
            )
        v = self.state.memory.load(address, size)
        if v.symbolic:
            log.warn(f"Memory at {hex(address)} ({size} bytes) is symbolic: {v}")
            raise exceptions.SymbolicValueError(f"Memory at {hex(address)} is symbolic")

        # Annoyingly, there isn't an easy way to convert BVV to bytes.
        return bytes([v.get_byte(i).concrete_value for i in range(0, size)])

    def read_memory_type(self, address: int, size: int) -> typing.Optional[typing.Any]:
        return None

    def read_memory_label(self, address: int, size: int) -> typing.Optional[str]:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing memory not supported once execution begins."
            )
        v = self.state.memory.load(address, size)
        if v.symbolic():
            if v.op == "Extract":
                # You got a piece of a possibly-labeled expression
                # Try parsing the inner expression to see if it's a single symbol.
                v = v.args[2]

            if v.op == "BVS":
                # You got a single symbol; I'll treat it as a label
                return v.args[0]
            else:
                # You got a symbolic expression; I can't decode it further
                log.warn(f"Memory at {hex(address)} ({size} bytes) is symbolic: {v}")
                raise exceptions.SymbolicValueError(
                    f"Memory at {hex(address)} is symbolic"
                )
        else:
            # Definitely no labels here
            return None

    def map_memory(self, address: int, size: int) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Mapping memory not supported once execution begins."
            )
        # Unlike Unicorn, angr doesn't care about pages.
        region = (address, address + size)
        self.state.scratch.memory_map.add_range(region)

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Mapping memory not supported once execution begins."
            )
        return list(self.state.scratch.memory_map.ranges)

    def write_memory_content(self, address: int, content: bytes) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing memory not supported once execution begins."
            )
        log.info(f"Storing {len(content)} bytes at {hex(address)}")
        v = claripy.BVV(content)
        self.state.memory.store(address, v)

    def write_memory_type(
        self, address: int, size: int, type: typing.Optional[typing.Any] = None
    ) -> None:
        pass

    def write_memory_label(
        self, address: int, size: int, label: typing.Optional[str] = None
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing memory not supported once execution begins."
            )
        if label is None:
            return
        # This will bind whatever value is currently at this address
        # to a symbol named after the label
        #
        # The same label will ALWAYS map to the same symbol!
        # This can introduce unintended restrictions on exploration,
        # or even a contradictory state.
        #
        # This will trigger angr's default value computation,
        # which may cause spurious results in some analyses.
        s = claripy.BVS(label, size * 8, explicit_name=True)
        v = self.state.memory.load(address, size)
        if not self.state.solver.satisfiable(extra_constraints=[v == s]):
            # Creating this binding will definitely cause a contradiction.
            # Have you already used this label somewhere else?
            raise exceptions.ConfigurationError(
                f"Contradiction binding memory at {hex(address)} to label {label}"
            )

        # Passing the last check doesn't mean you're safe.
        # There may be over-constraints.  Please be careful.
        self.state.memory.store(address, s)
        self.state.solver.add(v == s)

    def hook_instruction(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Instruction hooking not supported once execution begins"
            )
        if address in self.state.scratch.insn_bps:
            raise exceptions.ConfigurationError(
                "Instruction at address {hex(address)} is already hooked"
            )

        def hook_handler(state):
            emu = ConcreteAngrEmulator(state, self)
            function(emu)

        bp = self.state.inspect.b(
            "instruction", when=angr.BP_BEFORE, action=hook_handler, instruction=address
        )
        self.state.scratch.insn_bps[address] = bp

    def unhook_instruction(self, address: int) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Instruction hooking not supported once execution begins"
            )
        if address not in self.state.scratch.insn_bps:
            raise exceptions.ConfigurationError(
                "Instruction at address {hex(address)} is not hooked"
            )
        bp = self.state.scratch.insn_bps[address]
        del self.state.scratch.insn_bps[address]

        self.state.inspect.remove_breakpoint("instruction", bp)

    def hook_instructions(
        self, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Global instruction hooking not supported once execution begins"
            )

        if self.state.scratch.global_insn_bp is not None:
            raise exceptions.ConfigurationError(
                "Global instruction hook already registered"
            )

        def hook_handler(state):
            emu = ConcreteAngrEmulator(state, self)
            function(emu)

        self.state.scratch.global_insn_bp = self.state.inspect.b(
            "instruction", when=angr.BP_BEFORE, action=hook_handler
        )

    def unhook_instructions(self) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Global instruction unhooking not supported once execution begins"
            )

        if self.state.scratch.global_insn_bp is None:
            raise exceptions.ConfigurationError("No global instruction hook present")

        bp = self.state.scratch.global_insn_bp
        self.state.scratch.global_insn_bp = None
        self.state.inspect.remove_breakpoint("instruction", bp)

    def hook_function(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError("Cannot hook functions once emulation starts")
        hook = HookHandler(callback=function, parent=self)
        self.proj.hook(address, hook, 0)

        self.map_memory(address, 1)
        self.state.scratch.func_bps[address] = None

    def unhook_function(self, address: int) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError("Cannot unhook functions once emulation starts")
        self.proj.unhook(address)

    def hook_syscall(
        self, number: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError("Cannot hook syscalls once emulation starts")
        if number in self.state.scratch.syscall_funcs:
            raise exceptions.ConfigurationError(
                f"Already have a syscall hook for {number}"
            )

        def syscall_handler(state):
            function(ConcreteAngrEmulator(state, self))

        self.state.scratch.syscall_funcs[number] = syscall_handler

    def unhook_syscall(self, number: int) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError("Cannot unhook syscalls once emulation starts")
        if number not in self.state.scratch.syscall_funcs:
            raise exceptions.ConfigurationError(f"No syscall hook for {number}")
        del self.state.scratch.syscall_funcs[number]

    def hook_syscalls(
        self, function: typing.Callable[[emulator.Emulator, int], None]
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError("Cannot hook syscalls once emulation starts")

        if self.state.scratch.global_syscall_func is not None:
            raise exceptions.ConfigurationError("Already have a global syscall hook")

        def syscall_handler(state, number: int):
            function(ConcreteAngrEmulator(state, self), number)

        self.state.scratch.global_syscall_func = syscall_handler

    def unhook_syscalls(self) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError("Cannot unhook syscalls once emulation starts")

        if self.state.scratch.global_syscall_func is None:
            raise exceptions.ConfigurationError("No global syscall hook registered")
        self.state.scratch.global_syscall_func = None

    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[[emulator.Emulator, int, int], bytes],
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )
        if (start, end) in self.state.scratch.mem_read_bps:
            raise exceptions.ConfigurationError(
                f"{hex(start)}-{hex(end)} already hooked for reads"
            )

        # This uses angr's conditional breakpoint facility
        def read_condition(state):
            # The breakpoint condition.
            # This needs to be a bit clever to detect reads at bound symbolic addresses.
            # The actual address won't get concretized until later
            read_start = state.inspect.mem_read_address
            if not isinstance(read_start, int):
                if read_start.symbolic:
                    try:
                        values = state.solver.eval_atmost(read_start, 1)
                        # Truly unbound address.
                        # Assume it won't collapse to our hook address
                        if len(values) < 1:
                            return False
                        read_start = values[0]
                    except angr.errors.SimUnsatError:
                        return False
                    except angr.errors.SimValueError:
                        return False
                else:
                    read_start = read_start.concrete_value
                state.inspect.mem_read_address = read_start
            read_size = state.inspect.mem_read_length

            if read_size is None:
                return False
            read_end = read_start + read_size

            return start <= read_start and end >= read_end

        def read_callback(state):
            # The breakpoint action.
            addr = state.inspect.mem_read_address
            size = state.inspect.mem_read_length

            res = claripy.BVV(function(ConcreteAngrEmulator(state, self), addr, size))

            if self.platform.byteorder == platforms.Byteorder.LITTLE:
                # Fix byte order if needed.
                # I don't know _why_ this is needed,
                # but encoding the result as little-endian on a little-endian
                # system produces the incorrect value in the machine state.
                res = claripy.Reverse(res)
            state.inspect.mem_read_expr = res

        bp = self.state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            condition=read_condition,
            action=read_callback,
        )
        self.state.scratch.mem_read_bps[(start, end)] = bp

    def unhook_memory_read(self, start: int, end: int):
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )
        if (start, end) not in self.state.scratch.mem_read_bps:
            raise exceptions.ConfigurationError(
                f"{hex(start)} - {hex(end)} is not hooked for reads"
            )

        bp = self.state.scratch.mem_read_bps[(start, end)]
        del self.state.scratch.mem_read_bps[(start, end)]
        self.state.inspect.remove_breakpoint("mem_read", bp=bp)

    def hook_memory_reads(
        self, function: typing.Callable[[emulator.Emulator, int, int], bytes]
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )
        if self.state.scratch.global_read_bp is not None:
            raise exceptions.ConfigurationError(
                "Global memory read hook already present"
            )

        def read_callback(state):
            # the breakpoint action.
            addr = state.inspect.mem_read_address
            if not isinstance(addr, int):
                addr = addr.concrete_value
            size = state.inspect.mem_read_length

            res = claripy.BVV(function(ConcreteAngrEmulator(state, self), addr, size))

            if self.platform.byteorder == platforms.byteorder.LITTLE:
                # fix byte order if needed.
                # i don't know _why_ this is needed,
                # but encoding the result as little-endian on a little-endian
                # system produces the incorrect value in the machine state.
                res = claripy.Reverse(res)
            state.inspect.mem_read_expr = res

        bp = self.state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            action=read_callback,
        )
        self.state.scratch.global_read_bp = bp

    def unhook_memory_reads(self) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory unhooking not supported once execution begins"
            )
        if self.state.scratch.global_read_bp is not None:
            raise exceptions.ConfigurationError("Global memory read hook not present")

        bp = self.state.scratch.global_read_bp
        self.state.scratch.global_read_bp = None
        self.state.inspect.remove_breakpoint("mem_read", bp)

    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[emulator.Emulator, int, int, bytes], None],
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )
        if (start, end) in self.state.scratch.mem_write_bps:
            raise exceptions.ConfigurationError(
                f"{hex(start)} - {hex(end)} already hooked for writes"
            )

        def write_condition(state):
            write_start = state.inspect.mem_write_address
            if not isinstance(write_start, int):
                if write_start.symbolic:
                    # Need to use the solver to resolve this.
                    try:
                        values = state.solver.eval_atmost(write_start, 1)
                        if len(values) < 1:
                            return False
                        write_start = values[0]
                    except angr.errors.SimUnsatError:
                        return False
                    except angr.errors.SimValueError:
                        return False
                else:
                    write_start = write_start.concrete_value
                # Populate concrete value back to the inspect struct
                state.inspect.mem_write_address = write_start
            log.info(f"Writing to {hex(write_start)}")
            write_size = state.inspect.mem_write_length

            if write_size is None:
                # Some ISAs don't populate mem_write_length.
                # Infer length from value
                write_size = len(state.inspect.mem_write_expr) // 8
                # Populate concrete value back to the inspect struct
                state.inspect.mem_write_length = write_size
            write_end = write_start + write_size

            return start <= write_start and end >= write_end

        def write_callback(state):
            addr = state.inspect.mem_write_address
            size = state.inspect.mem_write_length
            expr = state.inspect.mem_write_expr
            if expr.symbolic:
                # Have the solver handle binding resolution for us.
                try:
                    values = state.solver.eval_atmost(expr, 1)
                    if len(values) < 1:
                        raise exceptions.AnalysisError(f"No possible values fpr {expr}")
                    value = values[0].to_bytes(size, byteorder=self.machdef.byteorder)
                    log.info("Collapsed symbolic {expr} to {values[0]:x} for MMIO")
                except angr.errors.SimUnsatError:
                    raise exceptions.AnalysisError(f"No possible values for {expr}")
                except angr.errors.SimValueError:
                    raise exceptions.AnalysisError(
                        f"Unbound value for MMIO write to {hex(addr)}: {expr}"
                    )
            else:
                value = expr.concrete_value.to_bytes(
                    size, byteorder=self.platform.byteorder.value
                )

            if size is None:
                size = len(expr)

            function(ConcreteAngrEmulator(state, self), addr, size, value)

        bp = self.state.inspect.b(
            "mem_write",
            when=angr.BP_BEFORE,
            condition=write_condition,
            action=write_callback,
        )
        self.state.scratch.mem_write_bps[(start, end)] = bp

    def unhook_memory_write(self, start: int, end: int) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )
        if (start, end) not in self.state.scratch.mem_write_bps:
            raise exceptions.ConfigurationError(
                f"{hex(start)} - {hex(end)} is not hooked for writes"
            )

        bp = self.state.scratch.mem_write_bps[(start, end)]
        del self.state.scratch.mem_write_bps[(start, end)]
        self.state.inspect.remove_breakpoint("mem_write", bp=bp)

    def hook_memory_writes(
        self, function: typing.Callable[[emulator.Emulator, int, int, bytes], None]
    ) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )
        if self.state.scratch.global_write_bp is not None:
            raise exceptions.ConfigurationError(
                "Global memory write hook already present"
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
                        raise exceptions.AnalysisError(f"No possible values fpr {expr}")
                    value = values[0].to_bytes(size, byteorder=self.machdef.byteorder)
                    log.info("Collapsed symbolic {expr} to {values[0]:x} for MMIO")
                except angr.errors.SimUnsatError:
                    raise exceptions.AnalysisError(f"No possible values for {expr}")
                except angr.errors.SimValueError:
                    raise exceptions.AnalysisError(
                        f"Unbound value for MMIO write to {hex(addr)}: {expr}"
                    )
            else:
                value = expr.concrete_value.to_bytes(
                    size, byteorder=self.platform.byteorder.value
                )

            function(ConcreteAngrEmulator(state, self), addr, size, value)

        bp = self.state.inspect.b(
            "mem_write",
            when=angr.BP_BEFORE,
            action=write_callback,
        )

        self.state.scratch.global_write_bp = bp

    def unhook_memory_writes(self) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory unhooking not supported once execution begins"
            )
        if self.state.scratch.global_write_bp is not None:
            raise exceptions.ConfigurationError("Global memory write hook not present")

        bp = self.state.scratch.global_read_bp
        self.state.scratch.global_read_bp = None
        self.state.inspect.remove_breakpoint("mem_write", bp)

    def _step(self, single_insn: bool):
        """Common routine for all step functions.

        This is rather verbose, so let's only write it once.

        Arguments:
            single_insn: True to step one instruction.  False to step to the end of the block
        """
        # As soon as we start executing, disable value access
        self._dirty = True
        if self._linear:
            if self.state._ip.concrete_value not in self.state.scratch.func_bps:
                disas = self.state.block().disassembly
                if disas is not None and len(disas.insns) > 0:
                    log.info(f"Stepping through {disas.insns[0]}")
                else:
                    # Capstone only supports a subset of the instructions supported by LibVEX.
                    # I can only disassemble what I can disassemble.
                    log.info(f"Stepping through {self.state._ip} (untranslatable!)")
            else:
                log.info(f"Stepping through {self.state._ip} (hook)")

        # Step execution once, however the user asked for it.
        if single_insn:
            # Not all architectures support single-step execution.
            # In particular, angr can't lift delay slot ISAs one instruction at a time,
            # since it has to lift the instruction and the slot as one unit.
            if not self.machdef.supports_single_step:
                raise exceptions.ConfigurationError(
                    f"AngrEmulator does not support single-instruction stepping for {self.platform}"
                )
            num_inst = 1
        else:
            num_inst = None
        self.mgr.step(
            num_inst=num_inst,
            successor_func=self.machdef.successors,
            thumb=self.machdef.is_thumb,
        )

        # Test for exceptional states
        if len(self.mgr.errored) > 0:
            raise exceptions.EmulationError(
                self.mgr.errored[0].error
            ) from self.mgr.errored[0].error

        # Handle linear execution mode
        if self._linear:
            if len(self.mgr.active) > 1:
                log.warn("Path diverged!  Detailes stored in simulation manager.")
                raise exceptions.EmulationStop("Path diverged in linear mode")
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
            ip = state._ip.concrete_value
            if (
                not self.state.scratch.bounds.is_empty()
                and self.state.scratch.bounds.find_range(ip) is None
            ):
                return True
            if self.state.scratch.memory_map.find_range(ip) is None:
                return True
            if ip in self.state.scratch.exit_points:
                return True
            return False

        self.mgr.move(
            from_stash="active", to_stash="deadended", filter_func=filter_func
        )

        # Stop if we're out of active states
        if len(self.mgr.active) == 0:
            raise exceptions.EmulationStop()

    def step_instruction(self) -> None:
        self._step(True)

    def step_block(self) -> None:
        self._step(False)

    def step(self) -> None:
        self._step(True)

    def run(self):
        log.info("Starting angr run")
        try:
            # Continue stepping as long as we have steps.
            while True:
                self._step(False)
        except exceptions.EmulationStop:
            return

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

    def get_bounds(self) -> typing.List[typing.Tuple[int, int]]:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing bounds not supported once execution begins"
            )
        return list(self.state.scratch.bounds.ranges)

    def add_bound(self, start: int, end: int) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing bounds not supported once execution begins"
            )
        self.state.scratch.bounds.add_range((start, end))

    def remove_bound(self, start: int, end: int) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing bounds not supported once execution begins"
            )

        self.state.scratch.bounds.remove_range((start, end))

    def get_exit_points(self) -> typing.Set[int]:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing exit points not supported once execution begins"
            )
        return set(self.state.scratch.exit_points)

    def add_exit_point(self, address: int) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing exit points not supported once execution begins"
            )
        self.state.scratch.exit_points.add(address)

    def remove_exit_point(self, address: int) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing exit points not supported once execution begins"
            )
        self.state.scratch.exit_points.remove(address)

    def __repr__(self):
        return f"Angr ({self.mgr})"


class ConcreteAngrEmulator(AngrEmulator):
    """
    "Emulator" for angr state access

    The primary AngrEmulator class is designed for symbolic execution;
    it represents many states being explored in parallel.
    As such, the notion of accessing state doesn't work; which state do you want?

    For hook evaluation, we do need an emulator-like object
    that can access a single state.  Hence, this wrapper class.

    NOTE: This is NOT a full emulator!
    Think of it more as a view onto an AngrEmulator instance.
    If you want to explore a single path using angr,
    use AngrEmulator and call enable_linear() before exploration.
    """

    @property
    def PAGE_SIZE(self):
        # Page Size should be inherited from the parent.
        return self.pagesize

    def __init__(self, state: angr.SimState, parent: AngrEmulator):
        # Do NOT call the superclass constructor.
        # It initializes the angr project, and we've already done that.
        self._dirty: bool = False
        self._linear: bool = False

        self.platform: platforms.Platform = parent.platform
        self.proj: angr.Project = parent.proj
        self.state: angr.SimState = state
        self.machdef: AngrMachineDef = parent.machdef
        self.pagesize: int = parent.PAGE_SIZE

    # Function hooking is not supported;
    # it relies on state global to the angr project, not individual states.
    def hook_function(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        raise NotImplementedError("Function hooking not supported inside a hook.")

    def unhook_function(self, address: int) -> None:
        raise NotImplementedError("Function hooking not supported inside a hook.")

    # Execution is not supported; this is not a complete emulator.
    def run(self) -> None:
        raise NotImplementedError("Running not supported inside a hook.")

    def _step(self, single_insn: bool) -> None:
        raise NotImplementedError("Stepping not supported inside a hook.")

    def __repr__(self):
        return f"Angr Hook ({self.state})"


__all__ = ["AngrEmulator"]
