from __future__ import annotations

import logging
import typing

import angr
import claripy
import cle

from ... import exceptions, platforms, utils
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
    emulator.ConstrainedEmulator,
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
        # Initializaed bit; tells us if angr state is initialized
        self._initialized: bool = False

        # Dirty bit; tells us if we can modify self.state
        self._dirty: bool = False

        # Linear mode bit; tells us if we're running in forced linear execution
        self._linear: bool = False

        # Plugin preset; tells us which plugin preset to use.
        self._plugin_preset = "default"

        # The machine definition;
        # helps translate between angr and smallworld
        self.machdef: AngrMachineDef = AngrMachineDef.for_platform(platform)

        self.platform = platform
        self.preinit = preinit
        self.init = init

        # Cached state modifications,
        # to be applied during initialization
        self._code: typing.List[typing.Tuple[int, bytes]] = list()
        self._register_contents: typing.Dict[
            str, typing.Union[int, claripy.ast.bv.BV]
        ] = dict()
        self._register_labels: typing.Dict[str, str] = dict()
        self._memory_maps: typing.List[typing.Tuple[int, int]] = list()
        self._memory_contents: typing.List[
            typing.Tuple[int, typing.Union[bytes, claripy.ast.bv.BV]]
        ] = list()
        self._memory_labels: typing.List[typing.Tuple[int, int, str]] = list()
        self._instr_hooks: typing.List[
            typing.Tuple[int, typing.Callable[[emulator.Emulator], None]]
        ] = list()
        self._gb_instr_hook: typing.Optional[
            typing.Callable[[emulator.Emulator], None]
        ] = None
        self._func_hooks: typing.List[
            typing.Tuple[int, typing.Callable[[emulator.Emulator], None]]
        ] = list()
        self._syscall_hooks: typing.Dict[
            int, typing.Callable[[emulator.Emulator], None]
        ] = dict()
        self._gb_syscall_hook: typing.Optional[
            typing.Callable[[emulator.Emulator, int], None]
        ] = None
        self._read_hooks: typing.List[
            typing.Tuple[
                int,
                int,
                typing.Callable[
                    [emulator.Emulator, int, int, claripy.ast.bv.BV],
                    typing.Optional[claripy.ast.bv.BV],
                ],
            ]
        ] = list()
        self._gb_read_hook: typing.Optional[
            typing.Callable[
                [emulator.Emulator, int, int, claripy.ast.bv.BV],
                typing.Optional[claripy.ast.bv.BV],
            ]
        ] = None
        self._write_hooks: typing.List[
            typing.Tuple[
                int,
                int,
                typing.Callable[[emulator.Emulator, int, int, claripy.ast.bv.BV], None],
            ]
        ] = list()
        self._gb_write_hook: typing.Optional[
            typing.Callable[[emulator.Emulator, int, int, claripy.ast.bv.BV], None]
        ] = None
        self._code_bounds: typing.List[typing.Tuple[int, int]] = list()
        self._exit_points: typing.Set[int] = set()
        self._constraints: typing.List[claripy.ast.bool.Bool] = list()
        self._extensions: typing.Dict[str, typing.Any] = dict()

    def initialize(self):
        """Initialize the emulator

        To take advantage of CLE, we need to know about all code
        before we initialize the angr state objects.
        However, applying register and memory changes requires access
        to the angr state object.

        SmallWorld doesn't support ordering how state is applied,
        so I need to collect it, then apply it once emulation starts.

        This function is invoked automatically when you cycle the emulator,
        but you're free to invoke it early if you want.
        """

        if self._initialized:
            raise exceptions.ConfigurationError("Cannot reinitialize running emulator")

        # Build a single, coherent byte stream out of our code
        self._code.sort(key=lambda x: x[0])

        code = utils.SparseIO()
        segments = list()

        if len(self._code) > 0:
            code_ranges = utils.RangeCollection()
            base_address = self._code[0][0]
            for addr, data in self._code:
                size = len(data)
                code.seek(addr - base_address)
                code.write(data)
                code_ranges.add_range((addr, addr + size))
            segments = list(
                map(lambda x: (x[0] - base_address, x[0], x[1] - x[0]), code_ranges)
            )

        # Create an angr project using a blank byte stream,
        # and registered as self-modifying so we can load more code later.
        backend = cle.Blob(
            None, code, is_main_bin=True, arch=self.machdef.angr_arch, segments=segments
        )
        loader = cle.Loader(backend)
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
        if self.preinit is not None:
            self.preinit(self)

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
        if self.init:
            self.init(self)

        # Mark this emulator as initialized
        self._initialized = True

        # Read back any changes that happened before initialization.
        for name, content in self._register_contents.items():
            self.write_register_content(name, content)

        for name, label in self._register_labels.items():
            self.write_register_label(name, label)

        for addr, size in self._memory_maps:
            self.map_memory(addr, size)

        for addr, content in self._memory_contents:
            self.write_memory_content(addr, content)

        self._write_memory_label_bulk(self._memory_labels)

        for addr, func in self._instr_hooks:
            self.hook_instruction(addr, func)

        if self._gb_instr_hook is not None:
            self.hook_instructions(self._gb_instr_hook)

        for addr, func in self._func_hooks:
            self.hook_function(addr, func)

        for num, func in self._syscall_hooks.items():
            self.hook_syscall(num, func)

        if self._gb_syscall_hook is not None:
            self.hook_syscalls(self._gb_syscall_hook)

        for start, end, func in self._read_hooks:
            self.hook_memory_read_symbolic(start, end, func)

        if self._gb_read_hook is not None:
            self.hook_memory_reads_symbolic(self._gb_read_hook)

        for start, end, func in self._write_hooks:
            self.hook_memory_write_symbolic(start, end, func)

        if self._gb_write_hook is not None:
            self.hook_memory_writes_symbolic(self._gb_write_hook)

        for start, end in self._code_bounds:
            self.add_bound(start, end)

        for addr in self._exit_points:
            self.add_exit_point(addr)

        for expr in self._constraints:
            self.add_constraint(expr)

        self.state.scratch.extensions |= self._extensions

    def read_register_symbolic(self, name: str) -> claripy.ast.bv.BV:
        if not self._initialized:
            raise exceptions.ConfigurationError(
                "Cannot read registers before initialization"
            )

        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Reading registers not supported once execution begins."
            )

        if name == "pc":
            name = self.machdef.pc_reg

        (off, size) = self.machdef.angr_reg(name)
        return self.state.registers.load(off, size)

    def read_register_content(self, name: str) -> int:
        out = self.read_register_symbolic(name)
        if out.symbolic:
            raise exceptions.SymbolicValueError(f"Register {name} is symbolic")
        else:
            return out.concrete_value

    def read_register_type(self, name: str) -> typing.Optional[typing.Any]:
        return None

    def read_register_label(self, name: str) -> typing.Optional[str]:
        if not self._initialized:
            raise exceptions.ConfigurationError(
                "Cannot read registers before initialization"
            )

        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Reading register not supported once execution begins."
            )

        if name == "pc":
            name = self.machdef.pc_reg

        try:
            # This considers all BVSs to be labeled values;
            # if it has a name, we're giving it to you.
            (off, size) = self.machdef.angr_reg(name)
            out = self.state.registers.load(off, size)
            if out.symbolic:
                if out.op == "BVS":
                    # This is a "pure" label; we can return it.
                    return out.args[0]
                else:
                    # This is a mixed expression; we can't return it
                    log.warn(f"Register {name} contains a symbolic expression")
                    raise exceptions.SymbolicValueError(
                        f"Register {name} contains a symbolic expression"
                    )
            else:
                # No propagated label
                return None
        except ValueError:
            # TODO: Handle invalid registers more gracefully
            return None

    def write_register_content(
        self, name: str, content: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        if not self._initialized and content is not None:
            if name == "pc":
                name = self.machdef.pc_reg
            # Test that the angr register exists
            _, _ = self.machdef.angr_reg(name)
            self._register_contents[name] = content
            return
        elif self._dirty and not self._linear:
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
        elif isinstance(content, int):
            v = claripy.BVV(content, size * 8)
        elif isinstance(content, claripy.ast.bv.BV):
            v = content
        else:
            raise TypeError(
                f"Content for register {name} was {type(content)}; expected (None | int | claripy.ast.bv.BV)"
            )

        if v.size() != size * 8:
            raise exceptions.ConfigurationError(
                f"Register {name} has size {size}, but content has size {v.size() // 8}"
            )

        self.state.registers.store(off, v)

    def write_register_type(
        self, name: str, type: typing.Optional[typing.Any] = None
    ) -> None:
        pass

    def write_register_label(
        self, name: str, label: typing.Optional[str] = None
    ) -> None:
        if label is None:
            return
        elif not self._initialized:
            if name == "pc":
                name = self.machdef.pc_reg
            # Test that the angr register exists
            _, _ = self.machdef.angr_reg(name)
            self._register_labels[name] = label
        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )
        else:
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
        if not self._initialized:
            raise exceptions.ConfigurationError(
                "Cannot read memory before initialization"
            )

        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Reading memory not supported once execution begins."
            )
        v = self.state.memory.load(address, size)
        if v.symbolic:
            log.warn(f"Memory at {hex(address)} ({size} bytes) is symbolic")
            raise exceptions.SymbolicValueError(f"Memory at {hex(address)} is symbolic")

        # Annoyingly, there isn't an easy way to convert BVV to bytes.
        return bytes([v.get_byte(i).concrete_value for i in range(0, size)])

    def read_memory_symbolic(self, address: int, size: int) -> claripy.ast.bv.BV:
        if not self._initialized:
            raise exceptions.ConfigurationError(
                "Cannot read memory before initialization"
            )

        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Reading memory not supported once execution begins."
            )
        return self.state.memory.load(address, size)

    def read_memory_type(self, address: int, size: int) -> typing.Optional[typing.Any]:
        return None

    def read_memory_label(self, address: int, size: int) -> typing.Optional[str]:
        if not self._initialized:
            raise exceptions.ConfigurationError(
                "Cannot read memory before initialization"
            )

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
        if not self._initialized:
            self._memory_maps.append((address, size))
        else:
            if self._dirty and not self._linear:
                raise NotImplementedError(
                    "Mapping memory not supported once execution begins."
                )
            # Unlike Unicorn, angr doesn't care about pages.
            region = (address, address + size)
            self.state.scratch.memory_map.add_range(region)

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        if not self._initialized:
            return list(map(lambda x: (x[0], x[0] + x[1]), self._memory_maps))
        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Mapping memory not supported once execution begins."
            )
        return list(self.state.scratch.memory_map.ranges)

    def write_memory_content(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ) -> None:
        if not self._initialized:
            self._memory_contents.append((address, content))
        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing memory not supported once execution begins."
            )
        else:
            log.info(f"Storing {len(content)} bytes at {hex(address)}")
            if isinstance(content, bytes):
                content = claripy.BVV(content)
            self.state.memory.store(address, content, inspect=False)

    def write_memory_type(
        self, address: int, size: int, type: typing.Optional[typing.Any] = None
    ) -> None:
        pass

    def write_memory_label(
        self, address: int, size: int, label: typing.Optional[str] = None
    ) -> None:
        if label is None:
            return
        elif not self._initialized:
            self._memory_labels.append((address, size, label))
        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Writing memory not supported once execution begins."
            )
        else:
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
            self.state.memory.store(address, s, inspect=False)
            self.state.solver.add(v == s)

    def _write_memory_label_bulk(
        self, labels: typing.List[typing.Tuple[int, int, typing.Optional[str]]]
    ) -> None:
        # Variant of write_memory_label that applies multiple labels in one go.
        # This addresses a performance bottleneck during initialization;
        # it's not really intended for public use,
        # as it lacks some of the safety checks.
        cs = list()
        for addr, size, label in labels:
            if label is None:
                continue
            s = claripy.BVS(label, size * 8, explicit_name=True)
            v = self.state.memory.load(addr, size)
            self.state.memory.store(addr, s)
            cs.append(s == v)
        c = claripy.And(*cs)
        self.state.solver.add(c)

    def write_code(self, address: int, content: bytes):
        if self._initialized:
            self.write_memory_content(address, content)
        else:
            self._code.append((address, content))

    def hook_instruction(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        if not self._initialized:
            self._instr_hooks.append((address, function))

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Instruction hooking not supported once execution begins"
            )

        elif address in self.state.scratch.insn_bps:
            raise exceptions.ConfigurationError(
                "Instruction at address {hex(address)} is already hooked"
            )

        else:

            def hook_handler(state):
                emu = ConcreteAngrEmulator(state, self)
                function(emu)

                # An update to angr means some operations on `state`
                # will clobber this variable, which causes bad problems.
                # Unclobber it, just in case
                state.inspect.action_attrs_set = True

            bp = self.state.inspect.b(
                "instruction",
                when=angr.BP_BEFORE,
                action=hook_handler,
                instruction=address,
            )
            self.state.scratch.insn_bps[address] = bp

    def unhook_instruction(self, address: int) -> None:
        if not self._initialized:
            self._instr_hooks = list(
                filter(lambda x: x[0] != address, self._instr_hooks)
            )

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Instruction hooking not supported once execution begins"
            )

        elif address not in self.state.scratch.insn_bps:
            raise exceptions.ConfigurationError(
                "Instruction at address {hex(address)} is not hooked"
            )

        else:
            bp = self.state.scratch.insn_bps[address]
            del self.state.scratch.insn_bps[address]

            self.state.inspect.remove_breakpoint("instruction", bp)

    def hook_instructions(
        self, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        if not self._initialized:
            self._gb_instr_hook = function

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Global instruction hooking not supported once execution begins"
            )

        elif self.state.scratch.global_insn_bp is not None:
            raise exceptions.ConfigurationError(
                "Global instruction hook already registered"
            )

        else:

            def hook_handler(state):
                emu = ConcreteAngrEmulator(state, self)
                function(emu)

                # An update to angr means some operations on `state`
                # will clobber this variable, which causes bad problems.
                # Unclobber it, just in case
                state.inspect.action_attrs_set = True

            self.state.scratch.global_insn_bp = self.state.inspect.b(
                "instruction", when=angr.BP_BEFORE, action=hook_handler
            )

    def unhook_instructions(self) -> None:
        if not self._initialized:
            self._gb_instruction_hook = None

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Global instruction unhooking not supported once execution begins"
            )

        elif self.state.scratch.global_insn_bp is None:
            raise exceptions.ConfigurationError("No global instruction hook present")

        else:
            bp = self.state.scratch.global_insn_bp
            self.state.scratch.global_insn_bp = None
            self.state.inspect.remove_breakpoint("instruction", bp)

    def hook_function(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        if not self._initialized:
            self._func_hooks.append((address, function))

        elif self._dirty and not self._linear:
            raise NotImplementedError("Cannot hook functions once emulation starts")

        else:
            hook = HookHandler(callback=function, parent=self)
            self.proj.hook(address, hook, 0)

            self.map_memory(address, 1)
            self.state.scratch.func_bps[address] = None

    def unhook_function(self, address: int) -> None:
        if not self._initialized:
            self._func_hooks = list(filter(lambda x: x[0] != address, self._func_hooks))

        elif self._dirty and not self._linear:
            raise NotImplementedError("Cannot unhook functions once emulation starts")

        else:
            self.proj.unhook(address)

    def hook_syscall(
        self, number: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        if not self._initialized:
            self._syscall_hooks[number] = function
        elif self._dirty and not self._linear:
            raise NotImplementedError("Cannot hook syscalls once emulation starts")
        elif number in self.state.scratch.syscall_funcs:
            raise exceptions.ConfigurationError(
                f"Already have a syscall hook for {number}"
            )
        else:

            def syscall_handler(state):
                function(ConcreteAngrEmulator(state, self))

            self.state.scratch.syscall_funcs[number] = syscall_handler

    def unhook_syscall(self, number: int) -> None:
        if not self._initialized:
            del self._syscall_hooks[number]

        elif self._dirty and not self._linear:
            raise NotImplementedError("Cannot unhook syscalls once emulation starts")

        elif number not in self.state.scratch.syscall_funcs:
            raise exceptions.ConfigurationError(f"No syscall hook for {number}")

        else:
            del self.state.scratch.syscall_funcs[number]

    def hook_syscalls(
        self, function: typing.Callable[[emulator.Emulator, int], None]
    ) -> None:
        if not self._initialized:
            self._gb_syscall_hook = function

        elif self._dirty and not self._linear:
            raise NotImplementedError("Cannot hook syscalls once emulation starts")

        elif self.state.scratch.global_syscall_func is not None:
            raise exceptions.ConfigurationError("Already have a global syscall hook")

        else:

            def syscall_handler(state, number: int):
                function(ConcreteAngrEmulator(state, self), number)

            self.state.scratch.global_syscall_func = syscall_handler

    def unhook_syscalls(self) -> None:
        if self._dirty and not self._linear:
            raise NotImplementedError("Cannot unhook syscalls once emulation starts")

        if self.state.scratch.global_syscall_func is None:
            raise exceptions.ConfigurationError("No global syscall hook registered")
        self.state.scratch.global_syscall_func = None

    def hook_memory_read_symbolic(
        self,
        start: int,
        end: int,
        function: typing.Callable[
            [emulator.Emulator, int, int, claripy.ast.bv.BV],
            typing.Optional[claripy.ast.bv.BV],
        ],
    ) -> None:
        if not self._initialized:
            self._read_hooks.append((start, end, function))

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )

        elif (start, end) in self.state.scratch.mem_read_bps:
            raise exceptions.ConfigurationError(
                f"{hex(start)}-{hex(end)} already hooked for reads"
            )

        else:
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
                expr = state.inspect.mem_read_expr
                res = function(ConcreteAngrEmulator(state, self), addr, size, expr)

                if res is None:
                    res = expr
                state.inspect.mem_read_expr = res

                # An update to angr means some operations on `state`
                # will clobber this variable, which causes bad problems.
                # Unclobber it, just in case
                state.inspect.action_attrs_set = True

            bp = self.state.inspect.b(
                "mem_read",
                when=angr.BP_AFTER,
                condition=read_condition,
                action=read_callback,
            )
            self.state.scratch.mem_read_bps[(start, end)] = bp

    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[
            [emulator.Emulator, int, int, bytes], typing.Optional[bytes]
        ],
    ):
        # Most of the machinery is handled in hook_memory_read_symbolic
        # We just need to concretize the inputs and claripy the outputs
        def sym_callback(
            emu: emulator.Emulator, addr: int, size: int, expr: claripy.ast.bv.BV
        ) -> typing.Optional[claripy.ast.bv.BV]:
            if not isinstance(emu, ConcreteAngrEmulator):
                raise TypeError("Where'd you get your emu?")
            if expr.symbolic:
                # Have the solver handle binding resolution for us.
                try:
                    values = emu.state.solver.eval_atmost(expr, 1)
                    if len(values) < 1:
                        raise exceptions.AnalysisError(f"No possible values fpr {expr}")
                    value = values[0].to_bytes(size, byteorder=self.byteorder)
                    log.info("Collapsed symbolic {expr} to {values[0]:x} for MMIO")
                except angr.errors.SimUnsatError:
                    raise exceptions.AnalysisError(f"No possible values for {expr}")
                except angr.errors.SimValueError:
                    value = b"\x00" * size
            else:
                value = expr.concrete_value.to_bytes(size, byteorder=self.byteorder)
            res = function(emu, addr, size, value)
            if res is not None:
                res_expr = claripy.BVV(res)
                if self.platform.byteorder == platforms.Byteorder.LITTLE:
                    # Fix byte order if needed.
                    # I don't know _why_ this is needed,
                    # but encoding the result as little-endian on a little-endian
                    # system produces the incorrect value in the machine state.
                    res_expr = claripy.Reverse(res_expr)
                return res_expr
            return res

        self.hook_memory_read_symbolic(start, end, sym_callback)

    def unhook_memory_read(self, start: int, end: int):
        if not self._initialized:
            self._read_hooks = list(
                filter(lambda x: x[0] != start and x[1] != end, self._read_hooks)
            )

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )

        elif (start, end) not in self.state.scratch.mem_read_bps:
            raise exceptions.ConfigurationError(
                f"{hex(start)} - {hex(end)} is not hooked for reads"
            )
        else:
            bp = self.state.scratch.mem_read_bps[(start, end)]
            del self.state.scratch.mem_read_bps[(start, end)]
            self.state.inspect.remove_breakpoint("mem_read", bp=bp)

    def hook_memory_reads_symbolic(
        self,
        function: typing.Callable[
            [emulator.Emulator, int, int, claripy.ast.bv.BV],
            typing.Optional[claripy.ast.bv.BV],
        ],
    ) -> None:
        if not self._initialized:
            self._gb_read_hook = function

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )

        elif self.state.scratch.global_read_bp is not None:
            raise exceptions.ConfigurationError(
                "Global memory read hook already present"
            )

        else:

            def read_callback(state):
                # the breakpoint action.
                addr = state.inspect.mem_read_address
                if not isinstance(addr, int):
                    addr = addr.concrete_value
                size = state.inspect.mem_read_length
                expr = state.inspect.mem_read_expr

                res = function(ConcreteAngrEmulator(state, self), addr, size, expr)

                if self.platform.byteorder == platforms.byteorder.LITTLE:
                    # fix byte order if needed.
                    # i don't know _why_ this is needed,
                    # but encoding the result as little-endian on a little-endian
                    # system produces the incorrect value in the machine state.
                    res = claripy.Reverse(res)
                state.inspect.mem_read_expr = res

                # An update to angr means some operations on `state`
                # will clobber this variable, which causes bad problems.
                # Unclobber it, just in case
                state.inspect.action_attrs_set = True

            bp = self.state.inspect.b(
                "mem_read",
                when=angr.BP_AFTER,
                action=read_callback,
            )
            self.state.scratch.global_read_bp = bp

    def hook_memory_reads(
        self,
        function: typing.Callable[
            [emulator.Emulator, int, int, bytes], typing.Optional[bytes]
        ],
    ):
        # Symbolic version does most of the lifting;
        # we just need to translate the values
        def sym_callback(
            emu: emulator.Emulator, addr: int, size: int, expr: claripy.ast.bv.BV
        ) -> typing.Optional[claripy.ast.bv.BV]:
            if not isinstance(emu, ConcreteAngrEmulator):
                raise TypeError("Where'd you get your emu?")
            if expr.symbolic:
                # Have the solver handle binding resolution for us.
                try:
                    values = emu.state.solver.eval_atmost(expr, 1)
                    if len(values) < 1:
                        raise exceptions.AnalysisError(f"No possible values fpr {expr}")
                    value = values[0].to_bytes(size, byteorder=self.byteorder)
                    log.info("Collapsed symbolic {expr} to {values[0]:x} for MMIO")
                except angr.errors.SimUnsatError:
                    raise exceptions.AnalysisError(f"No possible values for {expr}")
                except angr.errors.SimValueError:
                    raise exceptions.AnalysisError(
                        f"Unbound value for MMIO write to {hex(addr)}: {expr}"
                    )
            else:
                value = expr.concrete_value.to_bytes(size, byteorder=self.byteorder)
            res = function(emu, addr, size, value)
            if res is not None:
                return claripy.BVV(res)
            return res

        self.hook_memory_reads_symbolic(sym_callback)

    def unhook_memory_reads(self) -> None:
        if not self._initialized:
            self._gb_read_hook = None

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory unhooking not supported once execution begins"
            )

        elif self.state.scratch.global_read_bp is not None:
            raise exceptions.ConfigurationError("Global memory read hook not present")

        else:
            bp = self.state.scratch.global_read_bp
            self.state.scratch.global_read_bp = None
            self.state.inspect.remove_breakpoint("mem_read", bp)

    def hook_memory_write_symbolic(
        self,
        start: int,
        end: int,
        function: typing.Callable[
            [emulator.Emulator, int, int, claripy.ast.bv.BV], None
        ],
    ) -> None:
        if not self._initialized:
            self._write_hooks.append((start, end, function))

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )

        elif (start, end) in self.state.scratch.mem_write_bps:
            raise exceptions.ConfigurationError(
                f"{hex(start)} - {hex(end)} already hooked for writes"
            )

        else:

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

                if size is None:
                    size = len(expr)

                function(ConcreteAngrEmulator(state, self), addr, size, expr)

                # An update to angr means some operations on `state`
                # will clobber this variable, which causes bad problems.
                # Unclobber it, just in case
                state.inspect.action_attrs_set = True

            bp = self.state.inspect.b(
                "mem_write",
                when=angr.BP_BEFORE,
                condition=write_condition,
                action=write_callback,
            )
            self.state.scratch.mem_write_bps[(start, end)] = bp

    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[emulator.Emulator, int, int, bytes], None],
    ) -> None:
        def sym_callback(
            emu: emulator.Emulator, addr: int, size: int, expr: claripy.ast.bv.BV
        ) -> None:
            if not isinstance(emu, ConcreteAngrEmulator):
                raise TypeError("Where'd you get your emu?")
            if expr.symbolic:
                # Have the solver handle binding resolution for us.
                try:
                    values = emu.state.solver.eval_atmost(expr, 1)
                    if len(values) < 1:
                        raise exceptions.AnalysisError(f"No possible values fpr {expr}")
                    value = values[0].to_bytes(size, byteorder=self.byteorder)
                    log.info("Collapsed symbolic {expr} to {values[0]:x} for MMIO")
                except angr.errors.SimUnsatError:
                    raise exceptions.AnalysisError(f"No possible values for {expr}")
                except angr.errors.SimValueError:
                    raise exceptions.AnalysisError(
                        f"Unbound value for MMIO write to {hex(addr)}: {expr}"
                    )
            else:
                value = expr.concrete_value.to_bytes(size, byteorder=self.byteorder)
            function(emu, addr, size, value)

        self.hook_memory_write_symbolic(start, end, sym_callback)

    def unhook_memory_write(self, start: int, end: int) -> None:
        if not self._initialized:
            self._write_hooks = list(
                filter(lambda x: x[0] != start or x[1] != end, self._write_hooks)
            )

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )

        elif (start, end) not in self.state.scratch.mem_write_bps:
            raise exceptions.ConfigurationError(
                f"{hex(start)} - {hex(end)} is not hooked for writes"
            )

        else:
            bp = self.state.scratch.mem_write_bps[(start, end)]
            del self.state.scratch.mem_write_bps[(start, end)]
            self.state.inspect.remove_breakpoint("mem_write", bp=bp)

    def hook_memory_writes_symbolic(
        self,
        function: typing.Callable[
            [emulator.Emulator, int, int, claripy.ast.bv.BV], None
        ],
    ) -> None:
        if not self._initialized:
            self._gb_write_hook = function

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Memory hooking not supported once execution begins"
            )

        elif self.state.scratch.global_write_bp is not None:
            raise exceptions.ConfigurationError(
                "Global memory write hook already present"
            )

        else:

            def write_callback(state):
                addr = state.inspect.mem_write_address
                if not isinstance(addr, int):
                    addr = addr.concrete_value
                size = state.inspect.mem_write_length
                expr = state.inspect.mem_write_expr
                function(ConcreteAngrEmulator(state, self), addr, size, expr)

                # An update to angr means some operations on `state`
                # will clobber this variable, which causes bad problems.
                # Unclobber it, just in case
                state.inspect.action_attrs_set = True

            bp = self.state.inspect.b(
                "mem_write",
                when=angr.BP_BEFORE,
                action=write_callback,
            )

            self.state.scratch.global_write_bp = bp

    def hook_memory_writes(
        self, function: typing.Callable[[emulator.Emulator, int, int, bytes], None]
    ) -> None:
        def sym_callback(
            emu: emulator.Emulator, addr: int, size: int, expr: claripy.ast.bv.BV
        ) -> None:
            if not isinstance(emu, ConcreteAngrEmulator):
                raise TypeError("Where'd you get your emu?")
            if expr.symbolic:
                # Have the solver handle binding resolution for us.
                try:
                    values = emu.state.solver.eval_atmost(expr, 1)
                    if len(values) < 1:
                        raise exceptions.AnalysisError(f"No possible values fpr {expr}")
                    value = values[0].to_bytes(size, byteorder=self.byteorder)
                    log.info("Collapsed symbolic {expr} to {values[0]:x} for MMIO")
                except angr.errors.SimUnsatError:
                    raise exceptions.AnalysisError(f"No possible values for {expr}")
                except angr.errors.SimValueError:
                    raise exceptions.AnalysisError(
                        f"Unbound value for MMIO write to {hex(addr)}: {expr}"
                    )
            else:
                value = expr.concrete_value.to_bytes(size, byteorder=self.byteorder)
            function(emu, addr, size, value)

        self.hook_memory_writes_symbolic(sym_callback)

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
        # If we have not been initialized, initialize ourself
        if not self._initialized:
            self.initialize()

        # As soon as we start executing, disable value access
        self._dirty = True
        if self._linear:
            if self.state._ip.concrete_value not in self.state.scratch.func_bps:
                disas = self.state.block(opt_level=0).disassembly
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
                and not self.state.scratch.bounds.contains_value(ip)
            ):
                return True
            if not self.state.scratch.memory_map.contains_value(ip):
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

    def visit_states(
        self,
        function: typing.Callable[[emulator.Emulator], None],
        stash: str = "active",
    ) -> None:
        """Visit every state in the selected frontier

        This lets you work around the fact that most operations
        only work at emulation start, or in linear mode.
        """
        if not self._initialized:
            raise NotImplementedError("Cannot visit states before initialization")
        for s in self.mgr.stashes[stash]:
            function(ConcreteAngrEmulator(s, self))

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
        if not self._initialized:
            return list(self._code_bounds)

        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing bounds not supported once execution begins"
            )
        return list(self.state.scratch.bounds.ranges)

    def add_bound(self, start: int, end: int) -> None:
        if not self._initialized:
            self._code_bounds.append((start, end))

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing bounds not supported once execution begins"
            )

        else:
            self.state.scratch.bounds.add_range((start, end))

    def remove_bound(self, start: int, end: int) -> None:
        if not self._initialized:
            self._code_bounds = list(
                filter(lambda x: x[0] != start or x[1] != end, self._code_bounds)
            )

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing bounds not supported once execution begins"
            )

        else:
            self.state.scratch.bounds.remove_range((start, end))

    def get_exit_points(self) -> typing.Set[int]:
        if not self._initialized:
            return set(self._exit_points)

        if self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing exit points not supported once execution begins"
            )
        return set(self.state.scratch.exit_points)

    def add_exit_point(self, address: int) -> None:
        if not self._initialized:
            self._exit_points.add(address)
        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing exit points not supported once execution begins"
            )
        else:
            self.state.scratch.exit_points.add(address)

    def remove_exit_point(self, address: int) -> None:
        if not self._initialized:
            self._exit_points.remove(address)

        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing exit points not supported once execution begins"
            )

        else:
            self.state.scratch.exit_points.remove(address)

    def add_constraint(self, expr: claripy.ast.bool.Bool) -> None:
        if not self._initialized:
            self._constraints.append(expr)
        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing constraints not supported once execution begins"
            )
        else:
            self.state.solver.add(expr)

    def get_constraints(self) -> typing.List[claripy.ast.bool.Bool]:
        if not self._initialized:
            return list(self._constraints)
        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing constraints not supported once execution begins"
            )
        else:
            return list(self.state.solver.constraints)

    def satisfiable(
        self,
        extra_constraints: typing.List[claripy.ast.bool.Bool] = [],
    ) -> bool:
        if not self._initialized:
            raise exceptions.ConfigurationError(
                "Solver not available before initialization"
            )
        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing solver not supported once execution begins"
            )
        return self.state.solver.satisfiable(extra_constraints=extra_constraints)

    def eval_atmost(self, expr: claripy.ast.bv.BV, most: int) -> typing.List[int]:
        if not self._initialized:
            raise exceptions.ConfigurationError(
                "Solver not available before initialization"
            )
        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing solver not supported once execution begins"
            )
        try:
            return self.state.solver.eval_atmost(expr, most)
        except angr.errors.SimUnsatError:
            raise exceptions.UnsatError("No solutions")
        except angr.errors.SimValueError:
            raise exceptions.SymbolicValueError("Too many solutions")

    def eval_atleast(self, expr: claripy.ast.bv.BV, least: int) -> typing.List[int]:
        if not self._initialized:
            raise exceptions.ConfigurationError(
                "Solver not available before initialization"
            )
        elif self._dirty and not self._linear:
            raise NotImplementedError(
                "Accessing solver not supported once execution begins"
            )
        try:
            return self.state.solver.eval_atleast(expr, least)
        except angr.errors.SimUnsatError:
            raise exceptions.UnsatError("No solutions")
        except angr.errors.SimValueError:
            raise exceptions.SymbolicValueError("Not enough solutions")

    def add_extension(self, name: str, ext: typing.Any) -> None:
        """Add extra data to the machine state.

        This allows users to tie data structures
        to the emulator's execution states,
        allowing path-specific data tracking.

        Only one extension with a given name can be tied
        to a given state.  Usually, extensions are assigned
        before emulation starts, but it's perfectly
        possible to assign them later, either in linear mode,
        or through the emulator stub provided to a hook.

        All extensions must be compatible with `copy.deepcopy()`.

        Arguments:
            name: ID string used to retrieve the extension
            ext: The extension

        Raises:
            KeyError: `name` is already taken
        """

        if not self._initialized:
            if name in self._extensions:
                raise KeyError(f"Extension with name {name} exists")
            self._extensions[name] = ext
        elif self._dirty and not self._linear:
            raise NotImplementedError("Cannot extend state once execution has begun")
        else:
            if name in self.state.scratch.extensions:
                raise KeyError(f"Extension with name {name} exists")
            self.state.scratch.extensions[name] = ext

    def get_extension(self, name: str) -> typing.Any:
        """Fetch extra data from the machine state

        Arguments:
            name: ID string used to retrieve the extension

        Returns:
            Whatever was assigned to `name` using `add_extension`

        Raises:
            KeyError: If no extension exists tied to `name`
        """
        if not self._initialized:
            return self._extensions[name]
        elif self._dirty and not self._linear:
            raise NotImplementedError("Cannot extend state once execution has begun")
        else:
            return self.state.scratch.extensions[name]

    @property
    def byteorder(self) -> typing.Literal["big", "little"]:
        """Get the byteorder string for this platform

        Returns:
            'big' or 'little', appropriately-typed as literals.
        """
        if self.platform.byteorder == platforms.Byteorder.BIG:
            return "big"
        elif self.platform.byteorder == platforms.Byteorder.LITTLE:
            return "little"
        else:
            raise ValueError("Unsupported byteorder!")

    def __repr__(self):
        if self._initialized:
            return f"Angr ({self.mgr})"
        else:
            return "Angr (Uninitialized)"


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
        self._initialized: bool = True
        self._dirty: bool = False
        self._linear: bool = False

        # Force-initialize relevant state from the parent
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
