from __future__ import annotations

import io
import logging
import typing

import angr
import claripy
import cle

from .. import exceptions, state
from . import emulator

log = logging.getLogger(__name__)


class PathTerminationSignal(exceptions.AnalysisSignal):
    """Exception allowing an analysis to terminate an execution path."""

    pass


class HookHandler(angr.SimProcedure):
    """SimProcedure for implementing "finish" hooks.

    This requires a callback as an extra kwarg.
    """

    def run(self, *args, callback):
        emu = AngrHookEmulator(self.state)
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

    # Angr doesn't use capstone's arch/mode to specify architecture.
    # Truth be told, I'm not quire sure what it uses...
    CAPSTONE_ARCH_MODE_TO_ANGR = {
        ("x86", "32"): "x86",
        ("x86", "64"): "x86_64",
    }

    def __init__(self, preinit=None, init=None):
        self._entry: typing.Optional[angr.SimState] = None
        self._code: typing.Optional[emulator.Code] = None
        self.mgr: typing.Optional[angr.SimManager] = None
        self.analysis_preinit = preinit
        self.analysis_init = init
        self._reg_init_values = dict()
        self._mem_init_values = dict()
        self._hook_init_values = dict()
        self._plugin_preset = "default"

    @property
    def entry(self) -> angr.SimState:
        if self._entry is None:
            raise ValueError("Entry state does not exist")
        return self._entry

    @entry.setter
    def entry(self, e: angr.SimState):
        self._entry = e

    def get_pages(self, num_pages: int) -> int:
        raise NotImplementedError("Dynamic allco not implemented for angr.")

    def read_register(self, name: str):
        if self._reg_init_values is None:
            raise NotImplementedError(
                "Reading registers not supported once execution begins."
            )
        elif self._entry is None:
            raise NotImplementedError(
                "Reading registers not supported before code is loaded."
            )
        elif name == "pc":
            # Special case: "pc" is aliased to the instruction pointer
            out = self._entry._ip
        elif name not in self._entry.arch.registers:
            log.warn(f"Ignoring read of register {name}; it doesn't exist")
            return None
        else:
            (off, size) = self._entry.arch.registers[name]
            out = self._entry.registers.load(off, size)

        if out.symbolic:
            raise NotImplementedError(
                "Reading symbolic register values is not supported"
            )
        return out.concrete_value

    def write_register(self, reg: str, value: typing.Optional[int]) -> None:
        if self._reg_init_values is None:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )
        elif self._entry is None:
            self._reg_init_values[reg] = value
        elif reg == "pc":
            # Special case: alias "pc" to the instruction pointer
            self._entry.ip = value
        elif reg not in self._entry.arch.registers:
            log.warn(f"Ignoring write to register {reg}; it doesn't exist")
        elif value is not None:
            (off, size) = self._entry.arch.registers[reg]
            v = claripy.BVV(value, size * 8)
            self._entry.registers.store(off, v)

    def read_memory(self, addr: int, size: int):
        # TODO: Figure out a return format.
        # If the loaded data is symbolic,
        # I can't represent it accurately in bytes.
        if self._mem_init_values is None:
            raise NotImplementedError(
                "Reading memory not supported once execution begins."
            )
        elif self._entry is None:
            raise NotImplementedError(
                "Reading memory not supported before code is loaded."
            )
        else:
            return self._entry.memory.load(addr, size)

    def write_memory(self, addr: int, value: typing.Optional[bytes]):
        if self._mem_init_values is None:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )
        elif self._entry is None:
            self._mem_init_values[addr] = value
        elif value is not None:
            v = claripy.BVV(value)
            self._entry.memory.store(addr, v)

    def load(self, code: state.Code) -> None:
        # Keep the code object around for later.
        # I need some of the data contained inside
        self._code = code

        options: typing.Dict[str, typing.Union[str, int]] = {}

        if code.arch is None:
            raise ValueError(f"arch is required: {code}")
        if code.mode is None:
            raise ValueError(f"mode is required: {code}")
        if (code.arch, code.mode) not in self.CAPSTONE_ARCH_MODE_TO_ANGR:
            raise ValueError(f"Architecture {code.arch}:{code.mode} not recognized")

        options["arch"] = self.CAPSTONE_ARCH_MODE_TO_ANGR[(code.arch, code.mode)]

        if code.type is None:
            raise ValueError(f"type is required: {code}")
        options["backend"] = code.type

        if code.base is None:
            raise ValueError(f"base address is required: {code}")
        options["base_addr"] = code.base

        if code.entry is not None:
            if code.entry < code.base or code.entry > code.base + len(code.image):
                raise ValueError(
                    "Entrypoint is not in code: 0x{code.entry:x} vs (0x{code.base:x}, 0x{code.base + len(code.image):x})"
                )
            options["entry_point"] = code.entry
        elif code.type == "blob":
            # Only blobs need a specific entrypoint;
            # ELFs can use the one from the file.
            options["entry_point"] = code.base

        # Turn the image into a byte stream;
        # angr don't do byte strings.
        stream = io.BytesIO(code.image)
        loader = cle.Loader(stream, main_opts=options)
        self.proj = angr.Project(loader)

        # Perform any analysis-specific preconfiguration
        # Some features - namely messing with angr plugin configs
        # must be done before the entrypoint state is created.
        if self.analysis_preinit is not None:
            self.analysis_preinit(self)

        # Initialize the entrypoint state.
        self._entry = self.proj.factory.entry_state(
            plugin_preset=self._plugin_preset,
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            },
        )

        def handle_exit(state):
            raise PathTerminationSignal()

        # Set breakpoints to halt on exit
        exits = [b.stop for b in code.bounds]
        default_exit = code.base + len(code.image)
        if code.type == "blob" and default_exit not in exits:
            # Set a default exit point to keep us from
            # running off the end of the world.
            exits.append(default_exit)
        for exitpoint in exits:
            self._entry.inspect.b(
                "instruction", instruction=exitpoint, action=handle_exit
            )

        # Replay any value initialization
        # we captured before this
        for reg, val in self._reg_init_values.items():
            self.write_register(reg, val)
        for addr, val in self._mem_init_values.items():
            self.write_memory(addr, val)
        for addr, (callback, finish) in self._hook_init_values.items():
            print(f"Hooking {hex(addr)}")
            self.hook(addr, callback, finish)

        # Initialize the simulation manager to help us explore.
        self.mgr = self.proj.factory.simulation_manager(self._entry, save_unsat=True)

        # Perform any analysis-specific initialization
        if self.analysis_init is not None:
            self.analysis_init(self)

    def hook(
        self,
        address: int,
        callback: typing.Callable[[emulator.Emulator], None],
        finish: bool = False,
    ) -> None:
        if self._entry is None:
            self._hook_init_values[address] = (callback, finish)
        elif finish:
            # Use the power of SimProcedures to finish out the frame once we're done
            hook = HookHandler(callback=callback)
            self.proj.hook(address, hook, 0)
        else:
            # Otherwise, hook our one instruction
            @self.proj.hook(address, length=0)
            def hook_handler(state):
                emu = AngrHookEmulator(state)
                callback(emu)

    def step(self):
        # As soon as we start executing, disable value access
        self._reg_init_values = None
        self._mem_init_values = None

        # Step execution once
        self.mgr.step()

        # Filter out exited or invalid states
        self.mgr.move(
            from_stash="active",
            to_stash="unconstrained",
            filter_func=lambda x: (x._ip.symbolic),
        )
        self.mgr.move(
            from_stash="active",
            to_stash="deadended",
            filter_func=lambda x: x._ip.concrete_value
            in [b.stop for b in self._code.bounds],
        )

        # Test for exceptional states
        if len(self.mgr.errored) > 0:
            raise exceptions.EmulationError(self.mgr.errored[0].error)

        # Stop if we're out of active states
        return len(self.mgr.active) != 0

    def run(self):
        log.info("Starting angr run")
        while len(self.mgr.active) > 0:
            # Continue stepping as long as we have steps.
            if not self.step():
                break

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
        return self.pagesize

    def __init__(self, state: angr.SimState, pagesize: int = 0x1000):
        self.state: angr.SimState = state
        self.pagesize: int = pagesize

    def read_register(self, name: str) -> int:
        if name == "pc":
            # Special case: alias "pc" to the instruction pointer
            res = self.state.ip
        elif name not in self.state.arch.registers:
            raise exceptions.AnalysisError(f"Register {name} does not exist")
        else:
            # Extract the value from the register file
            (reg_addr, reg_size) = self.state.arch.registers[name]
            res = self.state.registers.load(reg_addr, reg_size)

        # Need a bit of different handling for symbolic or concrete registers
        if res.symbolic:
            raise NotImplementedError(f"Register {name} is symbolic")
        else:
            return res.concrete_value

    def write_register(self, name: str, value: typing.Optional[int]) -> None:
        if value is None:
            raise NotImplementedError("Not sure how to store non-specified values")

        if name == "pc":
            # Special case: alias "pc" to the instruction pointer
            self.state.ip = value
        elif name not in self.state.arch.registers:
            raise exceptions.AnalysisError(f"Register {name} does not exist")
        else:
            # Save the value to the register file
            (reg_addr, reg_size) = self.state.arch.registers[name]
            val = claripy.BVV(value, reg_size)
            self.state.registers.store(reg_addr, val)

    def get_pages(self, num_pages: int) -> int:
        raise NotImplementedError("Dynamic alloc not implemented for angr")

    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        # Load data from memory.
        res = self.state.memory.load(address, size)
        if res.symbolic:
            raise NotImplementedError(
                f"Memory range [{address}:{address + size}] is symbolic"
            )
        else:
            # Annoyingly, there isn't an easy way to convert BVV to bytes.
            return bytes(
                [res.get_byte(i).concrete_value for i in range(0, len(res) // 8)]
            )

    def write_memory(self, address: int, value: typing.Optional[bytes]) -> None:
        if value is None:
            raise NotImplementedError(
                "Writing symbolic memory not implemented for angr"
            )
        else:
            val = claripy.BVV(value)
        self.state.memory.store(address, val)

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
        # TODO: Should this hook only this state, or all states?
        # Both are doable, but which one makes sense?
        raise NotImplementedError("Hooking not implemented inside a hook.")

    def run(self) -> None:
        raise NotImplementedError("Running not supported inside a hook.")

    def step(self) -> bool:
        raise NotImplementedError("Stepping not supported inside a hook.")

    def __repr__(self):
        return f"Angr Hook ({self.state})"
