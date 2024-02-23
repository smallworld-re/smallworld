from __future__ import annotations

import io
import logging
import typing

import angr
import claripy
import cle

from .. import state
from . import emulator

log = logging.getLogger(__name__)


class AngrEmulator(emulator.Emulator):
    """
    Superclass for angr-based emulators.

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

    def __init__(self, preinit=None, init=None):
        self._entry: typing.Optional[angr.SimState] = None
        self._code: typing.Optional[emulator.Code] = None
        self.mgr: typing.Optional[angr.SimManager] = None
        self.analysis_preinit = preinit
        self.analysis_init = init
        self._reg_init_values = dict()
        self._mem_init_values = dict()

    @property
    def entry(self) -> angr.SimState:
        if self._entry is None:
            raise ValueError("Entry state does not exist")
        return self._entry

    @entry.setter
    def entry(self, e: angr.SimState):
        self._entry = e

    def read_register(self, name: str):
        if self._reg_init_values is None:
            raise NotImplementedError(
                "Reading registers not supported once execution begins."
            )
        elif self._entry is None:
            raise NotImplementedError(
                "Reading registers not supported before code is loaded."
            )
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
        options["arch"] = code.arch

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
        self.analysis_preinit(self)

        # Initialize the entrypoint state.
        self._entry = self.proj.factory.entry_state(
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            }
        )

        # Replay any value initialization
        # we captured before this
        for reg, val in self._reg_init_values.items():
            self.write_register(reg, val)
        for addr, val in self._mem_init_values.items():
            self.write_memory(addr, val)

        # Initialize the simulation manager to help us explore.
        self.mgr = self.proj.factory.simulation_manager(self._entry, save_unsat=True)

        # Perform any analysis-specific initialization
        self.analysis_init(self)

    def step(self):
        # As soon as we start executing, disable value access
        self._reg_init_values = None
        self._mem_init_values = None

        # Step execution once
        self.mgr.step()

        # Filter out exited or invalid states
        code_end = self._code.base + len(self._code.image)
        self.mgr.move(
            from_stash="active",
            to_stash="unconstrained",
            filter_func=lambda x: (
                x._ip.symbolic
                or x._ip.concrete_value < self._code.base
                or x._ip.concrete_value >= code_end
            ),
        )
        self.mgr.move(
            from_stash="active",
            to_stash="deadended",
            filter_func=lambda x: x._ip.concrete_value in self._code.exits,
        )

        # Stop if we're out of active states
        return len(self.mgr.active) != 0

    def run(self):
        while len(self.mgr.active) > 0:
            # Continue stepping as long as we have steps.
            if not self.step():
                break

    def __repr__(self):
        return f"Angr ({self.mgr})"
