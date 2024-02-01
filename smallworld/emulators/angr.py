import io
import logging
import typing

import angr
import claripy
import cle

from .. import emulator

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

    def __init__(self):
        self._entry: typing.Optional[angr.SimState] = None

    @property
    def entry(self) -> angr.SimState:
        if self._entry is None:
            raise ValueError("Entry state does not exist")
        return self._entry

    @entry.setter
    def entry(self, e: angr.SimState):
        self._entry = e

    def read_register(self, name: str):
        if self._entry is None:
            raise NotImplementedError(
                "Reading registers not supported once execution begins."
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
        if self._entry is None:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )
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
        if self._entry is None:
            raise NotImplementedError(
                "Reading memory not supported once execution begins."
            )
        else:
            return self._entry.memory.load(addr, size)

    def write_memory(self, addr: int, value: typing.Optional[bytes]):
        if self._entry is None:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )
        elif value is not None:
            v = claripy.BVV(value)
            self._entry.memory.store(addr, v)

    def load(self, code: emulator.Code) -> None:
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
        self.analysis_preinit()

        # Initialize the entrypoint state.
        self._entry = self.proj.factory.entry_state(
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            }
        )

        # Initialize the simulation manager to help us explore.
        self.mgr = self.proj.factory.simulation_manager(self._entry, save_unsat=True)

        # Perform any analysis-specific initialization
        self.analysis_init()

    def step(self):
        if self._entry is not None:
            # If we have not yet started processing,
            # run analysis on the entrypoint state...
            if not self.analysis_step():
                # It asked us to quit before we began
                return False
            # ... and mark that we're no longer in entry.
            self._entry = None
        # Step execution once
        self.mgr.step()
        # Process the results
        return self.analysis_step()

    def run(self):
        while len(self.mgr.active) > 0:
            # Continue stepping as long as we have steps.
            if not self.step():
                break

    def __repr__(self):
        return f"Angr ({self.mgr})"

    def analysis_preinit(self):
        """
        Configure angr platform for analysis

        This is the place to configure features of angr,
        such as plugin defaults, which can't be easily
        changed once the entry state and simulation manager are created.
        """
        pass

    def analysis_init(self):
        """
        Configure initial state and exploration strategy for analysis

        This method will have access to the following fields:

        - `self.proj` will contain the angr project for this experiment
        - `self._entry` will contain the entrypoint SimState
        - `self.mgr` will contain the SimManager for the experiment

        NOTE: You can replace the default `self._entry` state object,
        but you must also reinitialize `self.mgr` for the changes to take effect.
        """
        pass

    def analysis_step(self):
        """
        Analyze a single step of execution.

        This method will have access to the following fields:

        - `self.proj` will contain the angr project for this experiment
        - `self.mgr` will contain the SimManager, holding the current exploration frontier
        """
        return True
