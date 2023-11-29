import angr
import claripy
import logging
import typing

from ..executor import Executor

log = logging.getLogger(__name__)


class AngrExecutor(Executor):
    """
    Superclass for angr-based micro executors

    This is primarily designed to support symbolic execution,
    although subclasses can configure angr however they like.

    One challenge with symbolic execution is that
    it doesn't work on a single machine state,
    but rather multiple machine states representing
    parallel execution paths.

    As such, this interface doesn't yet fully support
    all features of the base Executor class;
    it's not clear what reading or writing machine state
    means when there's more than one state.
    """

    def __init__(
        self, infile=None, base=None, entry=None, arch=None, fmt=None, **kwargs
    ):
        # Create the angr project from the input file
        main_opts = {"backend": fmt, "arch": arch, "base_addr": base}
        if entry is not None:
            main_opts["entry_point"] = entry
        elif fmt == "blob":
            raise ValueError("Blob files need an entrypoint")

        self.proj = angr.Project(infile.as_posix(), main_opts=main_opts)

        # Perform any analysis-specific preconfiguration
        # Some features - namely messing with angr plugin configs
        # must be done before the entrypoint state is created.
        self.analysis_preinit()

        # Initialize the entrypoint state.
        self.entry = self.proj.factory.entry_state(
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            }
        )

        # Initialize the simulation manager to help us explore.
        self.mgr = self.proj.factory.simulation_manager(self.entry, save_unsat=True)

        # Perform any analysis-specific initialization
        self.analysis_init()

    def read_register(self, name: str):
        if self.entry is None:
            raise NotImplementedError(
                "Reading registers not supported once execution begins."
            )
        elif name not in self.entry.arch.registers:
            log.warn(f"Ignoring read of register {name}; it doesn't exist")
            return None
        else:
            (off, size) = self.entry.arch.registers[name]
            out = self.entry.registers.load(off, size)
            if out.symbolic:
                raise NotImplementedError(
                    "Reading symbolic register values is not supported"
                )
            return out.concrete_value

    def write_register(self, reg: str, value: typing.Optional[int]) -> None:
        if self.entry is None:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )
        elif reg not in self.entry.arch.registers:
            log.warn(f"Ignoring write to register {reg}; it doesn't exist")
        else:
            (off, size) = self.entry.arch.registers[reg]
            v = claripy.BVV(value, size * 8)
            self.entry.registers.store(off, v)

    def read_memory(self, addr: int, size: int):
        # TODO: Figure out a return format.
        # If the loaded data is symbolic,
        # I can't represent it accurately in bytes.
        if self.entry is None:
            raise NotImplementedError(
                "Reading memory not supported once execution begins."
            )
        else:
            return self.entry.memory.load(addr, size)

    def write_memory(self, addr: int, value: typing.Optional[bytes]):
        if self.entry is None:
            raise NotImplementedError(
                "Writing registers not supported once execution begins."
            )
        elif value is not None:
            # Claripy expresses sizes in bits, hence the '* 8'.
            v = claripy.BVV(value, len(value) * 8)
            self.entry.memory.store(addr, v)

    def load(self, image: bytes, base: int) -> None:
        # TODO: Unify the object loading workflow.
        # I need to look into how angr takes data; it might be able to take bytes.
        raise NotImplementedError(
            "Direct blob loading not yet supported for angr.  Use the constructor."
        )

    def step(self):
        if self.entry is not None:
            # If we have not yet started processing,
            # run analysis on the entrypoint state...
            if not self.analysis_step():
                # It asked us to quit before we began
                return False
            # ... and mark that we're no longer in entry.
            self.entry = None
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
        - `self.entry` will contain the entrypoint SimState
        - `self.mgr` will contain the SimManager for the experiment

        NOTE: You can replace the default `self.entry` state object,
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
