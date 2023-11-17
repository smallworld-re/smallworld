import logging
from .angr import AngrExecutor
from ..analyses.angr.typedefs import TypeDefPlugin
from ..analyses.angr.nwbt import NWBTMemoryPlugin, NWBTExplorationTechnique
from ..analyses.angr.utils import print_state
from ..analyses.utils.tui import SimpleTUI


class AngrNWBTExecutor(AngrExecutor):
    """
    Executor for messing with NWBT value detection.

    Currently, this is a semi-manual exploration.
    The executor will ask the user to help
    populate data types and values for
    uninitialized variables.

    The goal is to collect the type bindings,
    and package them up into an environment
    once we're done.
    """

    l = logging.getLogger("smallworld.nwbt")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.step_tui = SimpleTUI()
        self.step_tui.add_case("continue", lambda: True, hint="Continue analysis")
        self.step_tui.add_case("quit", lambda: False, hint="Quit analysis")

    def analysis_preinit(self):
        # Configure angr our custom memory plugin
        NWBTMemoryPlugin.register_default("sym_memory")
        TypeDefPlugin.register_default("typedefs")

    def analysis_init(self):
        # Configure the simulation manager to use our exploration strategy
        self.mgr.use_technique(NWBTExplorationTechnique())

    def analysis_step(self):
        # Log the current frontier
        for state in self.mgr.active:
            print_state(self.l.info, state, "active")
        for state in self.mgr.unconstrained:
            print_state(self.l.info, state, "exited")
        for state in self.mgr.deadended:
            print_state(self.l.info, state, "halted")
        for state in self.mgr.unsat:
            print_state(self.l.info, state, "unsat")
        for err in self.mgr.errored:
            print_state(self.l.info, err.state, "error")
            self.l.error(
                "\tError:",
                exc_info=(type(err.error), err.error, err.error.__traceback__),
            )
            err.debug()
        self.l.info(f"Summary: {self.mgr}")
        # In our case, return states are unconstrained.
        self.mgr.move(from_stash="deadended", to_stash="done")
        self.mgr.move(from_stash="unconstrained", to_stash="done")
        # Drop unsat states once we've logged them.
        self.mgr.drop(stash="unsat")

        return self.step_tui.handle("continue", set())
