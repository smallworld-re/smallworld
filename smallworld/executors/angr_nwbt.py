import logging
from .angr import AngrExecutor
from ..analyses.angr.typedefs import TypeDefPlugin
from ..analyses.angr.nwbt import NWBTMemoryPlugin, NWBTExplorationTechnique
from ..analyses.angr.utils import print_state
from ..analyses.utils.tui import SimpleTUI

log = logging.getLogger(__name__)


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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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
            print_state(log.info, state, "active")
        for state in self.mgr.unconstrained:
            print_state(log.info, state, "exited")
        for state in self.mgr.deadended:
            print_state(log.info, state, "halted")
        for state in self.mgr.unsat:
            print_state(log.info, state, "unsat")
        for err in self.mgr.errored:
            print_state(log.info, err.state, "error")
            log.error(
                "\tError:",
                exc_info=(type(err.error), err.error, err.error.__traceback__),
            )
            err.debug()
        log.info(f"Summary: {self.mgr}")
        # In our case, return states are unconstrained.
        self.mgr.move(from_stash="deadended", to_stash="done")
        self.mgr.move(from_stash="unconstrained", to_stash="done")
        # Drop unsat states once we've logged them.
        self.mgr.drop(stash="unsat")

        return self.step_tui.handle("continue", set())
