import logging

from .. import emulators, state
from . import analysis
from .angr.nwbt import NWBTExplorationTechnique, NWBTMemoryPlugin
from .angr.typedefs import TypeDefPlugin
from .angr.utils import print_state

log = logging.getLogger(__name__)


class AngrNWBTAnalysis(analysis.Analysis):
    name = "angr-nwbt"
    description = "Angr-based Not-Written-By-Trace detection and correction"
    version = "0.0.1"

    def __init__(self, *args, initfunc=None, **kwargs):
        self.initfunc = initfunc

    def analysis_preint(self, emu):
        NWBTMemoryPlugin.register_default("sym_memory")
        TypeDefPlugin.register_default("typedefs")

    def analysis_init(self, emu):
        emu.mgr.use_technique(NWBTExplorationTechnique())
        if self.initfunc is not None:
            self.initfunc(self, emu.entry)

    def run(self, image: emulators.Code, state: state.CPU):
        emu = emulators.AngrEmulator(self.analysis_preint, self.analysis_init)
        emu.load(image)
        state.apply(emu)

        while self.step(emu):
            pass

    def step(self, emu):
        for st in emu.mgr.active:
            print_state(log.info, st, "active")
        for st in emu.mgr.unconstrained:
            print_state(log.info, st, "exited")
        for st in emu.mgr.deadended:
            print_state(log.info, st, "halted")
        for st in emu.mgr.unsat:
            print_state(log.info, st, "unsat")
        for err in emu.mgr.errored:
            print_state(log.info, err.state, "error")
            log.error(
                "\tError:",
                exc_info=(type(err.error), err.error, err.error.__traceback__),
            )
        log.info(f"Summary: {emu.mgr}")

        # In our case, return states are unconstrained.
        emu.mgr.move(from_stash="deadended", to_stash="done")
        emu.mgr.move(from_stash="unconstrained", to_stash="done")
        # Drop unsat states once we've logged them.
        emu.mgr.drop(stash="unsat")

        return emu.step()
