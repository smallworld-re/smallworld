import logging

from .. import emulators, hinting, state
from . import analysis
from .angr.nwbt import configure_nwbt_plugins, configure_nwbt_strategy
from .angr.utils import print_state

log = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)


class AngrNWBTAnalysis(analysis.Analysis):
    name = "angr-nwbt"
    description = "Angr-based Not-Written-By-Trace detection and correction"
    version = "0.0.1"

    def __init__(self, *args, initfunc=None, **kwargs):
        self.initfunc = initfunc

    def analysis_preint(self, emu):
        configure_nwbt_plugins(emu)

    def analysis_init(self, emu):
        configure_nwbt_strategy(emu)
        if self.initfunc is not None:
            self.initfunc(self, emu.entry)

    def run(self, state: state.CPU):
        emu = emulators.AngrEmulator(self.analysis_preint, self.analysis_init)
        state.apply(emu)

        while self.step(emu):
            pass

    def _report_status(self, emu):
        for st in emu.mgr.unconstrained:
            hint = hinting.OutputHint(
                message="State left the program",
                registers=st.registers.create_hint(),
                memory=st.memory.create_hint(),
            )
            hinter.info(hint)
        for st in emu.mgr.deadended:
            hint = hinting.OutputHint(
                message="State exited due to breakpoint",
                registers=st.registers.create_hint(),
                memory=st.memory.create_hint(),
            )
            hinter.info(hint)
        for st in emu.mgr.unsat:
            hint = hinting.OutputHint(
                message="State cannot continue; constraints unsat",
                registers=st.registers.create_hint(),
                memory=st.memory.create_hint(),
            )
            hinter.info(hint)
        for err in emu.mgr.errored:
            print_state(log.info, err.state, "error")
            log.error(
                "\tError:",
                exc_info=(type(err.error), err.error, err.error.__traceback__),
            )
        log.info(f"Summary: {emu.mgr}")

    def step(self, emu):
        # Report our current status
        self._report_status(emu)
        # In our case, return states are unconstrained.
        emu.mgr.move(from_stash="deadended", to_stash="done")
        emu.mgr.move(from_stash="unconstrained", to_stash="done")
        # Drop unsat states once we've logged them.
        emu.mgr.drop(stash="unsat")
        if not emu.step():
            self._report_status(emu)
            return False
        return True
