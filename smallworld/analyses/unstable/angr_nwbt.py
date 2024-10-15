import logging

from .. import emulators, hinting, state
from . import analysis
from .angr.nwbt import configure_nwbt_plugins, configure_nwbt_strategy
from .angr.utils import print_state

log = logging.getLogger(__name__)
hinter = hinting.get_hinter(__name__)


class AngrNWBTAnalysis(analysis.Analysis):
    name = "angr-nwbt"
    description = "Angr-based Not-Written-By-Trace detection and correction"
    version = "0.0.1"

    def __init__(self, *args, initfunc=None, max_steps=500, **kwargs):
        self.steps_left = max_steps
        self.initfunc = initfunc

    def analysis_preint(self, emu):
        configure_nwbt_plugins(emu)

    def analysis_init(self, emu):
        configure_nwbt_strategy(emu)
        if self.initfunc is not None:
            self.initfunc(self, emu.entry)

    def run(self, cpu: state.CPU):
        emu = emulators.AngrEmulator(
            cpu.arch, cpu.mode, cpu.byteorder, self.analysis_preint, self.analysis_init
        )
        cpu.apply(emu)

        # Extract typedef info from the CPU state,
        # and bind it to the machine state
        for name, item in cpu.members().items():
            if isinstance(item, state.Register):
                if item.type is not None:
                    log.debug(f"Applying type for {item}")
                    emu.state.typedefs.bind_register(name, item.type)
            elif isinstance(item, state.Memory):
                for offset, typedef in item.type.items():
                    addr = item.address + offset
                    log.debug(f"Applying type for {hex(addr)}")
                    emu.state.typedefs.bind_address(addr, typedef)
            elif isinstance(item, state.Code):
                # TODO: Code is also memory, so it should have types...?
                pass
            else:
                if item.type is not None:
                    raise NotImplementedError(
                        f"Applying typedef {item.type} for {name} of type {type(item)} not implemented"
                    )

        while (self.steps_left is None or self.steps_left > 0) and not self.step(emu):
            if self.steps_left is not None:
                self.steps_left -= 1

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
        self._report_status(emu)
        return emu.step()
