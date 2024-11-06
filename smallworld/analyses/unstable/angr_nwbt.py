import logging

from ... import emulators, hinting, state
from .. import analysis
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

    def analysis_preinit(self, emu):
        log.info("Registering plugins")
        configure_nwbt_plugins(emu)

    def analysis_init(self, emu):
        configure_nwbt_strategy(emu)
        if self.initfunc is not None:
            self.initfunc(self, emu.entry)

    def run(self, machine: state.Machine):
        cpu = machine.get_cpu()
        emu = emulators.AngrEmulator(
            cpu.platform, preinit=self.analysis_preinit, init=self.analysis_init
        )
        machine.apply(emu)

        # Extract typedef info from the CPU state,
        # and bind it to the machine state
        for item in cpu:
            if isinstance(item, state.Register):
                if item.get_type() is not None:
                    log.debug(f"Applying type for {item}")
                    emu.state.typedefs.bind_register(item.name, item.get_type())
        for item in machine:
            if isinstance(item, state.memory.code.Executable):
                # TODO: Code is also memory, so it should have types...?
                pass
            elif isinstance(item, state.memory.Memory):
                for offset, value in item.items():
                    if value.get_type() is not None:
                        addr = item.address + offset
                        log.debug(f"Applying type for {hex(addr)}")
                        emu.state.typedefs.bind_address(addr, value.get_type())
            else:
                if not isinstance(item, state.cpus.CPU) and item.type is not None:
                    raise NotImplementedError(
                        f"Applying typedef {item.get_type()} of type {type(item)} not implemented"
                    )

        while (self.steps_left is None or self.steps_left > 0) and not self.step(emu):
            if self.steps_left is not None:
                self.steps_left -= 1

    def _report_status(self, emu):
        for st in emu.mgr.active:
            dis = "\r".join(map(str, st.block().disassembly.insns))
            log.debug(f"Active state: {dis}")
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
