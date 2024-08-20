import angr


def print_state(log, state, tag):
    """Pretty-print data contained in an execution state

    This prints useful registers, memory, and state constraints.
    """
    log(f"{state}: {tag}")
    if not state.regs.rip.symbolic:
        try:
            block = state.block()
            block.pp()
        except angr.errors.SimEngineError:
            log("(Invalid IP!)")
    else:
        log("(Exit state)")
    log("Registers")
    state.registers.pp(log)
    log("Memory")
    state.memory.pp(log)
    log("Constraints:")
    for expr in state.solver.constraints:
        log(f"\t{expr}")
    state.typedefs.pp(log)
