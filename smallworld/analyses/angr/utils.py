import angr


def print_state(l, state, tag):
    """
    Pretty-print data contained in an execution state

    This prints useful registers, memory, and state constraints.
    """
    l(f"{state}: {tag}")
    if not state.regs.rip.symbolic:
        try:
            block = state.block()
            block.pp()
        except angr.errors.SimEngineError:
            l("(Invalid IP!)")
    else:
        l("(Exit state)")
    l("Registers")
    state.registers.pp(l)
    l("Memory")
    state.memory.pp(l)
    l("Constraints:")
    for expr in state.solver.constraints:
        l(f"\t{expr}")
    state.typedefs.pp(l)
