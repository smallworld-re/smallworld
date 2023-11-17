# type ignore

import angr
import argparse
import pathlib


class SmallWorldMemoryPlugin(angr.storage.DefaultMemory):
    """
    Wrapper for symbolic memory
    """

    def __init__(self, **kwargs):
        print(f"Memory plugin initialized: {kwargs}")
        super().__init__(**kwargs)

    def _default_value(self, addr, size, **kwargs):
        res = super()._default_value(addr, size, **kwargs)
        if self.id == "reg":
            reg_name = self.state.arch.register_size_names[(addr, size)]
            print(f"Default Register: {reg_name} := {res}, kwargs: {kwargs}")
        else:
            print(f"Default Memory: {addr:x}[{size}] := {res}, kwargs: {kwargs}")
        return res


SmallWorldMemoryPlugin.register_default("sym_memory")


def parseint(val):
    """
    Convert a hex or decimal string into an int
    """
    if val.startswit("0x"):
        return int(val[2:], 16)
    else:
        return int(val)


def mem_read_callback(state):
    """
    Log memory reads
    """
    memory_address = state.inspect.mem_read_address
    memory_len = state.inspect.mem_read_length
    memory_expr = state.inspect.mem_read_expr
    print(f"mem_read {memory_address}[{memory_len}] = {memory_expr}")


def symbolic_create_callback(state):
    """
    Log creation of a new symbol
    """
    print(f"New Symbol: {state.inspect.symbolic_expr}")


def addr_collapse_callback(state):
    addrs = state.inspect.address_concretization_result
    if addrs is not None:
        addrs = list(map(hex, addrs))
        print(f"addr collapse: {state.inspect.address_concretization_expr} := {addrs}")


reg_list = [
    "rip",
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rdi",
    "rsi",
    "rsp",
    "rbp",
    "r8",
    "r9",
    "r10",
    "r11",
    "xmm0",
    "xmm1",
]


def print_state(state, tag):
    """
    Print a summary of a state
    """
    print(f"{state}: {tag}")
    if not state.regs.rip.symbolic:
        state.block().pp()
    else:
        print("(Exit state)")
    print("Registers")
    for reg in reg_list:
        print(f"\t{reg}: {state.regs.get(reg)}")
    print("Constraints:")
    for expr in state.solver.constraints:
        print(f"\t{expr}")


def create_project(path, base, entry):
    """
    Create an angr project.

    - Load the input file as a blob; all code, no format
    - Assume AMD64
    - Give it the base and entry addresses specified in args
    """
    return angr.Project(
        path.as_posix(),
        main_opts={
            "backend": "blob",
            "arch": "x86_64",
            "base_addr": base,
            "entry_point": entry,
        },
    )


def create_entrypoint(proj):
    # Create an entry state.
    # By default, set it to fill uninitialized values with symbols.
    # It will do this anyway, but this keeps it from complaining.
    entry = proj.factory.entry_state(
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        }
    )

    # Set up inspection points.
    entry.inspect.b("mem_read", when=angr.BP_AFTER, action=mem_read_callback)
    entry.inspect.b(
        "symbolic_variable", when=angr.BP_AFTER, action=symbolic_create_callback
    )
    entry.inspect.b(
        "address_concretization", when=angr.BP_AFTER, action=addr_collapse_callback
    )
    return entry


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--base", type=parseint, default=0x10000000)
    parser.add_argument("-e", "--entry", type=parseint)
    parser.add_argument(
        "--single-step", action=argparse.BooleanOptionalAction, default=False
    )
    parser.add_argument("infile", type=pathlib.Path)

    args = parser.parse_args()
    if args.entry is None:
        args.entry = args.base
    else:
        args.entry = args.base + args.entry
    return args


if __name__ == "__main__":
    args = parse_args()
    proj = create_project(args.infile, args.base, args.entry)

    entry = create_entrypoint(proj)
    mgr = proj.factory.simulation_manager(entry, save_unsat=True)
    while len(mgr.active) > 0:
        # Step through execution as long as there are steps to take.
        if args.single_step:
            # this might break things on MIPS
            # this might cause the results to be different because it doesn't do cross instruction optimization
            # run with opt_level=0 to duplicate optimization effects on a basic block level
            mgr.step(num_inst=1)
        else:
            mgr.step()
        # Log the states for this step
        for state in mgr.active:
            print_state(state, "active")
        for state in mgr.unconstrained:
            print_state(state, "exited")
        for state in mgr.unsat:
            print_state(state, "unsat")

        # Move defunct states to the side
        mgr.move(from_stash="unconstrained", to_stash="deadended")
        mgr.move(from_stash="unsat", to_stash="deadended")

        # Check with the user to see if we should keep going.
        # (Ctrl-C on angr causes endless stack traces)
        if input("Continue?") in {"n", "N", "q", "Q"}:
            break
