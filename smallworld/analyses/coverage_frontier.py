import typing
from collections import defaultdict

from smallworld.state.state import Machine

from ..hinting import BranchesHint, CoverageFrontierHint, Hint, TraceExecutionHint
from .analysis import Analysis
from .trace_execution_types import TraceElement

Edges = typing.NewType("Edges", typing.Dict[int, typing.Any])


# branches: set of pcs that are branch instructions
# edges: set of edges observed
def compute_coverage_frontier(
    branches: typing.Set[int], edges: Edges
) -> typing.Set[int]:
    # analyze to get coverage frontier,
    # i.e., set of half-covered conditionals
    coverage_frontier = set([])
    for branch_pc in branches:
        if branch_pc in edges:
            if (len(edges[branch_pc])) == 1:
                # a branch that only has one successor (observed) is a
                # half-covered conditional
                coverage_frontier.add(branch_pc)
    return coverage_frontier


# update pcs, branches, and edges
# given this trace
def update_coverage(
    trace: typing.List[TraceElement],
    pcs: typing.Any,  # count for each pc observed
    branches: typing.Set[int],  # set of branch instr
    edges: Edges,  # dict: from_pc -> count for each to_pc observed
) -> None:
    last_pc = None
    for te in trace:
        pcs[te.pc] += 1
        if last_pc is not None:
            if last_pc not in edges:
                edges[last_pc] = defaultdict(int)
            edges[last_pc][te.pc] += 1
        if te.branch:
            branches.add(te.pc)
        last_pc = te.pc


class CoverageFrontier(Analysis):
    name = "coverage_frontier"
    description = "deduce coverage frontier with respect to a set of traces"
    version = "0.0.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pcs = defaultdict(int)  # count for pcs across all traces
        self.edges = {}  # edges[from_pc] is set of to_pcs, thus edges
        self.branches = set([])  # set of pcs that are branch instructions
        self.hinter.register(TraceExecutionHint, self.monitor_branches)
        self.num_traces = 0

    def monitor_branches(self, hint: Hint) -> None:
        # examine execution trace and collect any branch information
        if isinstance(hint, TraceExecutionHint):
            update_coverage(hint.trace, self.pcs, self.branches, self.edges)
            self.num_traces += 1

    def run(self, machine: Machine) -> None:
        # run this *after* all TraceExecutionHints have been generated
        # by whatever and collected by this analysis
        self.hinter.send(
            BranchesHint(message="Branches encountered", branches=list(self.branches))
        )
        coverage_frontier = compute_coverage_frontier(self.branches, self.edges)
        edges_list = []
        for start in self.edges.keys():
            p = (start, list(self.edges[start]))
            edges_list.append(p)
        self.hinter.send(
            CoverageFrontierHint(
                message="Coverage frontier (half-covered conditionals) for a set of execution traces",
                coverage_frontier=list(coverage_frontier),
                edges=edges_list,
                branches=list(self.branches),
                num_traces=self.num_traces,
            )
        )
