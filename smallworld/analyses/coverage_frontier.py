from analysis import Analysis
from hinting import Hint, TraceExecutionHint, BranchesHint, CoverageFrontierHint


class CoverageFrontier(Analysis):
    name = "coverage_frontier"
    description = "deduce coverage frontier with respect to a set of traces"
    version = "0.0.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.edges = {}
        self.branches = set([])
        self.hinter.register(TraceExecutionHint, self.monitor_branches)

    def monitor_branches(self, hint: Hint) -> None:
        # examine execution trace and collect any branch information
        if isinstance(hint, TraceExecutionHint):
            lb = None
            for element in hint.trace:
                # print(f"hint: {element}")
                if lb is not None:
                    if lb.pc not in self.edges:
                        self.edges[lb.pc] = set([])
                    self.edges[lb.pc].add(element.pc)
                    lb = None
                if element.branch:
                    # instructions that are branches
                    self.branches.add(element.pc)
                    lb = element

    def run(self, machine):
        hint = BranchesHint(
            message="Branches encountered", branches=list(self.branches)
        )
        self.hinter.send(hint)
        # analyze to get coverage frontier,
        # i.e., set of half-covered  conditionals
        coverage_frontier = set([])
        for branch in self.branches:
            if (len(self.edges[branch])) == 1:
                coverage_frontier.add(branch)
        hint = CoverageFrontierHint(
            message="Coverage frontier (half-covered conditionals) for a set of execution traces",
            coverage_frontier=list(coverage_frontier),
        )
        self.hinter.send(hint)
