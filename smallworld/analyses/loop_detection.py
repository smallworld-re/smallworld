
"""Assumptions

Listens for TraceExecution hints.
Examines each for evidence of loops.

A loop has a *head* (first instruction, target of back-edge).

We also define, for each loop, a number of *strands*, which are
sequences of instructions starting at loop head and ending at
back-edge to loop head.

This analysis examines one or more TraceExecution hints, identifies
loop head + strands in each, and collects all strands for same head.

Thus, it should, given enough traces with enough coverage, fully
characterize all loops in code.

"""


class LoopDetection(analysis.Analysis):
    name = "loop_detection"
    description = "Analyze traces and detect loops"
    version = "0.0.1"
    
    def __init__(
        self,
        *args,
        min_iter: int = 3,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.min_iter = min_iter
        self.hinter.register(TraceExecutionHint, self.collect_traces)
        self.traces = []        

    def collect_traces(self, hint: Hint) -> None:
        if isinstance(hint, TraceExecutionHint):
            self.traces.append(hint)

    def run(self, machine: Machine) -> None:
        # NB: this analysis doesnt use machine.  it assumes something
        # else is generating TraceExecutionHints
        self.heads = set([])
        for teh in self.traces:
            last_pc = None
            pcs = set([])
            for te in teh.trace:
                # if pc jumps back to a lesser pc and that pc is in
                # set already observed then this is a back-edge and
                # te.pc is a loop head
                if last_pc is not None and last_pc > te.pc and te.pc in pcs:
                    # back-edge
                    self.heads.add(te.pc)
                pcs.add(te.pc)
                last_pc = te.pc                    
        self.strands = []
        for teh in self.traces:
            collecting = False
            for te in teh.trace: 
                if (collecting is None) and (te.pc in self.heads):
                    # start a new strand
                    collecting = te.pc
                    strand = []
                if (collecting is not None) and te.pc == collecting:
                    # we hit the back-edges
                    # save the strand
                    if te.pc not in self.strands:
                        self.strands[te.pc] = set([])
                        self.strands[te.pc].add(tuple(strand))
                    collecting = None
                    continue
                if collecting:
                    strand.append(te)
        print(f"Found {len(self.heads)} loops in {len(self.traces}) traces")
        for pc, strand in self.heads.items():
            print(f"  loop strand:", end="")
            for te in strand:
                print(f" {te.pc:x}")
            print("")
