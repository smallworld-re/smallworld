"""Simple detection of loops given traces.

Assumptions:

* Listens for TraceExecution hints. 

* Examines each for evidence of loops.

* Loops have a head (first instruction) and are succeeded by
  instructions (at higher pc) which have back-edges to the loops.
  Yes, this disincludes repz and any other single-instruction loops.
  This is a graph-based analysis

A loop has a *head* (first instruction, target of back-edge).

For a particular iteration of a loop, we define a *strand* for that
loop which is a sequence of instructions starting at loop head and
ending at back-edge to loop head.

For each head there is one or more strands (since there can be
branches and loops within that loop.

This analysis examines one or more TraceExecution hints, identifies
loop head + strands in each, and collects all strands for same head.

Thus, it should, given enough traces with enough coverage, fully
characterize all loops in code.

Output is zero or more LoopHint(s). Each of these contains loop head
instruction address, plus any strands discovered for that loop.

XXX Um, just realized that this analysis will likely *NOT* work quite
right if loops are nested!  TO DO.

"""

import typing

from smallworld.analyses import Analysis
from smallworld.hinting import Hint
from smallworld.hinting.hints import LoopHint, TraceExecutionHint
from smallworld.state import Machine


class LoopDetection(Analysis):
    name = "loop_detection"
    description = "Analyze traces and detect loops"
    version = "0.0.1"

    def __init__(
        self,
        *args,
        min_iter: int = 2,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.min_iter = min_iter
        self.hinter.register(TraceExecutionHint, self.collect_traces)
        self.traces: typing.List[TraceExecutionHint] = []

    def collect_traces(self, hint: Hint) -> None:
        if isinstance(hint, TraceExecutionHint):
            self.traces.append(hint)

    def run(self, machine: Machine) -> None:
        # NB: this analysis doesnt use machine; it assumes something
        # else is generating TraceExecutionHints.
        # First pass over traces to get loop heads
        heads: typing.Set[int] = set([])
        for teh in self.traces:
            last_pc = None
            pcs = set([])
            for te in teh.trace:
                # if pc jumps back to a lesser pc and that pc is in
                # set already observed then this is a back-edge and
                # te.pc is a loop head
                if last_pc is not None and te.pc < last_pc and te.pc in pcs:
                    # back-edge to a loop head
                    heads.add(te.pc)
                pcs.add(te.pc)
                last_pc = te.pc
        # second pass to get loop strands per head
        strands: typing.Dict[int, typing.Dict[int, typing.List[int]]] = {}
        for teh in self.traces:
            collecting = False
            head = None
            strand = []
            for te in teh.trace:
                if (not collecting) and (te.pc in heads):
                    # start a new strand
                    collecting = True
                    head = te.pc
                    strand = [te.pc]
                    continue
                if collecting:
                    strand.append(te.pc)
                if collecting and te.pc == head:
                    # we hit the back-edges
                    # save unique strands
                    sh = hash(tuple(strand))
                    if te.pc not in strands:
                        strands[te.pc] = {}
                    strands[te.pc][sh] = strand
                    collecting = False
                    head = None
                    strand = []
                    continue
        for pc in heads:
            the_strands = []
            for h, strand in strands[pc].items():
                the_strands.append(strand)
            self.hinter.send(
                LoopHint(
                    message="loop head and strands detected",
                    head=pc,
                    strands=the_strands,
                )
            )
