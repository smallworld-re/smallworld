.. _coverage_frontier_concept:

Coverage Frontier Analysis
==========================

The coverage frontier is a concept related to edge coverage of some code.
A few definitions first:

1. The *control-flow graph* (CFG) of some binary code has nodes that
   are the instructions in the code and there is a directed edge
   between any two instruction that can follow one another,
   sequentially, during some execution.
2. A *dynamic CFG* (DCFG) is constructed by running the code a number
   of times on different inputs. Instruction nodes and edges will be
   those that were observed for some trace. In many cases, there will
   be missing nodes and edges, as none of the inputs tried has
   revealed them. Note that there is usually a disparity between the
   DCFG and the ideal one that would come from perfect knowledge of
   all possible paths through code given all possible inputs. It is an
   unsolved problem to come up with a set of inputs for which the DCFG
   will match the ideal one.
3. Given a DCFG, some conditional branch instructions will have two
   successors, indicating that both branches were observed across
   traces. Conversely, some branch instructions will have only one
   successor. These branches are considered *half-covered* with
   respect to the set of inputs used to generate the traces and
   thus the DCFG.
4. The *coverage frontier* of some code is the set of half-covered
   conditionals for that code, given the DCFG constructed from the set
   of inputs used to generate traces. This is a useful concept in
   testing, generally, but also in *fuzzing* which generates lots of
   random inputs for executing some code. The coverage frontier is the
   branches in the code you have been unable to *solve* for both sides
   after some number of input tries.
      
The ``CoverageFrontier`` analysis will compute the coverage frontier
by collecting and examining the ``TraceExecutionHint`` outputs from a
number of runs of the ``TraceExecution`` analysis and determining
which conditionals are both executed *and* half-covered.

For more information, please have a look at the
:ref:`CoverageFrontier Analysis tutorial <coverage_frontier_tutorial>`.

The CoverageFrontier Hint
-------------------------

The ``CoverageFrontier`` analysis generates a single hint as its
output, which is the ``CoverageFrontierHint``.

.. code-block:: python3

    class CoverageFrontierHint(hinting.Hint):
        # set of half-covered conditionals (program counters)
        coverage_frontier: typing.List[int]
	# edges in the dcfg (pc1->pc2)
        edges: typing.List[typing.Tuple[int, typing.List[int]]]
	# set of conditionals (program counters)
        branches: typing.List[int]
	# number of traces processed in computing coverage frontier
        num_traces: int
