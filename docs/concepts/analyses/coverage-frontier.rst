.. _coverage_frontier_concept:

Coverage Frontier Analysis
==========================

The coverage frontier is a concept related to edge coverage of some code.
A few definitions first:

1. The *control-flow graph* (CFG) of some binary code has nodes that
   are the instructions in the code and there is a directed edge
   between any two instruction that can follow one another,
   sequentially, during some execution.
2. A *dynamic CFG* (DCFG) is constructed by running the code
   a number of times on different inputs. Instruction nodes and
   edges will be those that were observed for some trace. In
   many cases, there will be missing nodes and edges, as none of
   the inputs tried has revealed them. Note that there is usually
   a disparity between this DCFG and the ideal one that would come
   from perfect knowledge of all possible paths through code given
   all possible inputs. It is an unsolved and generally very
   difficult problem to come up with a set of inputs for which the
   DCFG will match the ideal one. 
3. Given a DCFG, some conditional branch instructions will have two
   successors, indicating that both branches were observed acros
   traces. Conversely, some branch instructions will have only one
   successor. These branches are considered *half-covered* with
   respect to the set of inputs used to generate the traces and
   thus the DCFG.
4. The *coverage frontier* of some code is the set of half-covered
   conditionals for that code, given the set of inputs used to
   generate traces. This is a useful concept in *fuzzing* which
   generates lots of random inputs for executing some code. The
   coverage frontier is the branches in the code you have been
   unable to *solve* for both sides after some number of input
   tries.
      
This analysis will compute the coverage frontier by collecting and
examining the ``TraceExecutionHint`` outputs from a number of runs
of the ``TraceExecution`` analysis.

