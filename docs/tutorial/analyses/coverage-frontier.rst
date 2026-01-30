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

Example Use
-----------

Consider a program that contains the a function ``foo`` which takes
a single argument (in the ``edi`` register). Here is that function:

.. code-block::

       [0x00001060]> pdf @ sym.foo
		   ; CALL XREF from sub.main_1168 @ 0x1192(x)
       ┌ 31: sym.foo (int64_t arg1);
       │ `- args(rdi) vars(1:sp[0xc..0xc])
       │           0x00001149      55             push rbp
       │           0x0000114a      4889e5         mov rbp, rsp
       │           0x0000114d      897dfc         mov dword [var_4h], edi     ; arg1
       │           0x00001150      8b45fc         mov eax, dword [var_4h]
       │           0x00001153      83e001         and eax, 1
       │           0x00001156      85c0           test eax, eax
       │       ┌─< 0x00001158      7507           jne 0x1161
       │       │   0x0000115a      b824000000     mov eax, 0x24               ; '$'
       │      ┌──< 0x0000115f      eb05           jmp 0x1166
       │      ││   ; CODE XREF from sym.foo @ 0x1158(x)
       │      │└─> 0x00001161      b842000000     mov eax, 0x42               ; 'B'
       │      │    ; CODE XREF from sym.foo @ 0x115f(x)
       │      └──> 0x00001166      5d             pop rbp
       └           0x00001167      c3             ret
       [0x00001060]> 

That argument copied into `eax` and tested to determine if it is
odd or even which is used to decide the conditional branch at ``0x1158``.
The returns either ``0x24`` or ``0x42`` based on the whether or not
the argument ``edi`` is even.

Here is a small script that harnesses a program ``cf`` that contains
this function ``foo``.
It executes the function one or more times, each time using the
``TraceExecution`` analysis.
The hints output by these analysis runs are consumed by a
``CoverageFrontier`` analysis.

.. literalinclude:: ../../../tests/coverage_frontier/coverage_frontier_test.py
  :language: Python

The script takes three arguments.
The first is the number of micro-executions or *traces* to run, each of
which is an execution of the function ``foo``.
The second sets a maximum number of instructions to execute.
The third argument is a seed for the random number generator.
If we run script, asking it to create a *single* trace, obviously we
can only execute one branch of the ``jne`` at ``0x1158``, so the
coverage frontier should contain that single branch instruction.

.. command-output:: python3 coverage_frontier_test.py 1 100 1233 2> /dev/null 
    :shell:		    
    :cwd: ../../../tests/coverage_frontier
    

And if we ask for three or more traces, with this same seed, we
will have enough execution diversity to have hit both branches,
and our coverage frontier will be empty.

.. command-output:: python3 coverage_frontier_test.py 3 100 1233 2> /dev/null 
    :shell:		    
    :cwd: ../../../tests/coverage_frontier

	  
	  




