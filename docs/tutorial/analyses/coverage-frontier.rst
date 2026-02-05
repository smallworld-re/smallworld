.. _coverage_frontier_tutorial:

Coverage Frontier Analysis Tutorial
===================================

Say you have a function and you want to determine, for some set of
concrete inputs, which conditionals are only ever taken in one
direction. This is sometimes called the "coverage frontier" and the
:ref:`concept is described at more length elsewhere
<coverage_frontier_concept>` in these docs.  Why would you want to
know that?  Well, if the set of inputs is large then the coverage
frontier tells you exactly which conditionals are not well served by
those inputs, since they are only ever taken in one direction.

The ``CoverageFrontier`` analysis computes exactly this; for some set
of execution traces (each of which generates a ``TraceExecutionHint``),
it analyses the sequences of instructions to identify conditionals
that are *half-covered*, meaning only one branch is ever taken.
These are the coverage frontier.

For this tutorial, you will consider a program that contains the
following function ``foo`` which takes a single argument (in the
``edi`` register).

.. code-block::

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

The argument is copied into `eax`
and tested to determine if it is odd or even, which is used to decide
the conditional branch at ``0x1158``. The function returns either
``0x24`` or ``0x42`` based on the whether or not the argument ``edi``
is even. Given how this function operates, if you execute it just
once, you should see just one of the branches of ``0x1158`` execute.
In this case, ``0x1158`` is certain to be in the coverage frontier.
However, if you execute the function more than once with both odd and
even inputs, or if you just run it a lot of times with random inputs,
then it is very likely to hit both branches, meaning ``0x1158`` will
not be in the coverage frontier.

There is a script in the SmallWorld test suite used to exercise and
verify the ``CoverageFrontier`` analysis. This script harnesses the
function ``foo`` above (setting the entry point to ``0x1149``), in the
program ``cf`` that is pre-compiled in that testing directory.  The
script contains a lot that is either boilerplate or relevant only to
testing.  Let's focus on the parts of it that make use of the
``CoverageFrontier``. First, there is code that sets up a hinter and
creates the ``CoverageFrontier`` analysis object.

.. literalinclude:: ../../../tests/coverage_frontier/coverage_frontier_test.py
  :language: Python
  :lines: 65-67

The script registers a function to collect the
``CoverageFrontierHint`` that is output by the analysis. Only one such
hint will be output by the analysis when it is run.

.. literalinclude:: ../../../tests/coverage_frontier/coverage_frontier_test.py
  :language: Python
  :lines: 51-54

The script creates ``num_micro_exec`` traces, using the
``TraceExecution`` analysis. For each, a different and random value is
assigned to ``rdi`` which is the input to the function ``foo``.  Each
of these runs of ``TraceExecution`` will output a ``TraceExecutionHint``
that is consumed by the ``CoverageFrontier`` analysis.

.. literalinclude:: ../../../tests/coverage_frontier/coverage_frontier_test.py
  :language: Python
  :lines: 69-77

After all these traces have been created and hinted, we run the ``CoverageFrontier`` analysis

.. literalinclude:: ../../../tests/coverage_frontier/coverage_frontier_test.py
  :language: Python
  :lines: 79-82

The upshot of all this should be that we collect a single
``CoverageFrontierHint`` which will be in the global ``hint[0]``.
This hint's ``coverage_frontier`` set is output with code like this
(where ``h = hint[0]``).

.. literalinclude:: ../../../tests/coverage_frontier/coverage_frontier_test.py
  :language: Python
  :lines: 99-102

Here is the complete script, which contains some code to harness the
``cf`` program as well as some needed for testing.

.. literalinclude:: ../../../tests/coverage_frontier/coverage_frontier_test.py
  :language: Python
	  
The script takes three arguments.
The first is the number of micro-executions or *traces* to run, each of
which is an execution of the function ``foo``.
The second sets a maximum number of instructions to execute.
The third argument is a seed for the random number generator.

If we run script, asking it to create a *single* trace, as noted
earlier, we can only execute one branch of the ``jne`` at ``0x1158``,
so the coverage frontier will contain that branch instruction.

.. command-output:: python3 coverage_frontier_test.py 1 100 1233 2> /dev/null 
    :shell:		    
    :cwd: ../../../tests/coverage_frontier
    

And if we ask for three or more traces, with this same seed, we
will have enough execution diversity to have hit both branches,
and our coverage frontier will be empty.

.. command-output:: python3 coverage_frontier_test.py 3 100 1233 2> /dev/null 
    :shell:		    
    :cwd: ../../../tests/coverage_frontier

	  
The function ``foo`` is not a complicated one; consider it a toy
example.  If it were much larger or more complicated, then
determining, merely by inspection, what conditionals were likely to
easily covered would be very difficult. The ``CoverageFrontier`` can
figure this out for you directly.


Further Reading
---------------

See the :ref:`CoverageFrontier Concepts <coverage_frontier_concept>` page
for more details.
