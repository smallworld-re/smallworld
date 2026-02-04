.. _colorizer_concept:

Colorizer Analysis
========================

This is a kind of simple dynamic data flow analysis, that is, it
provides the ability to follow the flow of specific values from
instruction to instruction. The fundamental idea, here, is based on
the presumption that, if we can initialize registers and memory with
random (but known) bytes, then we can know that their contents are
being re-used later in the code when we see the values again.  These
random values are called *colors*. To our knowledge, this use of the
term was coined in the NDSS paper describing the REDQUEEN fuzzer
[#A]_, though the idea seems likely to predate that paper.

The ``Colorizer`` class, itself, is fairly simple. It takes, as input
to its ``run`` method, some initial machine state. It uses the
``TraceExecution`` analysis both to generate an execution, but also to
investigate colors in registers and memory reads or writes before and
after each instruction executes.

- Before the instruction executes, every read made by the instruction
  is examined: there are two possibilities.
  
  - It is a *read-def* if it is new color. In other words, this is
    the first read or use observed of this color; this means it
    is an input of the trace,
  - It is a *read-flow* if it is not a new color. It is a color that
    has been previously observed, indicating there is a data-flow
    between that first use and this one.
    
- After the instruction executes, every write made by the instruction
  is examined: here, too, there are two possibilities.
  
  - it is a *write-def* if it is new color. This is a value computed by
    the instruction.
  - it is a *write-copy* if it not a new color. The value being
    written is a copy of a previously observed (when read or written)
    color.
      
The ``Colorizer`` relies upon the Capstone disassembler which provides
use/def information about every instruction. This would, for example,
tell us that the ``imul eax, eax`` instruction *uses* or *reads* the
``eax`` register, and *defines* or *writes* the ``eax`` register.

The establishment of colors is implicit and happens, by inspection,
whenever an instruction reads or writes a value. If it is a new value,
not seen before, then a new color is added to a set being tracked and
further reads and writes will be with respect to that.

This analysis is often used in conjunction with a helper function
``smallworld.colorizer.randomize_uninitialized`` which takes a machine
state and examines it, determining any registers or memory bytes that
are uninitialized, which it proceeds to set to random values. This is
important since otherwise those will contain 0, which is not a very
useful color. The colorizer's analysis depends upon the values in
registers or memory being unique and therefore characterstic and while
``randomize_uninitialized`` doesn't guarantee this, it is very
effective.

Note that the colorizer's constructor takes a parameter ``min_color``
which is used to set a minimum value below which a value will not be
considered a color. Obviously, values like 0 and 1 make terrible
colors since they are common in logic and data.  From experience a
minimum color of 30-50 seems good, but extensive testing or study of
this aspect of colorizer data-flow analysis is future work. The
default value used if this argument is not passed to the constructor
is a minimum color of 0x80, which is fairly conservative.

The colorizer generates output as two kinds of hints indicating the
observation of a dynamic value regarded as a *color*.

- ``DynamicRegisterValueHint`` -- the value is in a register
- ``DynamicMemoryValueHint`` -- the value is in memory

Both hints include all of the following fields

.. code-block::

    pc: int               # the program counter
    instruction_num: int  # insctruction count in trace
    exec_id: int          # trace number if multiple
    dynamic_value: int    # the actual dynamic value
    color: int            # the color
    size: int             # size of value in bytes
    use: bool             # true if a 'use' or 'read', else a 'def' or 'write'    
    new: bool             # true if first observation

For the register version of the hint we also have a field ``reg_name``.
For the memory version, all of the following additionally.

.. code-block::

    address: int     # the concrete address of the memory
    base: str        # if a BSID used to compute address
                     # this will be register base
    index: str       # .. index scale offset
    scale: int       # 
    offset: int


.. _colorizer_summary_concept:

Colorizer Summary Analysis
--------------------------

The ``ColorizerSummary`` analysis takes, as input, the hints generated
by the ``Colorizer``: ``DynamicRegisterValueHint`` and
``DynamicMemoryValueHint``.
That is, it registers functions to collect them.
This analysis simply normalizes colors across more than one trace.
Essentially, the first color observed becomes ``1`, and the second
becomes ``2`` etc.
Also, these are matched up across traces so the same semantic value
from two traces gets the same color.
If it is to used, the colorizer must set the ``exec_id`` correctly.
The output of this analysis is a pair of summary hints:

- DynamicRegisterValueSummaryHint
- DynamicMemoryValueSummaryHint

These are quite similar to the non-summary versions, additionally
providing

- the set of dynamic values corresponding to the same c
  olor across traces are collected.
- For the memory version of the hint, the set of addresses
  is also collected, which could be used to infer sequential
  access to array items in memory.

  
.. _colorize_write_read_concept:

Colorizer Write Read Analysis
-----------------------------

For those with a program analysis bent, it would seem a kind of
dynamic data-flow graph could be built from the colorizer's output.
It can, and this is the business of the ``ColorizerReadWrite`` analysis.

The nodes in this graph are instructions that were executed and which
either created or used some specific value or color.

Edges in the graph are between where a new value was first seen and
any place it was seen to be used.

Note that a new value (in the parlance of discussions above in this
tutorial, "first observation") can be *either* a read of a new value
not seen before, or by write of new, computed value.

The graph computed by the ``ColorizerReadWrite`` analysis is not exposed
as a hint.
However, a method is available that can use the graph to derive any value
in the graph, i.e., follow back-links to determine what inputs (new values)
to the graph are used to compute it.
    
