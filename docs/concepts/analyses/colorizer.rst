.. _colorizer_concept:

Colorizer Analysis
========================

This is a kind of simple dynamic data flow analysis, that is, it lets
you follow the flow of specific values from instruction to
instruction. The fundamental idea, here, is based on the presumption
that, if we can initialize registers and memory with random (but
known) bytes, then we can know that their contents are being re-used
later when we see the values again.  These random values are called
*colors*. To our knowledge, this use of the term was coined in the
NDSS paper describing the REDQUEEN fuzzer [#A]_, though the idea seems
likely to predate that paper.

The ``Colorizer`` class, itself, is fairly simple. It takes, as input
to its ``run`` method, some initial machine state. It uses the
``TraceExecution`` analysis both to generate an execution, but also to
investigate colors in registers and memory reads or writes before and
after each instruction executes.

- Before an instruction executes, every read it will make is examined;
  there are two possibilities.
  
  - It is a *read-def* if it is new color. In other words, this is the
    first read or use observed of this color; it is an input of the
    trace.
  - It is a *read-flow* if it is not a new color. This is a color that
    has been previously observed, indicating there is a data-flow
    between the first use and this one.
    
- After the instruction executes, every write made by the instruction
  is examined; here, too, there are two possibilities.
  
  - It is a *write-def* if it is new color. This is a value computed by
    the instruction.
  - It is a *write-copy* if it not a new color. The value being
    written is a copy of a previously first observed (when read or
    written) color.
      
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
which is used to set a minimum below which a value will not be
considered a color. Obviously, values like 0 and 1 make terrible
colors since they are common in logic and data.  From experience a
minimum color of 30-50 is often reasonable, but extensive testing or
study of this parameter of colorizer data-flow analysis is future
work. The default value used if this argument is not passed to the
constructor is a minimum color of 0x80, which is fairly conservative.

The colorizer generates output as two kinds of hints indicating the
dynamic observation of a color.

- ``DynamicRegisterValueHint`` -- the value is in a register
- ``DynamicMemoryValueHint`` -- the value is in memory

Both hints include all of the following fields

.. code-block:: python3

    exec_id: int          # trace number if multiple
    instruction_num: int  # insctruction count in trace
    pc: int               # program counter
    dynamic_value: int    # actual dynamic value
    color: int            # color 
    size: int             # size of value in bytes
    use: bool             # true if a 'use' or 'read', false if a 'def' or 'write'    
    new: bool             # true if first observation

For the register version of the hint we also have a field
``reg_name``.  For the memory version, all of the following
additional fields exist.

.. code-block:: python3

    address: int     # the concrete address of the memory
    base: str        # if a BSID used to compute address
                     # these will be register base
    index: str       # .. index scale offset
    scale: int       # 
    offset: int

    
.. _colorizer_summary_concept:

Colorizer Summary Analysis
--------------------------

The ``ColorizerSummary`` analysis takes, as input, the hints generated
by the ``Colorizer``: ``DynamicRegisterValueHint`` and
``DynamicMemoryValueHint``. That is, it registers functions to collect
them. This analysis simply normalizes colors across more than one
trace. Essentially, the first color observed becomes ``1`, and the
second becomes ``2`` etc. Also, these are matched up across traces so
the same semantic value from two traces gets the same color. In order
for this to work, the colorizer must set the ``exec_id`` correctly for
each distinct trace analyzed. The output of this analysis is a pair of
summary hints.

- ``DynamicRegisterValueSummaryHint``
- ``DynamicMemoryValueSummaryHint``

These are analogous to the non-summary versions, additionally
providing the following.

- The set of dynamic values corresponding to the same color across
  traces
- For the memory version of the hint, the set of addresses is also
  collected, which could be used to infer sequential access to array
  items in memory.

  
.. _colorize_write_read_concept:

Colorizer Write Read Analysis
-----------------------------

For those with a program analysis bent, it would seem a kind of
dynamic data-flow graph could be built from the colorizer's output.
It can, and this is the business of the ``ColorizerReadWrite``
analysis.

The nodes in this graph are instructions that were executed for some
trace and which either created or used some specific color (value).

Edges in the graph are between where a value was first seen (is new)
and any place it was used (not new).

To be clear, since there are multiple ways of expressing these
concepts, a new value is the same as a first observed value. This
value can be *either* a read of a new value, or by write of new,
computed value. Note that a read of a new value would, in some sense
be an input to the trace, a value that was established before the
trace happeened. This could also be interepreted as a value
uninitialized by the harness (although it may have been set by
``randomize_uninitialized``. These values are essentially *free
variables* of the trace or code; they must be defined outside its
scope and earlier.

This analysis does not output a hint. If it did, that hint would
contain the read->write graph. However, that graph would mostly be
used to derive values. Instead, the graph is accessible from the
analysis object and the graph, itself, has a method that performs
derivation. By derivation we mean starting with some value at some
instruction in the graph and following back-links to determine what
what inputs (new values) to the graph are used to compute the value.

After ``ColorizerReadWrite.run()``, one can perform derivations with
``ColorizerReadWrite.graph.derive(pc, is_read, val)``. The first
argument is the instruction from which to derive, and the second is
true if derivation is of a read value (else it is a written
value). The third argument indicates which value is to be derived and
has either the type ``RegisterDef`` or ``BSIDMemoryReferenceOperand``.


.. [#A] REDQUEEN: "Fuzzing with Input-to-State Correspondence", Cornelius
	Aschermann, Sergej Schumilo, Tim Blazytko, Robert Gawlik and
	Thorsten Holz, Network and Distributed Systems Security (NDSS)
 	Symposium, 2019
	
Tutorials
---------

We provide an example uses of ``Colorizer`` and
``ColorizerReadWrite`` in a :ref:`tutorial <colorizer_tutorial>`.
