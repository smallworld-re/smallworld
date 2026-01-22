Colorizer Analysis
==================

This is a kind of simple poor-man's (or woman's) dynamic data flow
analysis, that is, it gives one the ability to follow the flow of
specific values from instruction to instruction.
The fundamental idea, here, is based on the presumption that, if we can
initialize registers and memory with random (but known) bytes, then we can
know that their contents are being re-used later in the code
when we see the values in again.
These random values are called *colors*.

The ``Colorizer`` class, itself, is fairly simple.
It takes, as input to its ``run`` method, some initial machine state.
Then, it uses the ``TraceExecution`` analysis to both generate an
execution, but also to investigate dynamic colors before and
after each instruction executes.
- Before the instruction executes, every read made by the instruction
  is examined.
  For each read, there are two possibilities:
  - it is a *read-def* if it is new color. In other words, it is
    the first observation of this color, which is therefor an input
    of the trace,
  - it is a *read-flow* if it is not a new color. It is a color that
    has been previously observed, indicating there is a data-flow
    between that first use and this one.
- After the instruction executes, every write made by the instruction
  is examined.
  There are, again, two possibilities.
  - it is a *write-def* if it is new color. This is a value computed by
    the instruction.
  - it is a *write-copy* if it not a new color. The value being
    written is a copy of a previously observed (when read or written)
    color.
      
The ``Colorizer`` relies upon the Capstone disassembler which provides
use/def information about every instruction.
This would, for example, tell us that the ``imul eax, eax`` instruction
*uses* or *reads* the ``eax`` register, and *defines* or *writes* the ``eax``
register.

Note that the setting of or establishment of colors is implicit and happens,
by inspection, whenever an instruction reads or writes a value.
If it is a new value, then a new color is added to a set and further reads
and writes will reference that.

This analysis is often used in conjunction with a helper function
``smallworld.colorizer.randomize_uninitialized`` which takes a machine state
and examines it, determining any registers or memory bytes that are
uninitialized, and then setting them to random bytes.
This is important since otherwise those will contain 0, which is not
a very useful color. 
The colorizer's analysis depends upon the values in registers or memory being
unique and therefore characterstic and while ``randomize_uninitialized``
doesn't guarantee this, it does help a lot.
The colorizer's constructor takes a parameter ``min_color`` which is used
to set a minimum value below which a value will not be considered a color.
Obviously, values like 0 and 1 make terrible colors since they are common
in logic and data.
From experience a minimum color of 30-50 seems good, but extensive testing
or study of this aspect of colorizer data-flow analysis has not happened.

Example Use
-----------


Colorizer Summary Analysis
--------------------------



Colorizer Write Read Analysis
-----------------------------

