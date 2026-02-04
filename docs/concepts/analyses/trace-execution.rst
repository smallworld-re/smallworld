.. _trace_execution_concept:

Trace Execution Analysis
========================

The ``TraceExecution`` analysis class allows you to capture a single
execution trace for some code. Given an initial machine state passed
to its ``run`` method, the analysis uses the Unicorn emulator to
execute one instruction at a time, single-stepping through the code
until doing so raises an exception.

For each instruction, the analysis constructs a ``TraceElement``
object consisting of instruction address and mnemonics as well as
details about branch and comparison instructions (for those
instructions). The analysis collects these in a list which represents
the trace. This list and other information get bundled into the
``TraceExecutionHint``, along with the exception that was thrown to
end the trace. This hint is the main output of this analysis. There
are more details about these classes below.

Two known exceptions are explicitly caught whilst single-stepping:
``EmulationBounds`` and ``EmulationExitPoint``. These both indicate
the emulator should halt, as it has finished executing the required
code (and is about to walk off into other or missing code). Other
possible exceptions of interest that are not caught explicitly are
subclasses of ``EmulationError`` listed and explained in the
``smallworld.exceptions`` source and include invalid read/write of
memory (typically due to an address being unmapped). The exception
which ended the trace is obviously diagnostic and is captured by the
analysis and saved in the ``TraceExecutionHint``.

One way to build upon this analysis is to register a function to
receive the ``TraceExecutionHint`` and then doing something with it.

Another way to use this analysis is to registering functions to be run
before and after an instruction execution. This is done with

.. code-block:: python3

    TraceExecution.register_cb(cb_point, cb_function)

We provide an example of using this callback in the
:ref:`TraceExecution Analysis tutorial <trace_execution_tutorial>`.

For a even more detailed worked example, you can study the source code for
the ``Colorizer`` analysis works, which employs these callbacks.

For an example of an analysis that uses the ``TraceExecutionHint`` you
can study the source code for the ``CoverageFrontier`` analysis, as
well as looking at the :ref:`tutorial <coverage_frontier_tutorial>`
for that.


The TraceExecutionHint
----------------------
     
The ``TraceExecutionHint`` has the following structure

.. code-block:: python3

     @dataclass(frozen=True)
     class TraceExecutionHint(TypeHint):
         trace: typing.List[TraceElement]
         trace_digest: str
         seed: int
         emu_result: TraceRes
         exception: typing.Optional[Exception]
         exception_class: str

The ``trace_digest`` is an md5 sum that will be different for
different sequences of program counters.

The ``seed`` is a value that
can be set to indicate the PRNG seed to use to reproduce this trace,
given various random choices made in setting up the environment (this
could mean a call to
``smallworld.analyses.colorizer.randomize_uninitialized``.

``emu_results`` is used to indicate how the trace ended:

.. code-block:: python3

    class TraceRes(Enum):
        ER_NONE = 0
        ER_BOUNDS = 1      # hit execution bound or exit point
        ER_MAX_INSNS = 2   # hit max number of instructions
        ER_FAIL = 3        # some kind of emulation failure

Note that the actual exception that ended the trace is also stored in ``exception``.
	 
The ``trace`` member is a list of ``TraceElement`` objects, one for
each instruction executed.  These have the following structure.

.. code-block:: python3

     @dataclass
     class TraceElement:
         pc: int
         ic: int          # instruction count
         mnemonic: str    # these next two are from Capstone
         op_str: str
         cmp: typing.List[CmpInfo]   
         branch: bool                  # true iff this instruction is a branch
         immediates: typing.List[int]  # list of immediate operands in this instruction

The ``CmpInfo`` is a union of two possibilities:
``typing.Union[RegisterOperand, BSIDMemoryReferenceOperand, int]`` and
the intent is that it can represent the semantics of operands that are
registers, memory read or writes, and immediates.


