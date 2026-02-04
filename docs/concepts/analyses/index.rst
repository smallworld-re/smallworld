.. _analyses:

Analyses
========

SmallWorld provides a simple interface for encapsulating
analyses that take, as input, the machine state representation.
These can be *static* analyses, meaning the code is examined
but not run.
Or they can be *dynamic* analyses which will run the code, 
using the input ``Machine`` to specify the initial state of
memory and registers. 
Dynamic analysis will, additionally, employ instrumentation to
monitor execution and collect side information.

Each analysis should create a subclass of ``Analysis``.
This interface is incredibly free-form;
it includes a single method ``Analysis.run()``,
which takes a ``Machine`` object and performs whatever analyses
the class implements.

.. note::

   Analyses should not mutate the ``Machine`` they are passed.

The ``Analysis.run()`` method, notably, returns ``None``.
This is because analyses are intended to use ``Hints`` to
communicate any results, making them available for
additional processing.

The constructor for the ``Analysis`` class takes a ``Hinter``
object, which is stored in ``self.hinter``.


Hints
-----

Conceptually, hints are simply statements of discovery made by an
analysis.
The idea is that a given analysis will generate a number of discrete
discoveries -- hints -- about the nature of some code.
Hints can be collected, composed, and synthesized into even richer
insights, which can go into logs or reports for direct human
consumption or can, themselves, become higher-level hints intended
for downstream analysis.

Take, as an example, the ``CodeCoverage`` analysis class.
Given some SmallWorld harness that sets up the initial environment for
execution and packs it into a ``Machine`` object, this analysis will 
execute code using the Unicorn emulator until it hits an exit point,
steps outside a specified code bound, or raises an exception,
collecting counts for every instruction program counter encountered.
This coverage information (a dictionary mapping program counters to
counts) is included as part of the ``CoverageHint`` that is emitted
by this analysis.

Hints are packaged as data classes that subclass ``Hint``.

Analyses designed to consume hints use the specific ``Hint`` subclass to
filter the hints they want.

.. note::

    Data inside of a ``Hint`` is passed by reference and is
    never marshalled, so a ``Hint`` can contain arbitrarily-large
    or complex information.

SmallWorld includes a library of ``Hint`` subclasses covering
information relevant to evaluating a SmallWorld harness.
Analyses are encouraged to use existing hint subclasses,
although they may create their own if necessary.

Hinting is implemented as a basic pub-sub system via the ``Hinter`` class.
An ``Analysis`` takes, as input to its constructor, a ``Hinter`` object.
This is subsequently available in ``self.hinter`` and can be used with
``self.hinter.send()`` to publish a hint for consumption, and
``self.hinter.register()`` to register a callback that will fire if a
specific class of hint is received.
The callback will be of the form ``callback(Hint) -> None``.

.. caution::
   Callbacks are only triggered on an exact class match.
   If a callback is registered to a given ``Hint`` class,
   and an analysis sends a subclass, the callback will not fire.

The following is a basic example of two dependent analyses
that communicate via ``Hint``:

.. code-block:: python

    from smallworld.hinting import Hint, Hinter
    from smallworld.analysis import Analyses
    from smallworld.state import Machine

    class FirstAHint(Hint):
        pass

    class FirstAnalysis(Analysis):
        name = "first-analysis"
        version = "0"
        description = "An analysis that sends hints"

        def run(self, machine: Machine):
            # Send a hint when we start.
            self.hinter.send(FirstAHint(
                message="Hello, world!"
            ))

    class SecondAnalysis(Analysis):
        name = "second-analysis"
        version = "0"
        description = "An analysis that listens for hints"

        def on_hint(self, hint: Hint):
            print(f"Hint: {hint.message}")            

        def run(self, machine: Machine):
            # Listen for hints of type Hint.
            self.hinter.register(FirstAHint, self.on_hint)

    # Set up the hinter
    hinter = Hinter()

    # Prepare the dependent analysis;
    # should return without doing anything.
    machine.analyze(SecondAnalysis(hinter))

    # Run the base analysis.
    # Should cause SecondAnalysis to print "Hello, World!"
    machine.analyze(FirstAnalysis(hinter))

    
For a more realistic example of how analyses can compose, consider
studying the communication of hints between ``TraceExecution`` and
``CoverageFrontier``.
The ``TraceExecution`` analysis is somewhat like ``CodeCoverage``, in
that it takes the initial code execution environment specified by the
``Machine`` object passed, as input, to the ``self.run()`` method,
and uses this to execute code.
The output for ``TraceExecution`` is a ``TraceExecutionHint``
which includes the sequence of instructions executed, along wih
information about comparison and branch instructions encountered,
as well as indications about how a trace ended (in an exception
or simply because execution reached a proscribed bound).
The ``CoverageFrontier`` analyses registers a callback on the
``TraceExecutionHint``, collecting these hints across multiple
executions and analyzing them, in aggregate to determine which
branches in code are encountered but only ever go one way
(are half-covered).
These branches, or *coverage frontier* are interesting for
targeted fuzzing or other activities.

SmallWorld Analyses
-------------------

.. toctree::
   trace-execution
   coverage-frontier
   colorizer
