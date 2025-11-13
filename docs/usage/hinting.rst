.. _hinting:

Hinting
=======

SmallWorld provides a simple mechanism for composing analyses called "hinting".
It's based around the idea that a given analysis will generate
a number of discrete discoveries - hints - about the nature of a program
or the correctness of a harness. These hints can be synthesized into
even richer insightes into a program, or composed into a report for an analyst.

Hints are packaged as data classes that subclass ``Hint``.
Analyses use the specific ``Hint`` subclass to filter the hints they want.
Data inside of a ``Hint`` is passed by reference and is never marshalled,
so a ``Hint`` can contain arbitrarily-large or complex information.

SmallWorld includes a library of ``Hint`` subclasses covering
information relevant to harness evaluation.
Analyses are encouraged to use existing hint subclasses,
although they may create their own if absolutely necessary.

Hinting is implemented as a basic pub-sub system via the ``Hinter`` class.
All analyses take a ``Hinter`` as an input.
They can use ``Hinter.send()`` to publish a hint for consumption,
and ``Hinter.register()`` to register a callback
that will fire if a specific class of hint is sent.


.. caution::
   Callbacks are only triggered on an exact class match.
   If a callback is registered to a given ``Hint`` class,
   and an analysis sends a subclass, the callback will not fire.

The callback will be of the form ``callback(Hint) -> None``.

The following is a basic example of a two dependent analyses
that communicate via a hinter:

.. code-block:: python

    from smallworld.hinting import Hint, Hinter
    from smallworld.analysis import Analyses
    from smallworld.state import Machine


    class FirstAnalysis(Analysis):
        name = "first-analysis"
        version = "0"
        description = "An analysis that sends hints"

        def run(self, machine: Machine):
            # Send a hint when we start.
            self.hinter.send(Hint(
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
            self.hinter.register(self.on_hint, Hint)

    # Set up the hinter
    hinter = Hinter()

    # Prepare the dependent analysis;
    # should return without doing anything.
    machine.analyze(SecondAnalysis(hinter))

    # Run the base analysis.
    # Should cause SecondAnalysis to print "Hello, World!"
    machine.analyze(FirstAnalysis(hinter))
