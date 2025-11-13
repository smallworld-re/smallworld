.. _analyses:

Analyses
========

SmallWorld provides an interface for encapsulating
analyses that operate on our machine state representation.

Each analysis should create a subclass of ``Analysis``.
This interface is incredibly free-form;
it includes a single method ``Analysis.run()``,
which takes a ``Machine`` object and performs whatever analyses
the class implements.

.. note::

   Analyses should not mutate the ``Machine`` they are passed.

Analyses should use :ref:`hints <hinting>` to communicate results,
so that the results are easily available for additional processing.
The constructor for the ``Analysis`` class takes a ``Hinter``
object, which is stored in ``self.hinter``.
