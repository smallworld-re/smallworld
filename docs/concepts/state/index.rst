.. _state:

Machine State
=============

SmallWorld provides its own representation for machine state,
which is used to initialize an emulation or analysis attempt,
as well as to retrieve results from an emulator
once execution is complete.  This provides two key benefits:

    1. The machine state representation is not tied to a particular emulator
       or analytic back-end.  This makes it very easy to repurpose a single
       harness, as well as any pre-processing or post-processing code
       for multiple experiments.
    2. Machine state can be transferred between emulators, as long as they meet
       SmallWorld's :ref:`emulators` interface

.. toctree::
   values
   machine
   cpu
   memory/index
   hooks/hooks
   hooks/c_support
