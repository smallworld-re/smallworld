.. _state:

State
-----

The State in SmallWorld is an object representing the values for
registers and memory for some particular CPU. It is used to to set up
and initialize these values prior to running an anlaysis or
emulation, but also serves as a place where final values after emulation can
be copied into for inspection.  This provides two benefits.

   1. The state has a generic interface that is not tied to any
      particular emulator or analytic back-end. So initialization and
      post-emulation code can be written to be generic.
   2. The state can be applied to (copied into) or loaded from (copied
      out of) any emulator meeting SmallWorld's :ref:`emulators`
      interface.

At the lowest level, there are the State objects ``Register``,
``RegisterAlias``, ``Memory``, and ``Code``.

A ``Register`` represents a specific CPU register, such as ``edx`` and
includes name, width in bytes, and a concrete value if available.


      
