.. _emulators:

Emulators
=========

Emulators play a big role in SmallWorld. On the one hand, they represent a
possible consumer of the harness we'd build for code.  That is, once harnessed,
a reasonable thing to do with that harness is use an emulator to execute its
instructions.  This could mean executing with breakpoints or single stepping
and examining intermediate register values or memory contents in a dynamic
reverse engineering situation. Or the harness might be used to run code many
times with random draws from an initialization environment, possibly as part of
a fuzzing campaign.

Emulation is also employed by various analyzers to improve a harness. This
means we emulate with our current best harness in order to get hints to improve
our harness for emulation.  In other words, we emulate in order to emulate
better.

SmallWorld currently supports four emulation backends:

* **angr**: A user-space symbolic executor based on VEX or Pcode
* **Ghidra**: A user-space concrete emulator based on Pcode
* **Panda**: A full-system concrete emulator based on QEMU
* **Unicorn**: A user-space concrete emulator based on QEMU

These are abstracted behind a common interface.
While they all have different strengths and support slightly different
sets of features, most smallworld harnesses can be applied
to any of the four emulators,
with only a single line of code changed to specify which one.

Although the :ref:`state` interface is the preferred method of
defining a harness, analyses and event handlers
operate directly on an emulator to avoid the overhead
of extracting and reapplying the machine state representation.

.. toctree::
   interface
   unicorn
   angr
   panda
   ghidra
