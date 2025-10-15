.. _unicorn:

Unicorn Backend
===============

Unicorn is a user-space concrete emulator based on QEMU.

Unlike ``qemu-user``, Unicorn is fully self-contained;
it doesn't depend on the host kernel or library environment.
Unicorn is one of the simplest emulators to use,
one of the fastest, and is the only emulator
that currently supports fuzzing via AFL.

Execution Control
-----------------

``UnicornEmulator`` supports the standard execution control functions.

.. note::

    Unicorn needs some extra configuration when dealing with
    platforms that include multiple ISAs.
    The only currently-supported example is arm32, which supports ARM and THUMB.

    The function ``UnicornEmulator.set_thumb()`` allows a harness to specify
    that the current machine state should be interpreted using the THUMB isa.
    The mode will be tracked internally as code executes,
    and can be referenced using ``UnicornEmulator.get_thumb()``.

    Both of these functions will fail if the emulator
    is configured for a platform other than arm32. 

.. note::
   ``UnicornEmulator.step()`` may execute more than one instruction.

   This only happens on instructions with delay slots;
   the emulator must execute the instruction and its delay slot
   as a single step.

Exit Points and Bounds
----------------------

``UnicornEmulator`` supports exit points and bounds normally.
It will treat execution of unmapped memory as a memory error,
although it does support unmapped exit points.

Accessing Registers
-------------------

``UnicornEmulator`` supports normal register access.

Setting labels on registers has no effect on ``UnicornEmulator``,
and the labels are not preserved after execution starts.

.. caution::
   Unicorn supports some control registers,
   such as the x86 segmentation and parts of the MMU control registers.

   Configuring these in smallworld is difficult,
   since they must be configured in a specific order,
   or else produce an inconsistent state that will cause an exception.

   The :ref:`state` interface is not precise enough to perform this configuration,
   since it doesn't guarantee the order in which registers are applied.


Mapping Memory
--------------

``UnicornEmulator`` enforces its memory map.
Accesses to unmapped memory will produce an exception,
reporting either an unmapped "read", "write", or "fetch" (for an unmapped program counter.)

The memory map works on a page (4096 byte) resolution.

Accessing Memory
----------------

``UnicornEmulator`` supports normal memory accesses.

Setting labels on memory has no effect on ``UnicornEmulator``,
and labels are not preserved once execution begins.

.. warning::
   TODO: How well-supported are ISA features that change memory layout, 
   like x86 segmentation?

Event Handlers
--------------

``UnicornEmulator`` supports the following event types:

- Instruction Hooks
- Function Models
- Memory Accesses

.. warning::
   Unicorn also has an interface for interrupt hooking,
   but it is non-functional.

These have no special behaviors.

Interacting with Unicorn
------------------------

.. note::
   **Understanding this section is not necessary to write a normal harness.**
   
   The features described here are completely abstracted
   behind the ``UnicornEmulator`` interface, and are only useful
   if you want to leverage Unicorn for analysis.
   
   This section describes how to access the relevant objects,
   and any caveats regarding their access.
   Using them for analysis is an exercise left to other tutorials.

It's possible to access the Unicorn emulator directly
via the property ``UnicornEmulator.engine``.
This will be fully initialized when the ``UnicornEmulator`` object is constructed.
