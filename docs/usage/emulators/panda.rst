.. _panda:

Panda Backend
=============

Panda provides a full-system concrete emulator based on QEMU.



.. warning::
   SmallWorld is actively working on switching to an updated version of Panda.
   These features are subject to change.

.. warning::
   It is only possible to create one Panda instance in a given process tree.

   Panda uses some kind of global resource that persists across ``fork()`` and ``exec()``.
   If you create a ``PandaEmulator`` in a given process, and then try to create a second instance
   in the same process or one of its children, you will see very interesting errors.

Execution Control
-----------------

``PandaEmulator`` supports the standard execution control functions.

.. note::
   ``PandaEmulator.step()`` may execute more than one instruction.

   This only happens on instructions with delay slots;
   the emulator must execute the instruction and its delay slot
   as a single step.

Exit Points and Bounds
----------------------

``PandaEmulator`` supports exit points and bounds normally.
It will treat execution of unmapped memory as a memory error.

.. caution::
   Panda does not support unmapped exit points.

Accessing Registers
-------------------

``PandaEmulator`` supports normal register access.

Setting labels on registers has no effect on ``PandaEmulator``,
and the labels are not preserved after execution starts.

.. caution::
   Panda is a full-system emulator

   ``PandaEmulator`` configures Panda to provide a basic execution
   environment suitable for analysis of user-space code.
   Privileged features will likely behave strangely
   without a lot of extra harnessing to set up what amounts to an entire OS.

   Panda also does not expose many privileged registers or similar features directly.
   Harnessing code that interacts with a privileged subsystem will be extremely difficult.

Mapping Memory
--------------

``PandaEmulator`` enforces its memory map.
Accesses to unmapped memory will produce an exception,
reporting either an unmapped "read" or "write"

The memory map works on a page (4096 byte) resolution.

.. caution::
   Executing unmapped memory may exit the program.

   Panda is designed to boot and run full systems.
   Executing unmapped memory means something went horribly wrong.
   The default handler for an unmapped instruction fetch
   will invoke ``exit(1)`` in a way that can't be preempted.
   Some platforms will instead raise an exception,
   but the majority will just die.

   This does make using SmallWorld for post-mortem analysis rather difficult.

.. caution::
   Some platforms have limited address spaces.

   The biggest example is MIPS64, which reserves half the address space for MMIO operations.
   Attempting to use these regions will result in undefined behavior.

Accessing Memory
----------------

``PandaEmulator`` supports normal memory accesses.

Setting labels on memory has no effect on ``PandaEmulator``,
and labels are not preserved once execution begins.


.. note::
   The SmallWorld interface does not offer any mechanism to access
   the physical address space underlying the virtual address space.

Event Handlers
--------------

``PandaEmulator`` supports the following event types:

- Instruction Hooks
- Function Models
- Memory Accesses

.. warning::
   Panda also has an interface for interrupt hooking,
   but it is non-functional.

These have no special behaviors.

Interacting with Panda
----------------------

.. note::
   --Understanding this section is not necessary to write a normal harness.--
   
   The features described here are completely abstracted
   behind the ``UnicornEmulator`` interface, and are only useful
   if you want to leverage Unicorn for analysis.
   
   This section describes how to access the relevant objects,
   and any caveats regarding their access.
   Using them for analysis is an exercise left to other tutorials.

Please don't.

To get around some of Panda's synchronous operations,
SmallWorld runs Panda in a separate thread.
You can absolutely access the Panda object, 
but it will almost certainly be in an inconsistent state when you do.

Plus, there is currently no way to access or modify the Panda object
before execution begins, or to control how execution starts.
