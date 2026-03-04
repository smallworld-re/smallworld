.. _ghidra:

Ghidra Backend
==============

Ghidra provides a user-space concrete emulator based on its Pcode language models.

Pcode models a huge number of ISAs, offering far greater language support
than the other concrete emulators.  It's also very focused on user-space features,
making it a little more abstract and in some ways more forgiving than QEMU-based emulators.

The downside is that the Pcode language models vary wildly in their fidelity,
and exercising an unsupported or partially-supported feature will simply produce incorrect behavior,
rather than reporting an error.

.. note::
   Using ``GhidraEmulator`` requires an operation Ghidra installation,
   and requires that the environment variable ``GHIDRA_INSTALL_DIR``
   contain the path to that install directory.

   See the installation docs for more information
   about setting up Ghidra for use with smallworld. 

.. note::
   Using ``GhidraEmulator`` requires launching a Java Virtual Machine
   in the background of your python process.

   This is done once the first time you call the ``GhidraEmulator``
   constructor, and may take about ten seconds to complete.

Execution Control
-----------------

``GhidraEmulator`` supports ``run()`` and ``step()`` normally.

It does not support ``step_block()``; the underlying emulator
operates strictly on instructions.  Invoking ``step_block()`` will raise an exception.

.. note::
   ``GhidraEmulator.step()`` may execute more than one instruction.

   This only happens on instructions with delay slots;
   the emulator must execute the instruction and its delay slot
   as a single step.

Exit Points and Bounds
----------------------

``GhidraEmulator`` supports exit points and bounds normally.
It will treat execution of unmapped memory as an out-of-bounds execution.

Accessing Registers
-------------------

``GhidraEmulator`` supports normal register access.

Setting labels on registers has no effect on ``GhidraEmulator``,
and the labels are not preserved after execution starts.

Mapping Memory
--------------

``GhidraEmulator`` enforces its memory map.
Accesses to unmapped memory will produce an exception,
reporting either an unmapped "read", "write", or "fetch" (for an unmapped program counter.) 

The memory map works on a byte resolution.

Accessing Memory
----------------

``GhidraEmulator`` supports normal memory accesses.

Setting labels on memory has no effect on ``GhidraEmulator``,
and labels are not preserved once execution begins.

.. warning::
   TODO: How well-supported are ISA features that change memory layout,
   like x86 segmentation?

Event Handlers
--------------

``GhidraEmulator`` supports the following event types:

- Instruction Hooks
- Function Models
- Memory Accesses

.. caution::
   ``GhidraEmulator`` hooks behave oddly around delay slot instructions.

   Instruction hooks will not fire if attached to an instruction in a delay slot.

   Memory accesses that occur in a delay slot will report the program counter
   for the parent instruction, although all other machine state will be correct.

Interacting with Ghidra
-----------------------

.. note::
   **Understanding this section is not necessary to write a normal harness.**

   The features described here are completely abstracted
   behind the ``GhidraEmulator`` interface, and are only useful
   if you want to leverage Unicorn for analysis.

   This section describes how to access the relevant objects,
   and any caveats regarding their access.
   Using them for analysis is an exercise left to other tutorials.

It's possible to access the Ghidra emulator instance directly
via the property ``GhidraEmulator._emu``.
