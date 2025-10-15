Event Handlers
==============

SmallWorld specifies a number of event handlers
that allow inspection or modeling of various events during emulation.

All event handler classes have a way to specify
a callback that will fire on the relevant event.

Registering an event handler involves constructing the handler,
and adding it to a ``Machine``. 

.. note::
   SmallWorld emulators can handle a few more events that
   do not yet have corresponding event handler objects.

   See the relevant documentation for details.

Instruction Hooks
-----------------

A ``Hook`` object triggers a specific callback every time
execution passes through a specific program counter.

A ``Hook`` object takes an instruction address,
and a callback function, of the form ``callback(emu: Emulator) -> None``.

A ``Hook`` will trigger before the specified instruction
is proceessed by the emulator.  There is currently no way to specify an "after" hook.

Unless the callback specifically modifies emulator state,
a ``Hook`` has no impact on execution.

A ``Hook`` will only trigger if emulation executes the exact specified program counter.
(This is rarely a problem.)

A ``Machine`` can only contain one ``Hook`` for a given program counter.
Adding more will raise an exception when the machine is applied to an emulator.

There are subclasses of ``Hook`` which provide breakpoint-like behavior,
using PDB (``PDBBreakpoint``) or an interactive Python shell (``PythonShellBreakpoint``).

.. note::
   A few platforms (namely MIPS and MIPS64) have a concept called a delay slot instruction.
   This is an early form of instruction-level parallelism where one instruction
   has a "slot" where a second unrelated instruction can execute at the same  time.
   For example, MIPS branch and jump instructions have a slot for an aritmetic
   instruction.

   The different emulators all handle these a bit differently.
   See the docs for specific backends for more information.

Function Models
---------------

A ``Model`` object mimics a function every time
execution hits a specific instruction.

The ``Model`` class is abstract; models of specific functions
should extend ``Model``, implement ``model()`` with the actual model code,
and specify a name, the platform the model works with, and the ABI the model assumes.
For platforms without a concrete ABI, there is ``ABI.NOABI``.

The ``model()`` function receives the current emulator as an argument,
and returns nothing.  ``model()`` may access machine state as it likes,
although attempting to start or step emulation will have undefined behavior.

SmallWorld includes a library of standard C functions for multiple platforms and ABIs.
These, as well as any custom models, can be accessed using ``Model.lookup()``
to fetch and instantiate a model object for a specific named function,
platform, and ABI.

.. caution::
   ``Model.lookup()`` will behave unpredictably if the Python process
   contains more than one ``Model`` subclass with the same name,
   platform, and ABI.

   Recommend instantiating custom models of standard C functions directly,
   rather than using ``Model.lookup()``.

A ``Model`` requires the address of the instruction to bind as an argument.

A ``Machine`` can only contain one ``Model`` bound to a particular instruction.
Adding more will raise an exception when the ``Machine`` is applied to an emulator.

For compatibility with ``Model.lookup()``, 
``Model`` classes that require more configuration should expose
properties that begin as ``None``, and raise exceptions if those properties
are not populated by the harness.  (If you don't care about ``Model.lookup()``,
add whatever extra constructor arguments you want.)
Several of the standard C models use this method to accept extra
configuration; their documentation, as well as the raised exception,
will describe any required configuration.

A ``Model`` is designed to replace an entire function.
The emulator will not emulate the instruction bound by a ``Model``.
Instead, it will invoke ``model()``, and then mimic
a platform-appropriate "return" operation.
Therefore, a ``Model`` should be bound to the entrypoint
instruction of a function you wish to completely replace,
or to an unused address if the function is not within the loaded image.

Currently, there is no way to configure the "return" behavior,
making it difficult to mimic more exotic calling conventions
using ``Model``.

MMIO Models
-----------

The ``MemoryMappedModel`` class responds to reads and writes to a specific region of memory.

This has two uses:

    1. Act as a "watchpoint" to monitor how a program uses memory
    2. Model an MMIO device, where writing to a particular place in memory
       does more than just store data in the specified bytes.

The ``MemoryMappedModel`` class is abstract; handlers for specific events
should extend ``MemoryMappedModel``, and implement ``on_read()`` and ``on_write()``.

A ``MemoryMappedModel`` object requires the starting address
of the region to inspect, and the size in bytes of the region to inspect.

``on_read()`` will trigger on any read overlapping any part of the specified region.
It will receive the current emulator, the starting address of the region read,
the size in bytes of the region read, and the bytes that would be read by this operation.

``on_read()`` can modify machine state as it wishes, although attempting
to start or step emulation will have undefined behavior.
Also, reading or writing within the region specified by this ``MemoryMappedModel`` object
will have undefined behavior.

``on_read()`` can optionally return a ``bytes`` object of the same length as the data read.
The emulator will use this as the results of the read operation, instead of any data in memory.

``on_write()`` will trigger on any write overlapping any part of the specified region.
It will receive the current emulator, the starting address of the region written,
the size in bytes of the region written, and the bytes that were written by this operation.

``on_write()`` can modify machine state as it wishes, although attempting
to start or step emulation will have undefined behavior.
Also, reading or writing within the region specified by this ``MemoryMappedModel`` object
will have undefined behavior.

``on_write()`` cannot modify the value written back to memory;
it's recommended it record any modified value to a property of the ``MemoryMappedModel`` object,
and use that value to modify any future reads via ``on_read()``.
