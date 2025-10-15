Common Emulator Interface
=========================

.. note::
   This interface very closely mirrors the :ref:`state` interface,
   to the point it may not be obvious why SmallWorld has a
   separate machine state representation at all.
   
   There are two benefits of having this separation:

   1. Analyses may perform many emulation runs with slight modifications between each.
      It's much easier to store a single ``Machine`` object
      than to have to capture and re-run code to populate an ``Emulator`` for every run.
   2. There are a number of little gotchas and backend-specific pieces of boilerplate
      necessary when populating or accessing an ``Emulator`` directly.
      The state interface captures many of them.


Available Emulators
-------------------

All emulators are subclasses of ``Emulator``,
namely ``AngrEmulator``, ``GhidraEmulator``, ``PandaEmulator``, and ``UnicornEmulator``.
These all take a single ``Platform`` object as an argument to their constructor.

While this interface works hard to unify behavior across emulators,
these are all very different tools with different sets
of supported features and "gotchas".
Please see the docs for the specific backends for details.

.. note::
   Not all backends support all platforms,
   or all features of all platforms.

   See :ref:`platforms_support` for exact details of which
   backends support which platforms.

Execution Control
-----------------

Emulators support three modes of execution:

``Emulator.run()`` emulates code continuously until one of the following happens:

    - Execution encounters a code boundary (exit point or bounds).
    - An event handler raises ``EmulationStop``, or one of its subclasses.

Any other exceptions will get passed up to the caller.

``Emulator.step()`` emulates a single instruction at the current program counter.
All exceptions are raised to the caller.
This includes exceptions indicating a clean exit,
namely ``EmulationStop`` and its subclasses.

``Emulator.step_block()`` emulates a single basic block at the current program counter.
All exceptions are raised to the caller.
This includes exceptions indicating a clean exit,
namely ``EmulationStop`` and its subclasses.

.. note::
    The different backends have slightly different 
    basic block identification algorithms;
    ``Emulator.step_block()`` is not guaranteed to
    advance through the same code in the same way for all backends.

Exit Points and Bounds
----------------------

Emulators allow a harness to support two mechanisms
for bounding execution: exit points and bounds.

An exit point is an address which, if executed, will cause execution to stop.
Note that execution stops before the instruction at the exit point is executed.
There is currently no concept of an "exit-after point" in SmallWorld.

Exit points can be on any address, including one outside valid memory.
This is useful for exiting on return from the top-level function,
or detecting a call to a non-existent library.

.. caution::
   The :ref:`panda` backend does not support exit points on unmapped memory.
   This will likely be fixed with the next major update.

Harnesses or analyses may manually add exit points to the emulator
using ``Emulator.add_exit_point()``.  They may inspect the currently-registered
exit points using ``Emulator.get_exit_points()``. 

Bounds are ranges of addresses that the emulator is allowed to execute.
If the current program counter is not in any of the ranges specified,
emulation will stop.

If no bounds are specified, all mapped memory is considered "in bounds".
Note that, for emulators that treat unmapped memory accesses as errors,
executing an unmapped instruction will be reported as
an unmapped memory access, not as out-of-bounds execution.

Harnesses or analyses may manually add a memory range to the execution bounds
using ``Emulator.add_bound()``.  They may inspect the current bounds using
``Emulator.get_bounds()``, or remove a region from the execution bounds
using ``Emulator.remove_bound()`` (the range does not need to match a specifc added bound.)
 
Accessing Registers
-------------------

Harnesses and analyses may access an emulator's register state using 
``Emulator.read_register()`` and ``Emulator.write_register()``
Register state is represented as an integer in host byte order,
and is converted to and from guest byte order automatically.

.. note::
   Registers with more complicated data types (floating-point or structured data)
   are not represented specially.  It's up to the harness or analysis
   to convert the integral value into a more appropriate format.

   There are a very small number of exceptions;
   see the docs for specific backends for details.

.. note::
   Symbolic values produced by angr can't be represented as integers,
   and need special handling.

   This special handling is performed automatically
   by the :ref:`state` interface. It's only a concern
   when interacting directly with an ``Emulator``.

   See the docs for :ref:`angr` for details.

Emulators may also support a concept of labels (see :ref:`values` for details),
which may be accessed via ``Emulator.read_register_label()``
and ``Emulator.write_register_label()``.
See the docs for specific backends for details on label support.

.. note::
   There may be more than one popular naming convention or style
   for the registers of a specific platform.

   Consult the ``PlatformDefinition`` class for a specific platform
   (see :ref:`platforms`) for the convention SmallWorld uses.

Mapping Memory
--------------

SmallWorld emulators maintain a crude model of a memory map.

This allows emulators to detect out-of-bounds memory accesses;
exactly how this is handled is back-end specific.
See the docs for the specific back-ends.

.. note::
   SmallWorld does not currently support a notion
   of permissions on mapped memory regions.
   All mapped regions are assumed to allow read, write, and execute.

This is handled opaquely by the :ref:`state` interface;
any part of the machine state that needs
mapped memory will request it when the machine state
is applied to the emulator.

Harnesses and analyses may manually add additional memory to the memory map using
``Emulator.map_memory()``, which takes an address and a size.
Addresses and sizes do not need to be page-aligned.

Harnesses and analyses may fetch the current memory map
from an emulator using ``Emulator.get_memory_map()``.
This will return a list of ``Tuple[int, int]``
of the form ``(start, end)``.

.. caution::
   Modifying the memory map of a running emulator
   is untested, and may produce undefined behavior.

.. note::
   The resolution of the memory map differs between backends.
   If a backend maps memory in pages, it will
   automatically page-align requested regions.

   See the docs for the specific backends for details.

.. note::
    SmallWorld emulators don't readily support
    separate interactions with physical and virtual memory:

    1. Most backends don't support the necessary 
       privileged features to manage virtual-to-physical memory mapping.
    2. Managing virtual memory would usually require
       adding a large chunk of a live OS to your harness,
       defeating the purpose of micro execution.

    By default, SmallWorld emulators will support as close to
    a full virtual address space as possible, although
    some emulators may present slightly different
    memory layouts for some platforms.
    See the docs for the specific backends for details.

Accessing Memory
----------------

Harnesses and analyses may access an emulator's memory state using
``Emulator.read_memory()`` and ``Emulator.write_memory()``.
Memory state is represented as ``bytes`` objects.

.. note::
   Symbolic values produced by angr can't be represented as bytes,
   and need special handling.

   This special handling is performed automatically
   by the :ref:`state` interface; it's only a concern
   when interacting directly with an ``Emulator``.

   See the docs for :ref:`angr` for details.

This interface will obey the current memory map, as supported by the backend.
Accessing memory not mapped via ``Emulator.map_memory()`` may raise an exception.

This interface will obey platform-specific configuration, as supported by the backend.
All backends default to a "safe" state; a harness does not need to provide
any platform-specific configuration to perform basic memory accesses.
If a harness does provide such configuration,
memory acceses may raise an exception if they violate the configured parameters,
or if the configuration is invalid.

There is a separate function for writing
executable instruction information, ``Emulator.write_code()``.
For all currently-supported platforms, 
this has the exact same effect on machine state as ``Emulator.write_memory()``.

However, some emulators, namely angr, load code differently from data.
See the docs for specific backends.

Event Handlers
--------------

SmallWorld emulators accept handlers for a variety of events:

    - Instruction execution
    - Function calls
    - Memory accesses
    - System calls
    - Interrupts

Not every backend supports all event types.
see the docs for specific backends for details.

All callback functions receive an ``Emulator``
as their first parameter.  The callback
can use that ``Emulator`` to modify machine state,
including the current program counter.

Attempting to modify the emulator's memory map,
or start execution will result in undefined behavior.

A callback can raise an ``EmulationStop`` exception
to halt emulation gracefully.

Instruction Execution 
*********************

Harnesses or analyses can register callbacks to trigger
before a specific instruction gets executed using
``InstructionHookable.hook_instruction()``.

This takes the address of the instruction,
and a callback of the form ``callback(Emulator) -> None``.

Aside from any explicit modifications made by the callback,
an instruction event handler will not modify emulator state,
or the bound instruction's execution.

The callback will only trigger if the program counter
specifically equals the bound address.
(This is rarely a problem, but can happen
with certain ISAs that allow optional prefixes.)

Only one callback can be registered for a specific program counter.
Attempting to register more than one callback
will raise an exception.
 
A callback can be removed from an instruction
using ``InstructionHookable.unhook_instruction()``.

Harnesses or analyses can also use
``InstructionHookable.hook_instructions()`` to register a callback
that will trigger on every instruction.

Only one such callback can be applied to an ``Emulator``.
Attempting to apply a second callback will raise an exception.

A global instruction callback can be removed
using ``InstructionHookable.unhook_instructions()``.

Function Calls
**************

Harnesses or analyses can register callbacks
that replace an instruction with a function model
using ``FunctionHookable.hook_function()``.

This takes the address of the instruction,
and a callback of the form ``callback(Emulator) -> None``.

The emulator will not execute the bound instruction;
instead, it will execute the callback,
and then mimic a platform-appropriate "return" operation,
as if the instruction were the start of a larger function that then returned.

.. caution::
   Even though the bound instruction gets skipped,
   it must still be in mapped memory.

Only one function model can be registered for  a specific instruction.
Attempting to register more than one model will raise an exeception.

An instruction model can be removed using ``FunctionHookable.unhook_function()``.

Memory Reads
************

Harnesses or analyses can use ``MemoryReadHookable.hook_memory_read()``
to register a callback that triggers when a specific address range is read.

This takes the starting address of the memory region,
the size in bytes of the memory region,
and a callback of the form ``callback(Emulator, int, int, bytes) -> Optional[bytes]``.

The callback receives the start address of the read, the size of the read,
and the data that was read as a ``bytes`` object.

The callback can return ``None`` to allow the read to proceed normally,
or return a ``bytes`` object of the same size as the original read
to override the result of the read operation.

A read callback can be removed from the emulator using
``MemoryReadHookable.unhook_memory_read()``.

Harnesses or analyses can use ``MemoryReadHookable.hook_memory_reads()``
to register a callback that triggers when any memory is read.
The callback has the same semantics as the one for ``MemoryReadHookable.hook_memory_read()``

Only one global read callback can exist at once.
Attempting to register a second will raise an exception.

Multiple global or specific read callbacks can apply
to a particular read operation.  The order they are invoked is not guaranteed.
If a callback modifies the data read, it will override
the data passed to any pending callbacks.

.. note::
   Memory read callbacks will trigger if any part
   of a read overlaps any part of the hooked memory region.
   
   The whole access will be reported to the callback,
   including bytes outside the hooked region.

.. caution::
   A hooked memory region must be mapped.

Memory Writes
*************

Harnesses or analyses can use ``MemoryWriteHookable.hook_memory_write()``
to register a callback that triggers when a specific address range is written.

This takes the starting address of the memory region,
the size in bytes of the memory region,
and a callback of the form ``callback(Emulator, int, int, bytes) -> None``.

The callback receives the start address of the write, the size of the write,
and the data that will be written as a ``bytes`` object.

A write callback can be removed from the emulator using
``MemoryWriteHookable.unhook_memory_write()``.

Harnesses or analyses can use ``MemoryWriteHookable.hook_memory_writes()``
to register a callback that triggers when any memory is written.
The callback has the same semantics as the one for ``MemoryWriteHookable.hook_memory_write()``

Only one global write callback can exist at once.
Attempting to register a second will raise an exception.

Multiple global or specific write callbacks can apply
to a particular read operation.  The order they are invoked is not guaranteed.

Write callbacks can't modify the data written,
but they can store their own internal state
and make it available to a corresponding read callback.

.. note::
   Memory write callbacks will trigger if any part
   of a write overlaps any part of the hooked memory region.
   
   The whole access will be reported to the callback,
   including bytes outside the hooked region.

.. caution::
   A hooked memory region must be mapped.

System Calls
************

Harnesses and models can use ``SyscallHookable.hook_syscall()``
to hook specific system calls encountered by the emulator.

This takes a system call number,
and a callback of the form ``callback(Emulator) -> None``.
(It is assumed the callback was written with a specific syscall in mind.)

Only one callback can be registered for a specific system call number.
Attempting to add another will raise an exception.

A callback for a specific system call can be removed using
``SyscallHookable.unhook_syscall()``.

Harnesses and models can use ``SyscallHookable.hook_syscalls()``
to hook all system calls.
This takes a callback of the form ``callback(Emulator, int) -> None``.
The callback receives the system call number as its second parameter.

Only one callback can be registered for all system calls.
Attempting to add another will raise an exception.

Global system call hooks can be removed using
``SyscallHookable.unhook_syscalls()``.

Emulating an unhooked system call will cause the emulator to raise an exception.

By default, emulating a hooked system call will have no effect;
the emulator will continue at the instruction immediately following the system call.

The callback can modify machine state freely,
and cause emulation to resume at a different instruction by setting the program counter.

Both global and specific system call handlers can be registered at the same time.
The order in which the callbacks fire is not guaranteed.

Interrupts
**********

.. warning::
   SmallWorld has an interface for interrupt hooking,
   but it appears to be non-functional right now.
