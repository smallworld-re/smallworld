.. _angr:

Angr Backend
============

angr is a user-space symbolic executor.
This is a significantly different tool from the other emulators:

    1. It represents data as logical expressions,
       allowing it to reason over uninitialized or partially-initialized data.
       It also means that angr provides extremely high-fidelity
       data taint analysis natively.
    2. It can compute multiple possible outcomes from a single instruction,
       and explore all of them in parallel.

These features make it an extremely powerful analysis tool,
but using it to its full potential is much less intuitive than
a concrete emulator.  It's also the slowest of the included backends,
at about 53 steps (instruction or block) a second.

angr gets its platform support from two sources:
Valgrind's VEX IR, and Ghidra's Pcode IR.
There are essentially no outward-facing differences between the two IRs.

Execution Control
-----------------

``AngrEmulator`` has two execution modes.
By default, the emulator will operate in full symbolic mode,
exploring all possible program paths.
This is tricky to constrain, and is best suited for analyses.

Once full symbolic execution starts,
most of the emulator interface
won't work if called directly on the root emulator;
which machine state are you trying to access?

Event callbacks are passed a stub subclass of ``AngrEmulator``
that wraps the single machine state which triggered the callback.
This provides the same functionality you'd expect
from a concrete emulator,
except that it can't hook or unhook functions,
and it can't run or step emulation.
Any modifications the callback makes will only
apply to the current machine state and its successors.

In addition to standard event callbacks,
a harness or analysis can access all active machine states at any time
using ``AngrEmulator.visit_states()``.
This takes a callback of the form ``callback(Emulator) -> None``,
and calls the callback once on each state being considered by the emulator,
using the same stub emulator as an event callback.

.. note::
   The emulator objects from callbacks are not valid
   once the callback returns.  Please don't keep them.
 
``AngrEmulator`` can also be switched to "linear mode" using ``AngrEmulator.enable_linear()``.
This stops emulation as soon as it would explore more than one machine state.
In linear mode, it is possible to access emulator state once emulation starts.

.. note::
   ``AngrEmulator`` cannot single-step on platforms with delay slots,
   particularly MIPS and MIPS64.

Exit Points and Bounds
----------------------

``AngrEmulator`` supports exit points and bounds normally.
It will treat execution of unmapped memory as an out-of-bounds access,
and halt gracefully.

Accessing Registers
-------------------

If a register contains concrete information,
``read_register()`` will operate normally.
If the register contains a symbolic expression,
it will raise a ``SymbolicValueError``.

It's possible to access the symbolic expression using ``Emulator.read_register_symbolic()``,
and write back a symbolic expression using ``Emulator.write_register_symbolic()``.

``Emulator.write_register_label()`` has a special interaction with ``AngrEmulator``.
It will replace the contents of the register with a symbolic variable
named after the label.  If the register was initialized,
it will constrain the new variable to equal the expression it replaced.

Operations on that variable will treat it like a variable;
any computations using it will appear as expressions in terms of that variable.
But, it will evaluate to the expression it replaced
when computing conditional expressions or similar.

This allows for an extremely powerful form of data tagging::

    # Assume we configured an amd64 machine
    # with code which will execute
    #
    #     test  %rdi,%rdi
    #     cmove $0x2a,%rax
    #     inc   %rdi

    cpu.rdi.set(0x0)
    cpu.rdi.set_label("input")

    final_machine = machine.run(emulator)

    print(cpu.rdi.get())  # <BV64 input + 0x1>
    print(cpu.rax.get())  # 42

Mapping Memory
--------------

``AngrEmulator`` only uses the memory map to enforce execution boundaries.
The memory map works on a byte resolution.

angr itself does not enforce memory mapping,
and a number of the techniques it uses to operate in the face
of partially-initialized state rely on being able to co-opt unused memory.

Harnesses and analyses that want to be notified of accesses outside of mapped memory
should use the memory access event handlers.

.. caution::

   ``AngrEmulator`` uses angr's symbolic memory feature.

   This handles the case where the program dereferences a symbolic pointer.
   By default, angr will attempt to concretize a symbolic pointer.
   If this isn't possible, it will generate an arbitrary unused address
   and bind the pointer expression to that address.
   
   This allows angr to continue exploring where a concrete emulator
   would be forced to abort, but it does have limitations.

   For one, it makes ``AngrEmulator`` unsuited to the standard harnessing loop,
   since it will continue exploring even after it encounters uninitialized state.

   For another, the default concretization strategy is weak
   if applied to particularly complicated address expressions,
   and can lead to the executor exploring nonsensical program paths.
   
   Currently, this is configurable by modifying the angr memory plugins.

Accessing Memory
----------------

Memory accesses behave the same as registers
regarding symbolic values and labels.

``read_memory()`` will fail if the requested range contains a symbolic value.
``read_memory_symbolic()`` and ``write_memory_symbolic()`` will allow
accesses to memory using symbolic expressions.

``write_memory_label()`` will perform the same kind of variable replacement
as ``write_register_label()``.

.. caution::

    ``AngrEmulator`` is the one backend where ``write_memory()`` and ``write_code()``
    behave differenly.

    angr uses a different memory backend to store code and data.
    Instruction fetches against memory managed by the "data" memory backend
    are inefficient to the point of being unusable
    in some relatively common edge cases,
    so it's important to load code as code.

.. caution::
   
   The "code" memory backend is only configurable before
   the angr project is initialized.  This happens automatically
   if emulation is started or stepped, or can be triggered
   manually by calling ``AngrEmulator.initialize()``.

   Once initialzation has happened,
   ``write_code()`` will switch to using the "data"
   memory backend, with all the performance caveats
   that entails.  Please load your code up front if at all possible.

Event Handlers
--------------

``AngrEmulator`` supports the following event types:

- Instruction hooks
- Function models
- Memory accesses
- System calls

``AngrEmulator`` includes an additional set of memory access hooks
for dealing with symbolic values: ``hook_memory_read_symbolic`` and  
``MemoryReadHookable.hook_memory_read_symbolic()`` and
``MemoryWriteHookable.hook_memory_write_symbolic()``.
These operate in the exact same manner, except they 
use Claripy symbolic expressions instead of ``bytes`` objects.

It's still possible to register concrete memory access event handlers.  
If the symbolic value being read or written can be concretized,
such handlers will operate normally.
Otherwise, the emulator will raise an exception
when it encounters this case.

Interacting with Angr
---------------------

.. note::
   **Understanding this section is not necessary to write a normal harness.**

   The features described here are completely abstracted
   behind the AngrEmulator interface, and are only useful
   if you want to leverage angr for analysis.
   
   This section describes how to access the relevant objects,
   and any caveats regarding their access.
   Using them for analysis is an exercise left to other tutorials.

``AngrEmulator`` itself exposes three angr objects as properties:

- ``proj``: The angr ``Project`` object that holds global configuration
- ``mgr``: The angr ``SimulationManager`` object that tracks active states during execution
- ``state``: The angr ``SimState`` object for the current machine state. 
  (Only available before execution starts, during event hooks, or if linear execution is enabled.)

Actually configuring the angr environment is a bit involved,
and certain modifications must be made at specific points during initialization.
For this purpose, ``AngrEmulator`` takes two extra optional arguments to its constructor,
``preinit`` and ``init``.  These are both of the form ``callback(AngrEmulator) -> None``.

``preinit`` is called after ``proj`` is initialized.
This allows modification of ``proj`` itself, or modifications to angr's registered plugins,
both of which must be performed before ``mgr`` and ``state`` are initialized.

``init`` is called after ``mgr`` and ``state`` are initialized,
and allows custom modifications to those structures.

.. caution::
   
   angr backend initialization doesn't happen in the constructor.
   This is thanks to the whole code loading debacle described above.

   The actual procedure is as follows:

   1. The harness initializes ``AngrEmulator``.
      The angr environment is left uninitialized.

   2. The harness applies machine state to ``AngrEmulator``.  
      ``AngrEmulator`` stores the data temporarily.

   3. The harness triggers ``initialize()``,
      either by calling ``run()``, ``step()``, or ``step_block()``,
      or by calling ``initialize()`` directly.

   4. ``AngrEmulator`` initializes ``proj``,
      and performs default configuration.

   5. ``AngrEmulator`` invokes the ``preinit`` callback, if provided.

   6. ``AngrEmulator`` creates ``state`` and ``mgr``,
      and performs default configuration.

   7. ``AngrEmulator`` invokes the ``init`` callback, if provided.

   8. ``AngrEmulator`` applies stored machine state to ``state``.

   9. ``initialize()`` returns.

   Note that machine state from the harness is not available during the ``init`` callback.
   If an analysis needs to inspect or modify the angr objects
   with machine state applied, it should invoke ``initialize()`` manually.
