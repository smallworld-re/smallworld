.. _machine:

The Machine Object
==================

The root of SmallWorld's machine state representation is the ``Machine`` object.
All pieces of the harness environment are added to the machine,
which then mediates how those pieces are added to or lifted from the back-end emulator.

Adding State to a Machine
-------------------------

All parts of the harness state are added to a ``Machine`` using ``Machine.add()``.

State objects are loaded into a ``Machine`` by reference,
meaning you can create a part of the machine state,
register it with the machine, and then continue to modify it.

The following is a basic example of adding a CPU to a machine


.. code-block:: python

    from smallworld.state import CPU, Machine
    from smallworld.platforms import Architecture, Byteorder, Platform
    
    machine = Machine()

    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)

    machine.add(cpu)

    # Continue configuring `cpu` and `machine`, and eventually use them for an experiment


Applying and Extracting a Machine
---------------------------------

A machine can transfer its contents to an emulator using ``Machine.apply()``.

Unlike ``Machine.add()``, most components of a harness are copied by value.
Updating the original object afterward will not update the emulator's state.

The exception to this are hook objects; they are registered with the emulator,
but are not copied.

.. caution::
   ``Machine.apply()`` does not clear any state already applied to the emulator.
   Reusing an emulator for multiple experiments may cause very interesting
   exceptions or failure modes.

A machine can also copy the contents of an emulator into itself using ``Machine.extract()``.

This will overwrite most of the contents of the current machine, with the following exceptions:

    - Event hook objects are not extracted.
    - Symbolic path constraints (angr only).
    - **TODO**: Figure out what else doesn't get extracted.

.. caution::
   The :ref:`angr backend <angr>` can explore multiple program paths at one time.
   If run in this mode, invoking ``Machine.extract()`` on the emulator
   will fail; which machine state are you trying to extract?

   There's a separate interface on the angr emulator class
   that allows for traversal of the available machine states.
   See the docs for the :ref:`angr backend <angr>` for more information.


The following code uses ``Machine.apply()`` to provision an emulator,
and ``Machine.extract()`` to read back results

.. code-block:: python

    from smallworld.emulators import UnicornEmulator
    from smallworld.state import CPU, Executable, Machine
    from smallworld.platforms import Architecture, Byteorder, Platform
    
    machine = Machine()

    # Set up the CPU
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)
    machine.add(cpu)
    
    # Load a piece of code.
    # Assume this will store 0x2a in rax when done.
    exe_path = "/fake/exe/path.bin"
    code = Executable.from_filepath(exe_path, address=0x1000)
    machine.add(code)

    # Set the machine to start emulating at the start of the code.
    # Assume this is the correct entry point.
    cpu.pc.set(code.address)

    # Specify execution bounds
    machine.add_bound(code.address, code.address + code.get_capacity())

    # Create an emulator and emulate
    emu = UnicornEmulator(platform)
    machine.apply(emu)
    emu.run()
    machine.extract(emu)
    print(cpu.rax)  # (rax, 8)=0x2a

Accessing Extracted State
-------------------------

.. note::
   This interface is pretty incomplete.  You can help by proposing expansions.

``Machine`` includes several helpers to assist in inspecting the data
inside an extracted machine.

``Machine.get_cpu()`` extracts a ``CPU`` object from the machine,
allowing the harness to inspect registers.

``Machine.get_elfs()`` extracts all ELF executable representations,
allowing the harness to inspect all memory covered by their segments.


Execution Helpers
-----------------

``Machine`` supplies several helper functions for performing
common workflows involving ``apply()`` and ``extract()``.

``Machine.emulate()`` applies the ``Machine`` to an emulator, 
runs the emulator until it exits, deep-copies the ``Machine``, 
and extracts emulator state into the copy.

``Machine.step()`` applies the ``Machine`` to an emulator,
and then single-steps the emulator until it stops,
generating a new ``Machine`` after each instruction.

.. caution::
   ``Machine.step()`` can get very memory-hungry,
   since each new ``Machine`` wil contain a full copy
   of all memory ranges specified in the harness.
   This is fine for a hundred byte piece of shellcode,
   but adds up very quickly when harnessing a 4 GB 
   embedded firmware image.

   Consider interacting directly with the ``Emulator`` object
   to control code exploration in this case.

``Machine.analyze()`` passes the machine into an ``Analysis`` object
for analysis.  See the docs on :ref:`analyses <analyses>` for more information.

``Machine.fuzz()`` leverages ``unicornafl`` to fuzz the harness.
See the :ref:`fuzzing tutorial <fuzzing>` for more information.

The following is the apply/extract example rewritten to use ``Machine.emulate()``

.. code-block:: python

    from smallworld.emulators import UnicornEmulator
    from smallworld.state import CPU, Executable, Machine
    from smallworld.platforms import Architecture, Byteorder, Platform
    
    machine = Machine()

    # Set up the CPU
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)
    machine.add(cpu)
    
    # Load a piece of code.
    # Assume this will store 0x2a in rax when done.
    exe_path = "/fake/exe/path.bin"
    code = Executable.from_filepath(exe_path, address=0x1000)
    machine.add(code)

    # Set the machine to start emulating at the start of the code.
    # Assume this is the correct entry point.
    cpu.pc.set(code.address)

    # Specify execution bounds
    machine.add_bound(code.address, code.address + code.get_capacity())

    # Create an emulator and emulate
    emu = UnicornEmulator(platform)
    final_machine = machine.emulate(emu)
    final_cpu = final_machine.get_cpu()
    print(final_cpu.rax)  # (rax, 8)=0x2a


Exit Points
-----------

The ``Machine`` class stores exit points for the harness.

An exit point is an address which, if executed, will cause execution to stop.
Note that execution stops before the instruction at the exit point is executed.
There is currently no concept of an "exit-after point" in SmallWorld.

Exit points can be on any address, including one outside valid memory.
This is useful for exiting on return from the top-level function,
or detecting a call to a non-existent library.

.. caution::
   The :ref:`panda backend <panda>` doesn't allow exit points on unmapped memory.
   This will likely be fixed with the next major update.

The following is an example of specifying an exit point on a false return

.. code-block:: python

    from smallworld.emulators import UnicornEmulator
    from smallworld.state import CPU, Executable, Machine
    from smallworld.platforms import Architecture, Byteorder, Platform
    
    machine = Machine()

    # Using aarch64, since it's easy to specify a return address
    platform = Platform(Architecture.AARCH64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)
    machine.add(cpu)
    
    # Load a piece of code.
    # Assume it contains a function that returns
    exe_path = "/fake/exe/path.bin"
    code = Executable.from_filepath(exe_path, address=0x1000)
    machine.add(code)

    # Set the machine to start emulating at the start of the code.
    # Assume this is the correct entry point.
    cpu.pc.set(code.address)

    # Configure the link register with a spurious address,
    # and set an exit point on that address.
    exit_point = 0xdead0000
    cpu.lr.set(exit_point)
    machine.add_exit_point(exit_point)

    # Create an emulator and emulate.
    emu = UnicornEmulator(platform)
    final_machine = machine.emulate(emu)
    final_cpu = final_machine.get_cpu()

    # The final program counter should be the spurious return.
    print(final_cpu.pc) # (pc,8)=0xdead0000

.. note::

   Users who are used to Unicorn will be used to
   the emulator requiring an exit point in order to run.

   SmallWorld is engineered so that an exit point isn't required,
   even when running with the :ref:`unicorn backend <unicorn>`.

Bounds
------

The ``Machine`` class also stores program boundaries.

These are ranges of addresses that are valid to execute;
emulation will stop gracefully if it encounters a program counter
outside these ranges or, for symbolic executors, an unconstrained program counter.

If no bounds are specified, emulation will consider any concrete address in-bounds.
Emulation will still stop if the program leaves mapped memory
or tries to execute an invalid instruction.
    
The following example constrains a program's execution using bounds alone.
This is useful if you don't know exactly where a program will exit,
but do know what parts of memory are code that you want to explore:

.. code-block:: python

    from smallworld.emulators import UnicornEmulator
    from smallworld.state import CPU, Executable, Machine
    from smallworld.platforms import Architecture, Byteorder, Platform
    
    machine = Machine()

    # Using aarch64, since it's easy to specify a return address
    platform = Platform(Architecture.AARCH64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)
    machine.add(cpu)
    
    # Load a piece of code.
    # Assume it contains a function that returns
    exe_path = "/fake/exe/path.bin"
    code = Executable.from_filepath(exe_path, address=0x1000)
    machine.add(code)

    # Set the machine to start emulating at the start of the code.
    # Assume this is the correct entry point.
    cpu.pc.set(code.address)

    # Configure the link register with a spurious address,
    # and set an exit point on that address.
    exit_point = 0xdead0000
    cpu.lr.set(exit_point)
    machine.add_exit_point(exit_point)

    # Create an emulator and emulate.
    emu = UnicornEmulator(platform)
    final_machine = machine.emulate(emu)
    final_cpu = final_machine.get_cpu()

    # The final program counter should be the spurious return.
    print(final_cpu.pc) # (pc,8)=0xdead0000

Constraints
-----------

A ``Machine`` can accept symbolic constraint expressions using ``Machine.add_constraints()``

A constraint is an expression that some emulators (currently, only angr) can use
to limit the possible values of uninitialized variables without fully committing to one value.
This is useful for placing conditions on your initial program state,
without over-constraining the value and risking missing interesting
program paths.

A symbolic executor will also build up constraints
based on the choices the program made in resolving conditional operations.
It's possible to examine these constraints using ``Machine.get_constraints()``

Other parts of machine state will imply constraints;
a ``Value`` with a label and contents will create stating that
the label must equal the contents of the ``Value``.
These will not show up in ``Machine.get_constraints()`` before
the machine is applied to an emulator, but they will show up if the machine is extracted.

Constraints are represented as Claripy expression objects.

.. warning::
   TODO: Write a tutorial for this; interpreting Claripy gets a bit involved.
