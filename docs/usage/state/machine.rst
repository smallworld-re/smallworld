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

The following is a basic example of adding a CPU to a machine::

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

    - Hook objects are not extracted.
    - TODO: Figure out what else doesn't get extracted.

.. caution::
   ``Machine.extract()`` will fail if used on ``AngrEmulator`` run in full symbolic mode.
   Symbolic execution explores multiple program paths simultaneously;
   there is no single state to extract.

   There are separate helpers on ``AngrEmulator`` to explore the entire state frontier.

The following code uses ``Machine.apply()`` to provision an emulator,
and ``Machine.extract()`` to read back results::

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

   Consider interacting directly with the ``Emulator`` object
   to control code exploration in this case.

``Machine.analyze()`` passes the machine into an ``Analysis`` object
for analysis.

``Machine.fuzz()`` leverages ``unicornafl`` to fuzz the harness.

.. warning::
    TODO: Link to a dedicated fuzzing tutorial.

The following is the apply/extract example rewritten to use ``Machine.emulate()``::

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
   The Panda backend doesn't allow exit points on unmapped memory.
   This will likely be fixed with the next major update.

The following is an example of specifying an exit point on a false return::

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
    

Bounds
------

The ``Machine`` class also stores program boundaries.

These are ranges of addresses 

Constraints
-----------

A ``Machine`` can accept symbolic constraint expressions using ``Machine.add_constraints()``

A constraint is an expression that some emulators (currently, only angr) can use
to limit the possible values of uninitialized variables without fully committing to one value.
This is useful for exploring a specific subset of code paths, without committing
to a single path.

.. warning::
   TODO: Write a tutorial for this.
