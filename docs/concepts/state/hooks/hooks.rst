Event Handlers
==============

SmallWorld specifies a number of event handlers
that allow inspection or modeling of various events during emulation.

All event handler classes have a way to specify
a callback that will fire on the relevant event.
That callback accesses the current machine state
through the :ref:`emulator <emulators_interface>` interface.

Registering an event handler involves constructing the handler,
and adding it to a ``Machine``.

.. note::
   SmallWorld emulators can handle a few more events that
   do not yet have corresponding event handler objects.

   See the :ref:`relevant documentation <emulators_interface>` for details.

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

The following is an example of a harness using a ``Hook``
to detect when a specific instruction gets called:

.. code-block:: python

    from smallworld.emulators import UnicornEmulator
    from smallworld.state import CPU, Executable, Machine
    from smallworld.platforms import Architecture, Byteorder, Platform
    from smallworld.state.models import Hook
    
    machine = Machine()

    # Set up the CPU
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)
    machine.add(cpu)
    
    # Load a piece of code.
    # Assume this will execute a loop
    # that passes the first instruction ten times.
    exe_path = "/fake/exe/path.bin"
    code = Executable.from_filepath(exe_path, address=0x1000)
    machine.add(code)

    # Set the machine to start emulating at the start of the code.
    # Assume this is the correct entry point.
    cpu.pc.set(code.address)

    # Specify execution bounds
    machine.add_bound(code.address, code.address + code.get_capacity())

    # Set up an instruction hook on the first instruction.
    seen = 0
    def instruction_hook(emu):
        global seen
        seen += 1

    hook = Hook(code.address, instruction_hook)
    machine.add(hook)

    # Create an emulator and emulate
    emu = UnicornEmulator(platform)
    machine.apply(emu)
    emu.run()

    # Print the number of times the hook fired
    print(seen) # 10

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
    
The following example uses a pre-provided function model
to capture the behavior of ``puts()``:

.. code-block:: python

    from smallworld.emulators import UnicornEmulator
    from smallworld.state import CPU, Executable, Machine
    from smallworld.state.memory.stack import Stack
    from smallworld.platforms import ABI, Architecture, Byteorder, Platform
    from smallworld.state.models import Model
    
    machine = Machine()

    # Set up the CPU
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)
    machine.add(cpu)
    
    # Load a piece of code.
    # Assume that the function `puts()` exists at offset 0x1000,
    # and will get called to print "Hello, world!"
    exe_path = "/fake/exe/path.bin"
    code = Executable.from_filepath(exe_path, address=0x1000)
    machine.add(code)

    # Set the machine to start emulating at the start of the code.
    # Assume this is the correct entry point.
    cpu.pc.set(code.address)


    # Specify execution bounds
    machine.add_bound(code.address, code.address + code.get_capacity())

    # Set up an execution stack
    stack = Stack.for_platform(platform, 0x8000, 0x4000)
    machine.add(stack)
    stack.push_integer(0xffffffff, 8, "")
    sp = stack.get_pointer()
    cpu.rsp.set(sp)

    # Add a model for puts
    puts = Model.lookup("puts", platform, ABI.SYSTEMV, code.address + 0x1000)
    machine.add(hook)

    # Create an emulator and emulate
    emu = UnicornEmulator(platform)
    machine.apply(emu)
    emu.run()  # Prints "Hello, world!" to stdout.


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

The following is an example of using an ``MemoryMappedModel`` 
to capture reads and writes to a certain location:

.. code-block:: python

    from smallworld.emulators import UnicornEmulator
    from smallworld.state import CPU, Executable, Machine
    from smallworld.platforms import Architecture, Byteorder, Platform
    from smallworld.state.models import MMIOModel
    
    machine = Machine()

    # Set up the CPU
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)
    machine.add(cpu)
    
    # Load a piece of code.
    # Assume this will read and write to a global 4-byte int at offset 0x1000
    exe_path = "/fake/exe/path.bin"
    code = Executable.from_filepath(exe_path, address=0x1000)
    machine.add(code)

    # Set the machine to start emulating at the start of the code.
    # Assume this is the correct entry point.
    cpu.pc.set(code.address)

    # Specify execution bounds
    machine.add_bound(code.address, code.address + code.get_capacity())

    # Set up a MemoryMappedModel to capture writes to our target location.
    class MyIntModel(MemoryMappedModel):
        def __init__(self, address: int, size: int):
            super().__init__(address, size)
            self.curr_value = 0
        
        def on_read(self, emu, addr, size, content):
            # Ignore reads
            pass

        def on_write(self, emu, addr, size, content):
            # Capture a modification to our int.
            if addr >= self.address and addr + size <= self.address + self.size:
                # This is a valid write.
                # It needs to handle partial writes.
                curr_data = bytearray(self.curr_value.to_bytes(self.size, "little"))
                curr_data[address:address + size] = content
                self.curr_value = int.from_bytes(curr_data, "little")
            else:
                # Odd access.  Either someone is using a very ham-fisted vector operation,
                # or we were wrong about the layout of memory.
                raise Exception(f"Unexpected write to tracked variable [{hex(addr)} - {hex(addr + size)}]")

    myint = MyIntModel(code.address + 0x1000, 4)
    machine.add(myint)

    # Create an emulator and emulate
    emu = UnicornEmulator(platform)
    machine.apply(emu)
    emu.run()

    # Print the final value of our variable
    print(myint.curr_value)
