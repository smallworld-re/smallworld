Execution Stacks
================

A ``Stack`` object is a specialized ``Memory`` object
dedicated to representing an execution stack.

In addition to start address and size,
a ``Stack`` maintains a notion of a stack pointer.
It provides helpers to push data onto the stack,
which will insert the correct ``Value`` and advance
the stack pointer.  The harness can access
the current stack pointer via ``Stack.get_pointer()``.

``Stack`` exposes a number of methods for pushing data.

``Stack.push()`` takes a pre-build ``Value`` object.

``Stack.push_bytes()`` takes a ``bytes`` object, 
and a string label to apply to the pushed data.

``Stack.push_int()`` takes an integer value, a size in bytes, 
and a string label to apply to the pushed data.

There are separate ``Stack`` subclasses for each supported platform.
This is to support different growth direction and alignment
requirements, as well as future work to add helpers
that construct call frames or initial program environments.

The following is an example of setting up a call to ``main`` using a ``Stack``

.. code-block:: python

    from smallworld.platforms import Architecture, Byteorder, Platform
    from smallworld.state import Machine
    from smallworld.state.cpus import CPU
    from smallworld.state.memory.code import Executable
    from smallworld.state.memory.stack import Stack

    # Define the platform
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    
    # Create the machine
    machine = Machine()

    # Create the CPU
    cpu = CPU.for_platform(platform)
    machine.add(cpu)

    # Load some code.
    # Assume this is an ELF that defines a main() function.
    bin_path = "/path/to/fake.elf"
    with open(filename, "rb") as f:
        code = Executable.from_elf(bin_path, address=0x40000000, platform=platform)
        machine.add(code)

    # Transfer bounds from code to machine.
    for bound in code.bounds:
        machine.add_bound(bound[0], bound[1])

    # Set the entrypoint to main()
    entrypoint = code.get_symbol_value('main')
    cpu.rip.set(entrypoint)

    # Create the stack
    stack = Stack.for_platform(platform, 0x7fff0000, 0x10000)
    machine.add(stack)
    
    # Push arguments onto the stack
    arg1_string = b"Hello, world!\0"
    stack.push_bytes(arg1_string, None)

    arg1_addr = stack.get_pointer()
    
    arg0_string = b"./fake.elf\0"
    stack.push_bytes(arg0_string, None)

    arg0_addr = stack.get_pointer()

    # Push padding to align the stack pointer to 16 bytes.
    padding = b"\0" - (16 - ((len(arg0_string) + len(arg1_string)) % 16))
    stack.push_bytes(padding)
    
    # Push the argv addresses onto the stack
    stack.push_integer(0, 8, None)          # NULL terminator
    stack.push_integer(arg1_addr, 8, None)  # Address of argv[1]
    stack.push_integer(arg0_addr, 8, None)  # Address of argv[0]

    argv_addr = stack.get_pointer()

    # Push argc and argv onto the stack
    stack.push_integer(argv_addr, 8, None)
    stack.push_integer(2, 8, None)

    # Push a fake return address onto the stack
    stack.push_integer(0x10101010, 8, None)
    machine.add_exit_point(0x10101010)

    # Configure the stack pointer
    sp = stack.get_pointer()
    cpu.rsp.set(sp)

    # Set argument registers
    cpu.rdi.set(2)          # argc
    cpu.rsi.set(argv_addr)  # argv

    # Emulate
    emulator = UnicornEmulator(platform)
    final_machine = machine.emulate(emulator)
