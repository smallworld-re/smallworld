Heaps
-----

A ``Heap`` is a specialized ``Memory`` object
that represents a dynamically-allocated region of memory.

A ``Heap`` can be manipulated by allocation.
It can take a raw ``Value`` using ``Heap.allocate()``,
or a primitive type using ``Heap.allocate_integer()``,
``Heap.allocate_bytes()``, or ``Heap.allocate_ctype()``.

The interface also supports freeing
an allocation using ``Heap.free()``,
although this doesn't have an impact on all implementations.

``Heap`` itself is an abstract class.
SmallWorld currently provides ``BumpAllocator``,
which is a simple linear allocator with no free support,
and ``CheckedBumpAllocator``, which adds invalid access detection.

The following is an example of using a ``Heap`` 
to store data passed into the harness by reference:

.. code-block:: python
    
    from smallworld.platforms import Architecture, Byteorder, Platform
    from smallworld.state import Machine
    from smallworld.state.cpus import CPU
    from smallworld.state.memory.code import Executable
    from smallworld.state.memory.heap import BumpAllocator
    from smallworld.state.memory.heap import Stack

    # Define the platform
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    
    # Create the machine
    machine = Machine()

    # Create the CPU
    cpu = CPU.for_platform(platform)
    machine.add(cpu)

    # Load some code.
    # Assume this is an ELF that defines a function
    # void needs_memory(int -arg);
    bin_path = "/path/to/fake.elf"
    with open(filename, "rb") as f:
        code = Executable.from_elf(bin_path, address=0x40000000, platform=platform)
        machine.add(code)

    # Transfer bounds from code to machine.
    for bound in code.bounds:
        machine.add_bound(bound[0], bound[1])

    # Set the entrypoint to needs_memory()
    entrypoint = code.get_symbol_value('needs_memory')
    cpu.rip.set(entrypoint)

    # Create a heap
    heap = BumpAllocator(0x2000, 0x1000)
    machine.add(heap)
    
    # Allocate an integer argument on the heap
    arg_address = heap.allocate_integer(42, 4, None)
    
    # Create a stack
    stack = Stack.for_platform(platform)
    machine.add(stack)

    # Push a fake return address onto the stack
    stack.push_integer(0x10101010, 8, None)
    machine.add_exit_point(0x10101010)
    
    # Configure the stack pointer
    sp = stack.get_pointer()
    cpu.rsp.set(sp)

    # Configure the argument to the target function
    cpu.rdi.set(arg_address)
    
    # Emulate
    emulator = UnicornEmulator(platform)
    final_machine = machine.emulate(emulator)
