.. _memory:

Memory Objects
==============

SmallWorld represents ``Memory`` objects as fixed-length sparse arrays of bytes.
Each ``Memory`` object includes a start address, a size, and an indication of the byte order.

.. caution::
   SmallWorld will allow you to add overlapping ``Memory`` objects to a harness.
   The results will be unpredictable, as the order in which they're applied
   is not guaranteed.

Values in Memory
----------------

Data within the ``Memory`` object is stored as a mapping
from starting offset to ``Value`` objects holding the actual data.

See :ref:`values` for more information on ``Value`` objects in general

The most precise mechanism for laying out a memory region
is to treat the ``Memory`` object as a ``Dict[int, Value]``,
mapping an offset into the ``Memory`` object to a ``Value``.

All ``Memory`` objects also support accessor methods to modify contents
without having to manually manipulate the ``Value`` mapping.

``Memory.read_bytes()`` extracts a sequence of bytes
from a ``Memory`` object.  It takes the absolute starting address of the byte sequence,
and its size in bytes. It returns a ``bytes`` object,
and raises an exception if the requested range is outside the
boundaries of the ``Memory`` object, if part of the range is symbolic,
or part of the range is uninitialized.

``Memory.write_bytes()`` modifies a sequence of bytes
in a ``Memory`` object.  It takes the absolute starting address of the range to modify,
and a ``bytes`` object containing the data to overwrite.
It will raise an exception if the requested sequence is outside the boundaries of the ``Memory`` object,
or if part of the existing contents is symbolic.

``Memory.read_int()`` and ``Memory.write_int()`` perform the same operations,
but with the output/input provided as integers.

Some sub-classes may support additional helpers beyond this set.

Unstructured Memory
-------------------

A ``Memory`` object can represent unstructured memory.
This is useful if it's not clear how a piece of memory gets allocated in the program,
or if you simply don't care how the memory gets allocated.
The harness is responsible for creating and placing ``Value`` objects
to initialize data within the range covered by the ``Memory`` object.


The ``RawMemory`` class is a variant of ``Memory``
that simplifies loading a single concrete byte string that fills the entire region.

``RawMemory`` provides helpers for initializing an object directly from a file,
namely ``RawMemory.from_file()``, which uses a file handle,
and ``RawMemory.from_filepath()``, which uses a path string.

Execution Stacks
----------------

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

The following is an example of setting up a call to ``main`` using a ``Stack``::

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
to store data passed into the harness by reference::
    
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

Executables
-----------

An ``Executable`` is a subclass of ``Memory`` representing some form of code.

The basic ``Executable`` class represents unstructured code, such as a RAM dump or shell code.
It should be initialized using ``Executable.from_file()`` or ``Executable.from_filepath()``

.. caution::
   Some emulators and platforms handle code differently from data.
   Using an ``Exectuable`` instead of a more general ``Memory`` subclass
   is how a harness communicates this split to the emulator.

   - angr uses a different memory backend for code than it does for data.
     Specifying large (more than tens of MBs) of memory as data
     will make the execution engine unusably slow.
   - Ghidra and Panda can model architectures
     that use different address spaces when accessing code
     and data.  We don't support any yet, but this will be the mechanism for controlling
     which address space your memory lands in. 

Object File Loaders
-------------------

Subclasses of ``Executable`` support loading object files.
These are structured binary files that provide
a large amount of information to a program loader:

- Specify platform details to ensure compatibility.
- Specify how to lay out the memory image for this program or library.
- Provide initial data for parts of memory that have initial data.
- Provide an entry point address, if the image is executable
- Provide relocation information, if the image is position-independent.
- Provide information about required libraries and other runtime linking requirements.
- Provide information on imported and exported symbols.
- Provide runtime-specific information, such as the location of initializer routines.

Currently, SmallWorld supports the following formats:

- **ELF**: Used by Linux (and many other platforms) for executables and shared objects.
- **PE32+**: Used by Windows (and a few other platforms) for executables and DLLs.

Such objects should be instantiated using helpers on ``Executable``,
namely ``Executable.from_elf()`` and ``Executable.from_pe()``

.. note::
   SmallWorld doesn't really provide an interface for introspecting
   the metadata of an object file.
   It's assumed that the harness author has access to better 
   dedicated inspection tools like objdump or Ghidra.

.. note::
   ELF files can also represent "relocatable objects",
   which only contain logical program layout information,
   and are waiting for a linker to finalize them into a physical image.

   Relocatable objects include ``.o`` files produced as intermediate compilation
   artifacts or components of a ``.a`` static library, as well as
   ``.ko`` files holding kernel modules.

   The SmallWorld ELF loader currently doesn't handle relocatable objects;
   it requires parsing a different, slightly more complex
   set of metadata from a fully-linked ELF.

Platform Verification
*********************

Object file representations indicate to a certain resolution
which platform the code inside them is compatible with.

The harness can use the optional ``platform`` argument
to ``Executable.from_elf()`` or ``Executable.from_pe()`` to specify a required platform.
If the platform from the header doesn't match,
the loader will raise an exception.

The harness can also leave the ``platform`` argument blank,
and allow the loader to determine its own platform.
The derived platform will be available at the ``platform`` attribute
of the resulting object.

Load Address
************

Object files can specify a base address for their memory image,
or allow the program loader to determine one at runtime.

The harness can specify a load address via the optional ``address``
parameter to ``Executable.from_elf()`` or ``Executable.from_pe()``.

This works differently for ELF and PE files:

- **ELF:** ELF files that specify a load address generally must be loaded at that address.
  If not, the harness must provide an address.  If both or neither specify a load address,
  the parser will raise an exception.
- **PE32+:** PE files nearly always specify a load address that is nearly always optional.
  The harness may specify a load address, otherwise the parser will default to the
  load address in the file.

Memory Layout
*************

Once successfully loaded, an object file representation
will act as a ``Memory`` object with one ``Value`` per allocated segment
in the specified memory image.

This will properly handle both file-backed and zero-initialized (BSS) segments.

.. caution::

   SmallWorld's object file loaders build a memory image
   as it exists raw from the object file.
   It does not duplicate any runtime initialization.

   The problem is that certain libraries are relatively unusable
   without runtime initialization.  Glibc relies on runtime initializers
   to populate data structures for thread-local storage, the heap, the locale subsystem,
   and a host of other critical subsystems.
   Manually piecing together the data structures for the entire ptmalloc heap
   will require a harness of extraordinary complexity.

   SmallWorld provides two alternatives:

   * Using function models to approximate the impacted functions in Python.
   * Starting emulation from a core dump. 

.. note::
   PE32+ files have overlapping initialized segments.
   This is normal, and the overlap always contains the same data.
   This case is handled correctly by the accessor functions on ``Memory``,
   as well as when applying the ``Executable`` to an emulator.

   Be aware of this if you try to manually modify the ``Value`` objects.

.. note::
   Object file representations will apply executable segments
   to emulators as code, and non-executable segments as data.


Entry Point
***********

Object file representations present the entrypoint
specified in the file via the ``entrypoint`` property.

.. note::
   The entrypoint of most desktop application binaries will point
   to runtime initializers that are a) extremely difficult to micro-execute,
   and b) very rarely interesting.

   See :ref:`program_loading` on how to find and exercise ``main()`` on Windows and Linux. 

Bounds
******

Object file representations derive execution bounds 
for the loaded image based on the locations of the executable segments.

The list of ranges will be exposed via the ``bounds`` property of the ``Executable``.

.. caution::
   Bounds are NOT transferred to a ``Machine`` when the ``Executable`` is added,
   nor are they applied to the emulator when the ``Machine`` is applied.

   This makes it easier for a harness to constrain execution
   to a small part of a program or library,
   or to leave execution unconstrained.

Linking and Loading
*******************

Aside from laying out memory, the other major responsibility
of an object file is to provide the metadata needed for runtime linking.

These concepts work almost completely differently for ELF and PE32+ files,
and so are presented separately.

.. caution::

   As a micro-execution framework, SmallWorld's linker and loader models are optional.
   An ``Executable`` can be included in a harness with some or all of its symbols
   left undefined.

   Accessing an undefined symbol will have very platform-specific
   and somewhat difficult-to-diagnose undefined behavior.


PE32+ Relocations
^^^^^^^^^^^^^^^^^

PE32+ files have a concept of relocations,
but they are exclusively used to adjust a program if loaded at a non-standard load address.

SmallWorld handles these opaquely when the ``Executable`` gets initialized.

PE32+ Imports and Exports
^^^^^^^^^^^^^^^^^^^^^^^^^

PE32+ runtime linking is (usually) extremely simple.

A DLL will expose exports, which are a list of identifiable addresses
that other files can reference.  This includes things like function or global variable addresses.

An executable or DLL will expose "imports", which are identifiers (string names or integer ordinals)
into a specific DLL's exports.

At runtime, the linker reads each import for a file and finds the corresponding export
on the specified DLL.  It then copies the address for that export into
the relevant import address table (IAT) entry.  The code will read that address
out of the IAT when it wants to access that export.

SmallWorld has two methods to populate the IAT of a PE32+ file.

The first is ``PEExecutable.update_import()``.
This takes the name of the DLL, a name or ordinal of an import,
and the integer value to write into the IAT.
It will raise an exception if the specified import
doesn't exist.

The second is ``PEExecutable.link_pe()``.
This takes a second ``PEExecutable`` object and updates
any imports in the first PE that have corresponding exports in the second PE.

.. caution::
   PE32+ exports may actually be "forwarded", i.e.: alias an export in another DLL.
   SmallWorld currently does not support this feature.

ELF Symbols and Relocations
^^^^^^^^^^^^^^^^^^^^^^^^^^^

ELF files represent all cross-references as symbols,
essentially named variables within the file metadata.
These serve a lot of purposes, including marking exports,
indicating required imports, and just generally indicating
interesting locations and metadata within the file.

SmallWorld harnesses can access symbols within an ELF
using ``ELFExecutable.get_symbol_value()``
and ``ELFExecutable.get_symbol_size()``.
These both take a string specifying the symbol's name,
and will raise an exception if the symbol doesn't exist.

Any time an image uses an undefined symbol,
the ELF will include a relocation entry
indicating how the image should change when the program loader defines it.

Exactly what kinds of relocations are available,
how they are specified in the ELF file,
and how they are used by the program loader is entirely platform specific.
Currently, only common, relatively simple relocation types are supported by SmallWorld.

SmallWorld has two methods to populate a symbol and update its relocations.

The first is ``ELFExecutable.update_symbol_value()``
It takes the name of a symbol, and the new integer value.
It will overwrite the value of the symbol recorded in the ``ELFExecutable``,
and apply any relocations associated with the symbol.
It will raise an exception if there is no symbol with that
name in the ELF, if the symbol has an associated relocation
that SmallWorld can't handle, or (in rare cases) where there
are multiple symbols with the same name in the ELF.

The second is ``ELFExecutable.link_elf()``
This takes a second ``ELFExecutable``,
and updates all undefined symbols in the first ELF
with the values of defined symbols that share the same name
in the second ELF.
It will raise an exception if any symbol has an associated
relocation that SmallWorld can't handle.
It will skip a symbol if there's more than one
symbol with that name in the first ELF.

.. caution::
   ELF symbols are not bound to a library like PE32+ symbols.
   It's either assumed that there is only one symbol with a specific name
   in an entire process, or the linker will just pick the first copy it sees.

   SmallWorld's model works exactly the same;
   whichever symbol matches first is the one that will stick.

.. caution::
   SmallWorld's ELF linker is currently very basic.

   It will work for common dynamically-linked programs and libraries,
   but the full set of features available for runtime linking
   is absurdly complicated.  Please inform the Smallworld team 
   if you need a feature we don't yet model.

.. caution::
   Some platforms define a "copy" relocation.
   Whereas most relocations compute some value from the symbol and write that into the image
   copy relocations compute an address based off the symbol, dereference that,
   and copy the retrieved data into the image.

   This is extremely annoying to model in a harness,
   since the ``ELFExecutable`` objects don't have access to a complete memory image,
   and in a number of cases, the relevant memory gets initialized at runtime,
   between program start and dynamic symbol resolution.

   Currently, SmallWorld breaks the spec a bit, and allows the harness
   to specify the ultimate value, instead of an address pointing to the ultimate value.

   It is currently up to the harness author to identify when a symbol is referenced
   by a copy relocation. 

The following is an example of a program that exercises ELF linking 
  

Core Dump Loader
----------------

SmallWorld supports loading Linux core dumps.
These are modified versions of ``ELFExecutable``, loaded
using ``Executable.from_elf_core()``

Linux core files are very simple ELF files,
with an extra metadata struct that specifies register state
at the moment the core dump was created.

While core dumps are usually created when a program irretrievably fails,
manually-created core dumps are an amazing way to harness a complex process.

See :ref:`coredump_loading` for a tutorial on building a harness around a core dump.
