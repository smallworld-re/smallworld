Loading an ELF
==============

In this tutorial, you will be guided through loading an ELF object file.

Executable and Linkable Format (ELF) is the file format Linux
and most other Unix-descended operating systems use to store
native code.  It contains the code and data for one executable or library,
as well as metadata detailing what the program loaders need to do
to set up that code and data within a process.

Loading a single ELF
--------------------

Consider the example ``tests/elf/elf.amd64.elf.s``:

.. literalinclude:: ../../tests/elf/elf.amd64.elf.s
    :language: GAS

This is a very simple, not totally correct program that will perform
the equivalent of ``strlen`` on ``argv[1]``.
You can build it into ``elf.amd64.elf`` by running the following::

    cd smallworld/tests
    make elf/elf.amd64.elf

.. warning:: 
    
    Unlike previous tests, this requires ``as`` to assemble.

    This will only work correctly on an amd64 host;
    on another platform, ``as`` will target the wrong architecture.

In order to harness code contained in an ELF,
we need to do at least the following:

- Follow the metadata in the ELF to unpack the memory image inside
- Set execution to start at the correct place

Using the ELF Loader
********************

SmallWorld includes a model of the basic features of the Linux kernel's ELF loader.
To exercise it, you need to use ``Executable.from_elf()``, described in
:ref:`memory`.

ELFs can contain code that's intended to be loaded at a specific position,
or that can be loaded at any address (position-independent).
If our example is position independent, we will need to specify a load address.

Let's take a look at our example, using the command ``readelf -l elf.amd64.elf``

.. command-output:: readelf -l elf.amd64.elf
    :cwd: ../../tests/elf

This lists the different "program headers", or instructions to the OS
describing how to load the program.  The ``LOAD`` headers
define blocks of memory allocated in the process.

The fact that the segment for offset zero is at address ``0x400000``
tells us that this is a fixed-position ELF.
We do not need to provide a load address when calling ``Executable.from_elf()``,
and we need to avoid memory around address ``0x400000``, or risk clobbering our ELF.

.. code-block:: python

    binpath = "elf.amd64.elf"
    with open(binpath, "rb") as f:
        # from_elf() needs to take the file handle as an argument.
        #
        # The "platform" argument is optional;
        # if absent, the elf loader will infer the platform from the ELF header.
        # if present, the elf loader will error if the ELF is for a different platform.
        code = smallworld.state.memory.code.Executable.from_elf(
            f, platform=platform
        )
        machine.add(code)

Finding the entrypoint
**********************

We need to find the start of our code within the ELF.

In our assembly, the code is contained in the ``_start`` function symbol.
This is a special symbol for Linux programs; it defines the program entrypoint,
which is exposed in the ELF metadata, and can be accessed via ``ElfExecutable.entrypoint``.

.. code-block:: python

    entrypoint = code.entrypoint
    cpu.rip.set(entrypoint)

Adding Bounds
*************

We can use an ELF's metadata to identify executable regions of memory,
and put them "in-bounds" for emulation.

This does not happen automatically,
since a harness may want to restrict execution to a narrower
subset of memory than "everything executable in the ELF."

Here, we are fine defining all code in the ELF as in-bounds:

.. code-block:: python

    for bound in code.bounds:
        machine.add_bound(bound[0], bound[1])

Putting it all together
***********************

Combined, this can be found in the script ``elf.amd64.py``:

.. literalinclude:: ../../tests/elf/elf.amd64.py
    :language: Python

Here, we load the code from our ELF and set the program counter to the entrypoint.
We also configure a stack with the expected argc/argv layout,
and set ``rdi`` and ``rsi`` equal to argc and argv respectively.

We halt execution before the final return (which won't work),
and read out the result from ``rax``.

Here is what running the harness looks like:

.. command-output:: python3 elf.amd64.py foobar
    :cwd: ../../tests/elf/

Since "foobar" is length six, we have harnessed ``elf.amd64.elf`` completely.

Loading an ELF with dependencies
--------------------------------

On desktop or serve Linux systems, the majority of ELF executables
will be dynamically-linked.  This means some of their code is referenced
from other ELF files, known as "shared objects".

The kernel ELF loader isn't sufficient to load a dynamically-linked program;
it needs a utility called the Runtime Link Editor (RTLD) to
load the required shared objects and resolve any cross-referenced between them.

SmallWorld doesn't require that you fully link a dynamic executable,
but you may want to harness code that calls a function
or references data from a shared obejct.

Consider the example ``tests/link_elf/link_elf.elf.c`` and ``tests/link_elf/link_elf.so.c``

.. literalinclude:: ../../tests/link_elf/link_elf.elf.c
    :language: C

.. literalinclude:: ../../tests/link_elf/link_elf.so.c
    :language: C

This is an artifical example, with ``link_elf.so.c`` providing ``atoi``,
which is usually provided by glibc.
The glibc version of ``atoi`` is significantly more complicated,
and is actually pretty difficult to micro-execute.

(Note we actually need to provide ``atoi`` and ``strtol``;
in later versions of glibc, ``atoi`` is just an alias for ``strtol``.
This will come back to bite us later.)

You can build these into ``link_elf.amd64.elf`` and ``link_elf.amd64.so``
using the following commands::

    cd smallworld/tests
    make link_elf/link_elf.amd64.elf link_elf/link_elf.amd64.so


.. warning:: 
    
    Unlike previous tests, this requires ``gcc`` to compile and assemble.

    This will only work correctly on an amd64 host;
    on another platform, ``gcc`` will target the wrong architecture.

Specifying dynamic dependencies
*******************************

The first part of the dynamic linking process is identifying
necessary shared objects.

SmallWorld leaves this process up to the harness author,
allowing them to provide specific versions of any required shared objects,
or to leave out shared objects that won't be relevant to the harness.

We can get a list of the shared objects required by an executable
or shared object using ``readelf -d``.  Let's try this with ``link_elf.amd64.elf``:

.. command-output:: readelf -d link_elf.amd64.elf
    :cwd: ../../tests/link_elf/

The ``NEEDED`` tag specifies the names of the required shared objects.
In this case, we only need ``libc.so.6``, which we will substitute
with ``link_elf.amd64.so`` for ease of harnessing.

Loading multiple ELFs
*********************

Loading multiple ELF files is as simple as calling the elf loader multiple times,
and adding multiple objects to the ``Machine``.

Shared objects are almost always position-independent,
so the harness will need to specify a load address.

.. code-block::

    filename = "link_elf.amd64.elf"
    with open(filename, "rb") as f:
        code = smallworld.state.memory.code.Executable.from_elf(
            f, platform=platform, address=0x400000
        )
        machine.add(code)

    libname = "link_elf.amd64.elf"
    with open(libname, "rb") as f:
        lib = smallworld.state.memory.code.Executable.from_elf(
            f, platform=platform, address=0x800000
        )
        machine.add(lib)

Linking ELFs
************

The final step is to resolve the cross-references between
our binaries, a process called "linking".

The ELF linker is an extremely simple algorithm
with a lot of extremely complicated details.

Each dynamically-linkable ELF defines a set of symbols,
essentially named variables.  Some of these are left undefined,
representing references to code or data in another ELF file.

Each ELF also defines a list (two lists, actually)
of relocations.  These are internal cross-references
describing how assigning a value to an undefined symbol
should change data in the loaded image:  

- How many bits should the value overwrite?
- Should the value be written absolutely,
  or relative to another value?
- Will this value need space allocated
  in a dynamic data structure?

On Linux, the rtld runs before your application code,
finds matching defined and undefined symbols,
and performs the necessary fixups defined in the relocations.

SmallWorld models this process on a few levels.
A harness can link a specific symbol by updating its value;
the ELF model will perform all necessary relocations opaquely:

.. code-block:: python

    atoi = lib.get_symbol_value("atoi")
    code.update_symbol_value("atoi", atoi)

Beware that the link-level interface
of some binaries may not match their public API.
Case in point: in the version of glibc this example was written against,
``atoi`` was a true function.  In a recent update,
it's become a macro that actually calls ``strtol``.

SmallWorld also offers a method ``ElfExecutable.link_elf()``
to perform this operation for every undefined symbol
in a destination ELF which has a corresponding defined symbol
in a source elf:

.. code-block:: python
   
    # Link code and lib against themselves.
    #
    # By default, the Linux compiler will always call a dynamic function
    # indirectly using the platform's dynamic call mechanism,
    # even when calling a function in the same ELF.
    code.link_elf(code, all_syms=True)
    lib.link_elf(lib, all_syms=True) 

    # Link code against lib to resolve actual dependencies.
    code.link_elf(lib)

Note that this requires a bit of care from the harness
when loading multiple ELFs.
If a symbol is defined in more than one shared obejct,
it will take the first version it finds.

Finding ``main()``
******************

A harness can take advantage of the symbol information in an ELF
to start execution at places other than the file's entrypoint.

Even if you want to run the program from the beginning,
the entrypoint of a Linux application ELF
points not to application code, but to the C runtime initializer.
This is a) insanely complicated to harness,
and b) completely uninteresting for most analyses.

In this example, we want to start executing from ``main()``.
We can look up the address of ``main()`` like so:

.. code-block:: python

    entrypoint = code.get_symbol_value("main")
    cpu.rip.set(entrypoint)

.. caution::

    Many ELF files are "stripped";
    they have all metadata not absolutely essential
    for the kernel program loader and rtld removed
    in order to save space, or to bamboozle analysts.

    The symbols defining internal functions like ``main()``
    fall into the category of "non-essential",
    so this technique won't always work.

Putting it all together
***********************

Using what we've learned about the ELF loader and linker model,
we can build ``link_elf.amd64.py``:

.. literalinclude:: ../../tests/link_elf/link_elf.amd64.py
    :language: Python

This includes code for linking an ELF,
as well as setting up the stack and registers
to provide ``argc`` and ``argv`` to ``main()``.

Here is what running this harness looks like:

.. command-output:: python3 link_elf.amd64.py 42
    :cwd: ../../tests/link_elf/
