.. _tutorial_elf:

Loading an ELF
==============

In this tutorial, you will be guided through loading an ELF object file.

Executable and Linkable Format (ELF) is the file format Linux
and most other Unix-descended operating systems use to store
native code.  It contains the code and data for one executable or library,
as well as metadata detailing what the program loaders need to do
to set up that code and data within a process.

Consider the example ``tests/elf/elf.amd64.elf.s``:

.. literalinclude:: ../../../tests/elf/elf.amd64.elf.s
    :language: GAS

This is a very simple, not totally correct program that will perform
the equivalent of ``strlen`` on ``argv[1]``.
You can build it into ``elf.amd64.elf`` by running the following:

.. code-block:: bash

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
--------------------

SmallWorld includes a model of the basic features of the Linux kernel's ELF loader.
To exercise it, you need to use ``Executable.from_elf()``, described in
:ref:`memory`.

ELFs can contain code that's intended to be loaded at a specific position,
or that can be loaded at any address (position-independent).
If our example is position independent, we will need to specify a load address.

Let's take a look at our example, using the command ``readelf -l elf.amd64.elf``

.. command-output:: readelf -l elf.amd64.elf
    :cwd: ../../../tests/elf

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
----------------------

We need to find the start of our code within the ELF.

In our assembly, the code is contained in the ``_start`` function symbol.
This is a special symbol for Linux programs; it defines the program entrypoint,
which is exposed in the ELF metadata, and can be accessed via ``ElfExecutable.entrypoint``.

.. code-block:: python

    entrypoint = code.entrypoint
    cpu.rip.set(entrypoint)

Adding Bounds
-------------

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
-----------------------

Combined, this can be found in the script ``elf.amd64.py``:

.. literalinclude:: ../../../tests/elf/elf.amd64.py
    :language: Python

Here, we load the code from our ELF and set the program counter to the entrypoint.
We also configure a stack with the expected argc/argv layout,
and set ``rdi`` and ``rsi`` equal to argc and argv respectively.

We halt execution before the final return (which won't work),
and read out the result from ``rax``.

Here is what running the harness looks like:

.. command-output:: python3 elf.amd64.py foobar
    :cwd: ../../../tests/elf/

Since "foobar" is length six, we have harnessed ``elf.amd64.elf`` completely.

