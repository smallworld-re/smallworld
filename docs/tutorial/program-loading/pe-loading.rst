.. _tutorial_pe:

Loading a PE
============

In this tutorial, you will be guided through loading a PE32+ object file.

Portable Executable (PE) is the file format Windows and
UEFI bootloaders use to store code.  Like ELF,
it contains the code and data for one executable
or library, and the metadata detailing
what the program loader needs to do to set up that code and data
within a process.

The original 32-bit version of the format is known as PE32;
the extended 64-bit version is called PE32+.

Consider the example ``tests/pe/pe.pe.c``:

.. literalinclude:: ../../../tests/pe/pe.pe.c
    :language: C

This is "hello world".  We can build it into a PE file
using the MinGW version of GCC, since true Windows compilers
are extremely annoying to actuate on other platforms:

.. code-block:: bash

    cd smallworld/tests
    make pe/pe.amd64.pe


.. warning::

    This requires a version of GCC targeting MinGW.
    On Debian and Ubuntu, this can be installed via the apt package
    ``gcc-mingw-w64``.

In order to harness the code contained in a PE,
we need to do at least the following:

- Follow the metadata in the PE to unpack the memory image inside
- Set execution to start at the correct place

In this case, we will also need to provide
some kind of implementation for ``puts()``.

Using the PE loader
-------------------

SmallWorld includes a model of the basic features of a PE loader.
To exercise it, you will need to use ``Executable.from_pe()``, described in :ref:`memory`.

PE files define a "preferred" load address,
but usually include enough metadata for the program loader
to use an alternate load address.

Let's take a look at our example:

.. command-output:: objdump -p pe.amd64.pe | head -n 20
    :shell:
    :cwd: ../../../tests/pe

The PE format nicely lists the image load address right in its header;
the default is ``0x140000000``. If we don't specify a load address, it will be loaded here.
For this harness, we chose to specify our own address at ``0x10000``.
The SmallWorld PE loader will handle relocating the code.

.. code-block:: python

    filename = "pe.amd64.pe"
    with open(filename, "rb") as f:
        code = smallworld.state.memory.code.Executable.from_pe(
            f, platform=platform, address=0x10000
        )
    machine.add(code)

Finding ``main()``
------------------

The next step is to figure out where we want to begin executing.

Sadly, internal symbols are a deprecated feature on PE files;
Windows and most MinGW binaries won't have them,
and SmallWorld doesn't look for them.


This is a case for manual RE.
Inspecting the entrypoint routines in Ghidra
tells us that the most probable candidate for ``main()``
is at offset ``0x1000`` in the file,
or the start of the text segment.

.. code-block:: python

    entrypoint = code.address + 0x1000
    cpu.rip.set(entrypoint)

Stubbing out the runtime
------------------------

.. note:: TODO: This bit is likely mingw-specific.  I need to take a look at an actual Windows binary.

If we tried to harness our program now, it would fail with an unmapped memory error.
Let's take a look at ``main()`` in a disassembler:

.. command-output:: objdump -d pe.amd64.pe | grep -A 10 '140001000:'
    :shell:
    :cwd: ../../../tests/pe

I recognize everything there except for the call to ``0x1620``.
Let's look at it in a disassembler:

.. command-output:: objdump -d pe.amd64.pe | grep -A 10 '140001620:'
    :shell:
    :cwd: ../../../tests/pe

If we manually RE this function,
we find that it's just more runtime initialization
that we really don't care about modelling.

Thankfully, it doesn't return anything or otherwise modify the caller,
so we can easily use SmallWorld's function hooking feature
to stub it out:

.. code-block:: python

    # Configure __main model
    class InitModel(smallworld.state.models.Model):
        name = "__main"
        platform = platform
        abi = smallworld.platforms.ABI.NONE
    
        def model(self, emulator: smallworld.emulators.Emulator) -> None:
            # Return
            pass
    
    
    init = InitModel(code.address + 0x1620)
    machine.add(init)


Putting it all together
-----------------------

Using what we now know about the PE loader and our particular executable,
we can build a complete harness in ``pe.amd64.py``.
This will load our file, as well as set up the main stack,
and hook ``puts()``.  See :ref:`this tutorial <tutorial_hooking_pe>` for a more complete guide on how
to hook a function, and :ref:`this tutorial <tutorial_pe_linking>` for how to
handle external function references in a PE file.

.. literalinclude:: ../../../tests/pe/pe.amd64.py
    :language: Python

Here is what running the harness looks like:

.. command-output:: python3 pe.amd64.py
    :cwd: ../../../tests/pe

We see "Hello, world!", so we have successfully harnessed ``pe.amd64.pe``.

