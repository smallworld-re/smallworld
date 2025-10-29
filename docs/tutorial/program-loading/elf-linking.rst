.. _tutorial_elf_linking:

Linking an ELF
==============

In this tutorial, you will be guided through
loading and linking multiple ELF object files.

.. note::

    This tutorial builds on :ref:`tutorial_elf`;
    it's highly recommended you read it first.

On desktop or server Linux systems, the majority of ELF executables
will be dynamically-linked.  This means some of their code is referenced
from other ELF files, known as "shared objects".

The kernel ELF loader isn't sufficient to load a dynamically-linked program;
it needs a utility called the Runtime Link Editor (RTLD) to
load the required shared objects and resolve any cross-referenced between them.

SmallWorld doesn't require that you fully link a dynamic executable,
but you may want to harness code that calls a function
or references data from a shared obejct.

Consider the example ``tests/link_elf/link_elf.elf.c`` and ``tests/link_elf/link_elf.so.c``

.. literalinclude:: ../../../tests/link_elf/link_elf.elf.c
    :language: C

.. literalinclude:: ../../../tests/link_elf/link_elf.so.c
    :language: C

This is an artifical example, with ``link_elf.so.c`` providing ``atoi``,
which is usually provided by glibc.
The glibc version of ``atoi`` is significantly more complicated,
and is actually pretty difficult to micro-execute.

(Note we actually need to provide ``atoi`` and ``strtol``;
in later versions of glibc, ``atoi`` is just an alias for ``strtol``.
This will come back to bite us later.)

You can build these into ``link_elf.amd64.elf`` and ``link_elf.amd64.so``
using the following commands:

.. code-block:: bash

    cd smallworld/tests
    make link_elf/link_elf.amd64.elf link_elf/link_elf.amd64.so


.. warning:: 
    
    Unlike previous tests, this requires ``gcc`` to compile and assemble.

    This will only work correctly on an amd64 host;
    on another platform, ``gcc`` will target the wrong architecture.

Specifying dynamic dependencies
-------------------------------

The first part of the dynamic linking process is identifying
necessary shared objects.

SmallWorld leaves this process up to the harness author,
allowing them to provide specific versions of any required shared objects,
or to leave out shared objects that won't be relevant to the harness.

We can get a list of the shared objects required by an executable
or shared object using ``readelf -d``.  Let's try this with ``link_elf.amd64.elf``:

.. command-output:: readelf -d link_elf.amd64.elf
    :cwd: ../../../tests/link_elf/

The ``NEEDED`` tag specifies the names of the required shared objects.
In this case, we only need ``libc.so.6``, which we will substitute
with ``link_elf.amd64.so`` for ease of harnessing.

Loading multiple ELFs
---------------------

Loading multiple ELF files is as simple as calling the elf loader multiple times,
and adding multiple objects to the ``Machine``.

Shared objects are almost always position-independent,
so the harness will need to specify a load address.

.. code-block:: python

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
------------

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

- How many bits should the relocated value overwrite?
- Should the symbol value itself be written,
  or do we want to write the result of a computation?
- Will this value need space allocated
  in a dynamic data structure?

On Linux, the rtld runs before your application code,
finds matching defined and undefined symbols,
and performs the necessary fixups defined in the relocations.

SmallWorld offers a few interfaces for simulating this process.

A harness can link a specific symbol by updating its value;
the ELF model will perform all necessary relocations opaquely:

.. code-block:: python

    atoi = lib.get_symbol_value("atoi")
    code.update_symbol_value("atoi", atoi)

This method is also useful if a harness needs to provide its own address,
say for a function hook (for more information, see :ref:`tutorial_hooking`):

.. code-block:: python

    atoi = smallworld.state.models.Model.lookup(
        "atoi", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
    )
    machine.add(atoi)
    code.update_symbol_value("atoi", atoi.address)

Beware that the link-level interface
of some binaries may not match their public API.
Case in point: in the version of glibc this example was written against,
``atoi`` was a true function.  In a recent update,
it's become a macro that actually calls ``strtol``.
The code above would not be resilient to this change.

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
------------------

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
-----------------------

Using what we've learned about the ELF loader and linker model,
we can build ``link_elf.amd64.py``:

.. literalinclude:: ../../../tests/link_elf/link_elf.amd64.py
    :language: Python

This includes code for linking an ELF,
as well as setting up the stack and registers
to provide ``argc`` and ``argv`` to ``main()``.

Here is what running this harness looks like:

.. command-output:: python3 link_elf.amd64.py 42
    :cwd: ../../../tests/link_elf/

Since ``0x2a`` is the integer version of 42,
we have successfully harnessed ``link_elf.amd64.elf``
and ``link_elf.amd64.so``
