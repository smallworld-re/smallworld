.. _tutorial_pe_linking:

Linking a PE
============

In this tutorial, you will be guided through
loading and linking multiple PE32+ object files.

.. note:: 

    This tutorial builds on :ref:`tutorial_pe`;
    it's highly recommended you read it first.


The majority of PE executables on a desktop or server system
will be dynamically linked.  This means some of their code
is referenced from other PE files,
known as Dynamically Linked Libraries (DLLs).

The program loader is responsible for loading
all DLLs needed by an executable, and resoving
any code and data cross-referenced between them.

SmallWorld doesn't require that you fully link a dynamic executable,
but you may want to harness code that calls a function
or references data from a DLL.

Consider the example ``tests/link_pe/link_pe.pe.c`` and ``tests/link_pe/link_pe.dll.c``:

.. literalinclude:: ../../../tests/link_pe/link_pe.pe.c
    :language: C

.. literalinclude:: ../../../tests/link_pe/link_pe.dll.c
    :language: C

``link_pe.pe.c`` calls the function ``my_atoi()``,
which is defined in ``link_pe.dll.c``.
As the names suggest, we are going to build these two files
into a separate executable and DLL,
so the harness will need to resolve the cross-reference between the two binaries.

You can build these into ``link_pe.amd64.pe`` and ``link_pe.amd64.dll``
using the following commands:

.. code-block:: bash

    cd smallworld/tests

    # NOTE: The order of these files is important
    # link_pe.amd64.dll must exist for link_pe.amd64.pe to link correctly.
    make link_pe/link_pe.amd64.dll link_pe/link_pe.amd64.pe

.. warning::

    This requires a version of GCC targeting MinGW.
    On Debian and Ubuntu, this can be installed via the apt package
    ``gcc-mingw-w64``.

Specifying dynamic dependencies
-------------------------------

The first part of the dynamic linking process
is identifying necessary DLLs.

SmallWorld leaves this process up to the harness author,
allowing them to provide specific versions of any required DLLs,
or to leave out DLLs that won't be relevant to the harness.

We can get a list of the DLLs required by an executable or DLL
using ``x86_64-w64-mingw32-objdump -p``.  Let's try this with ``link_pe.amd64.pe``:

.. command-output:: x86_64-w64-mingw32-objdump -p link_pe.amd64.pe | grep 'DLL Name'
    :shell:
    :cwd: ../../../tests/link_pe

We see that, aside from the core windows libraries ``KERNEL32.dll`` and ``msvcrt.dll``,
our program requires ``link_pe.amd64.dll``.

Loading multiple PEs
--------------------

Loading multiple PE files is as simple as calling the PE loader multiple times,
and adding multiple objects to the ``Machine``.

Like other PEs, DLLs specify a default load address which can be overridden.

.. code-block:: python

    filename = "link_pe.amd64.pe"
    with open(filename, "rb") as f:
        code = smallworld.state.memory.code.Executable.from_pe(
            f, platform=platform, address=0x400000
        )
        machine.add(code)

    libname = "link_pe.amd64.dll"
    with open(libname, "rb") as f:
        lib = smallworld.state.memory.code.Executable.from_pe(
            f, platform=platform, address=0x800000
        )
        machine.add(lib)


Linking PEs
-----------

The final step is to resolve the cross-references between
our binaries, a process called "linking".

PE file linking is mercifully simple.
DLLs provide a data structure called the Export Address Table (EAT).
This is essentially just a list of addresses
that can be looked up by name or by a numeric index called an "ordinal".

PE files and DLLs include a set of Import Address Tables,
one for each required DLL.
These are blank lists of addresses,
with each entry tied to the name or ordinal
of an export from the particular DLL.

The PE dynamic linker simply looks up the named export in the relevant EAT,
and writes its value into the relevant IAT entry.
Any code that needs the imported address
will refer to its IAT entry.

Contrast this with ELF, where there's essentially no limit
to where and in what form an imported value can appear
in code or data.  The PE system is inflexible,
but it's far simpler to model.

SmallWorld offers a few interfaces for simulating this process.

A harness can link a specific import by updating its value;
the PE file will write the correct IAT entry opaquely.

.. code-block:: python
    
    # Remember, exports and imports are defined by (DLL name, export name)
    atoi = lib.get_export("link_pe.amd64.dll", "my_atoi")
    code.update_import("link_pe.amd64.dll", "my_atoi", atoi)

This method is also useful if a harness needs to provide its own address,
say for a function hook (for more information, see :ref:`tutorial_hooking`):

.. code-block:: python
    
    atoi = smallworld.state.models.Model.lookup(
        "atoi", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
    )
    machine.add(atoi)
    code.update_import("link_pe.amd64.dll", "my_atoi", atoi.address)

Beware that the IAT can define an import according
to either the name or ordinal; if one doesn't work, try the other.
Also, the link-level interface of some binaries may not match their public API.
If an update replaced ``my_atoi()`` with a macro calling another function,
the code above would not be resilient to the change.

SmallWorld also offers a method ``PEExecutable.link_pe()``
to perform this operation for every import
in a destination PE which has a corresponding export
in a source PE:

.. code-block:: python

    code.link_pe(lib)

Since PEs index symbols by DLL name, this is somewhat resilient to load order.

Putting it all together
-----------------------

Using what we've learned about the PE loader and linker model,
we can build ``link_pe.amd64.py``:

.. literalinclude:: ../../../tests/link_pe/link_pe.amd64.py
    :language: Python

This includes code for linking a PE file,
as well as setting up the stack and registers to provide
``argc`` and ``argv`` to main,
as well as stubbing out the library initializers.

Here is what running this harness looks like:

.. command-output:: python3 link_pe.amd64.py 42
    :cwd: ../../../tests/link_pe

Since ``0x2a`` is the integer version of 42,
we have successfully harnessed ``link_pe.amd64.pe``
and ``link_pe.amd64.dll``
