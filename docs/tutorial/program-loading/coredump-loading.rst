.. _tutorial_coredump:

Loading a core dump
===================

One of the big limitations of micro-execution is that it is blind
to any kind of state built up by the program before your start point.
Normally, the harness has to build up that state explicitly.

However, there is another option, and that's to load a memory dump
from a live program.

Linux and similar platforms can automatically produce "core dumps"
on certain kinds of program failures, or command a debugger
to produce a similar file.

This file is a modified ELF that contains the memory image
of the faulting process, as well as the values of registers
at the time of the fault.  Perfect for setting up a harness!

.. note::

    Windows can produce similar memory dumps.
    SmallWorld does not yet support loading them.

Consider the program ``elf_core.elf.c``:

.. literalinclude:: ../../../tests/elf_core/elf_core.elf.c
    :language: C

The ``__builtin_trap()`` statement
puts some kind of illegal or faulting instruction
between the ``fscanf`` and the ``puts``.
We want to use that as our starting point for emulation,
and just explore the results of the ``puts``,
without having to deal with the machinations of ``fscanf``.

.. note:: 
    In practice, a program won't put a nice ``__builtin_trap()``
    right where you need it.
    You will need to modify the binary
    to inject a faulting instruction yourself.

You can turn this program into a core dump as follows:

.. code-block:: bash
    
    # Build the test program
    cd smallworld/tests
    make elf_core/elf_core.amd64.elf

    # Enable core dumps
    ulimit -c unlimited

    # Create the core dump
    cd smallworld/tests/elf_core
    make elf_core.amd64.elf.core


In order to build a harness around this file,
we need to do the following:

- Follow the metadata in the core file to unpack the memory image inside.
- Load the registers from the core dump.
- Avoid or replace the trapping instruction so we can keep emulating.

.. warning::
    Generating these core dumps requires a good bit of setup.

    The Makefile assumes the default GCC targets amd64 linux.
    It also needs user-mode QEMU and multiarch gdb
    to actuate the program.

    If you are running SmallWorld in a container,
    ``ulimit -c`` will probably fail; Docker and similar environments
    do not let containers modify ulimits internally.
    Most platforms have some mechanism for setting ulimits
    when you launch a container.
    See your specific container solution's documentation for details.
    
    If you're running on an IT-managed system,
    core dumps may be redirected to a reporting tool.
    You will need to alter ``/proc/sys/kernel/core_pattern``
    to contain the following::
    
        core

    By default, Linux does not dump file-backed pages,
    such as the .text sections of a binary.
    In theory, setting ``/proc/${pid}/coredump_filter``
    to "0x3f" should fix this problem, but it didn't work in testing.

    The SmallWorld team advocates consulting your IT team
    before elevating container privileges or altering auditing facilities.
    Please harness responsibly.

Loading a core dump
-------------------

Core files are just slightly extended ELFs.
We can take a look at our core dump with ``readelf -l``:

.. command-output:: readelf -l elf_core.amd64.elf.core
    :cwd: ../../../tests/elf_core

The ``NOTE`` segment will contain the register map.
The ``LOAD`` segments define blocks of memory from the core file
that must get loaded at specific addresses in memory to rebuild the 
original program's memory image.

SmallWorld includes an extended version of its ELF loader
that will also extract the register map.
You can access this via ``Executable.from_elf_core()``:

.. code-block:: python

    with open(filename, "rb") as f:
        # Load the core dump
        code = smallworld.state.memory.code.Executable.from_elf_core(f, platform=platform)
        machine.add(code)

As with normal ELFs, the loader uses the ``platform`` argument
to verify that the expected platform is being loaded.
The harness can leave that argument blank,
and the ``platform`` property of the ``ElfCoreExecutable`` object
will contain the platform derived by the loader.

Unlike normal ELFs, core files are always fixed-position.

Applying registers
------------------

Actually applying register state from a core dump to a ``CPU``
is extremely straightforward, but must be done explicitly in a harness:

.. code-block:: python

    code.populate_cpu(cpu) 

Avoiding the trap
-----------------

If we were to start emulating now,
we'd get the same illegal instruction trap that killed
the program to begin with.

There are two possible approaches to solve this.

Stepping past the trap
**********************

If the trapping instruction was part of the original program,
and we know we will never pass this point again,
we can simply advance the program counter past it.

SmallWorld doesn't include a facility for disassembling code directly,
but there are already very good tools to get us the information we need.

For this demo, the Makefile produced a second file ``elf_core.amd64.elf.registers``
that contains the register values at the time of the original crash:

.. literalinclude:: ../../../tests/elf_core/elf_core.amd64.elf.registers

Here, we see that ``rip`` is ``0x7ffff6a7a55c``.
Now, if we remember the output of ``readelf -l``,
the file size of that segment was zero.
By default, core dumps don't include the executable segments
of code  

.. command-output:: objdump -d elf_core.amd64.elf.core | grep '5b8:'
    :shell:
    :cwd: ../../../tests/elf_core

Our trap is thanks to a ``ud2`` instruction, which is two bytes long.
We could repair the program counter thusly:

.. code-block:: python

    entrypoint = cpu.rip.get() + 2
    cpu.rip.set(entrypoint)

Removing the trap
*****************

If we expect to encounter this code again,
or if we had to replace an existing instruction in the program
in order to add our trap, simply advancing the program counter won't help.
We will need to rewrite the instruction bytes to remove the trap entirely.

If we replaced an existing instruction, we will know the specific bytes we want to write back.
Otherwise, we will need to use the disassembler as above to learn the number of bytes to rewrite.

In this example, we know the ``ud2`` instruction is two bytes long,
and it did not replace an existing instruction,
so we want to replace it with a two-byte NOP.

In SmallWorld, ``Executables`` are just memory, so we can use the
bytes accessors from the ``Memory`` class to perform our modification quickly:

.. code-block:: python
    
    # 2-byte x86 NOP.
    nop = b'\x66\x90'
    code.write_bytes(cpu.rip.get(), nop) 

.. note::

    Some ISAs present instructions in native byte order,
    so an instruction on a little-endian system will appear backwards in memory.
    Be careful of this when manually rewriting code.

Putting it all together
-----------------------

Combined, this can be found in the script ``actuate/elf_core.amd64.py``:

.. literalinclude:: ../../../tests/elf_core/actuate/elf_core.amd64.py
    :language: Python

Aside from loading the core dump and patching bytes,
the only other step is to hook ``puts``;
we may have the process memory, but we don't have a system call model.

Here is what running the harness looks like:

.. command-output:: python3 elf_core.amd64.py
    :cwd: ../../../tests/elf_core/actuate

Handling missing segments
-------------------------

As mentioned above, Linux won't dump file-backed read-only segments;
it assumes you already have the data.

(There is theoretically way to enable these segments in dumps,
but it may be blocked by other security policies.)

If this happens, we can replace the data by loading the executable
segment out of our original binary:

.. code-block:: python

    origname = filename.replace(".core", "")
    with open(origname, "rb") as f:
        orig = smallworld.state.memory.code.Executable.from_elf(f, platform=platform, address=code.address)
    
    # The core file reserves space before the true load address for its metadata.
    #
    # NOTE: You may need to adjust the masking depending on the segment's offset.
    code_offset = (cpu.pc.get() - code.address) & 0xfffffffffffff000
    code[code_offset] = orig[0x0]

When tested, this wasn't the case for amd64 binaries,
but it was the case for all other architectures.
See any other example ``elf_core_actuate.$ARCH.py`` for examples of this working.

Known Limitations
-----------------

On some platforms, core dumps exercise features that not all emulators support.

- amd64 core dumps include the ``rflags`` register, which angr doesn't represent directly
- i386 core dumps include the ``eflags`` register, which angr doesn't represent directly
- i386 core dumps include segment registers, which require complex setup for Panda and Unicorn

Additionally, extracting the full machine state from Ghidra or angr can take a while.
If you don't need the final machine state,
use ``Machine.apply()`` paired with ``emulator.run()``.
