Function Hooking with ELF Relocations
=====================================

In this tutorial, you will be guided through the steps
to model a function, and hook it using the linker
metadata found in an ELF file.

.. note::

    Details on actually loading an ELF file can be found
    in :ref:`this tutorial <tutorial_elf>`.
    It's strongly recommended you complete that one first.

Consider the example ``tests/rela/rela.elf.c``:

.. literalinclude:: ../../../tests/rela/rela.elf.c
    :language: C 

Here, we have an ELF that references the library function ``puts``.

You can build this into ``rela.amd64.elf`` using the following commands:

.. code-block:: bash
    
    cd smallworld/tests
    make rela/rela.amd64.elf

Let's take a look at the ELF metadata, specifically regarding puts:

.. command-output:: readelf -s -D rela.amd64.elf | grep 'puts'
    :shell:
    :cwd: ../../../tests/rela/

.. command-output:: readelf -r rela.amd64.elf | grep 'puts'
    :shell:
    :cwd: ../../../tests/rela/

The symbol is undefined, and it has a ``JUMP_SLOT`` relocation,
meaning that this is a dynamic symbol that's going to get
loaded from another library.

We could load and harness an entire other library
just to provide ``puts``, but we're not that interested
in exercising the library.  Let's use a model instead.

To do that, we will need the following:

- An execution stack, to support the ``call`` opcode
- A model of ``puts``

Adding a Stack
--------------

Setting up a stack is covered in :ref:`this tutorial <tutorial_mapping>`.
For this test, we don't need any interesting data on the stack.
We just need to reserve the memory and configure the registers:

.. code-block:: python
    
    # Create our stack
    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 4000)
    machine.add(stack)
    
    # Push a fake return value onto the stack.
    # Make it something we can use as an exit point later.
    stack.push_integer(0x7FFFFFF8, 8, "fake return address")

    sp = stack.get_pointer()
    cpu.rsp.set(sp)

Adding a Puts Model
-------------------

Let's write our own ``puts`` model.
We want to read a null-terminated string out of memory
at the address specified at the argument register,
and print it to stdout.

Let's be a little careful.  If someone feeds us an unterminated string,
our model could fail in a variety of ways:

- We could get an "unmapped read" error if we go off the edge of mapped memory
- We could get a "symbolic value" error if we're using angr and read past the edge of initialized memory.

The first case has fairly good error reporting.
Let's add a little more introspection for the second case:

.. code-block:: python

    # Define a puts model
    class PutsModel(smallworld.state.models.Model):
        name = "puts"
        platform = platform
        abi = smallworld.platforms.ABI.NONE
    
        def model(self, emulator: smallworld.emulators.Emulator) -> None:
            # Reading a block of memory from angr will fail,
            # since values beyond the string buffer's bounds
            # are guaranteed to be symbolic.
            #
            # Thus, we must step one byte at a time.
            s = emulator.read_register("rdi")
            v = b""
            try:
                b = emulator.read_memory_content(s, 1)
            except smallworld.exceptions.SymbolicValueError:
                b = None
            while b is not None and b != b"\x00":
                v = v + b
                s = s + 1
                try:
                    b = emulator.read_memory_content(s, 1)
                except smallworld.exceptions.SymbolicValueError:
                    b = None
            if b is None:
                raise smallworld.exceptions.SymbolicValueError(f"Symbolic byte at {hex(s)}")
            print(v)

Linking the Puts Model
----------------------

We don't have a fixed address for ``puts``.  Normally, that would be up to the program loader.
Let's just make up a nice round number.

.. code-block:: python

    # Configure the puts model at an arbitrary address
    puts = PutsModel(code.address + 0x10000)
    # Add the puts model to the machine
    machine.add(puts)

We also need to do the program loader's job and update our ELF
with the address of ``puts``:

.. code-block:: python

    # Relocate puts
    code.update_symbol_value("puts", puts._address)

Putting it All Together
-----------------------

Combined, this harness can be found in the script ``tests/rela/rela.amd64.py``

.. literalinclude:: ../../../tests/rela/rela.amd64.py
    :language: Python

This harness should print ``Hello, world!\n`` to the console.

Here is what running it looks like:

.. command-output:: python3 rela.amd64.py
    :cwd: ../../../tests/rela 

We do in fact see, ``Hello, world!\n`` printed to the console,
so we harnessed ``rela.amd64.elf`` successfully.
