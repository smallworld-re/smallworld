.. _tutorial_hooking_pe:

Function Hooking with PE Imports
================================

In this tutorial, you will be guided through the steps
to model a function, and hook it using the linker metadata
found in a PE32+ file.

.. note::

    Details on actually loading a PE file can be found
    in :ref:`this tutorial <tutorial_pe>`.
    It's strongly recommended you complete that one first.

Consider the example ``tests/pe/pe.pe.c``:

.. literalinclude:: ../../../tests/pe/pe.pe.c
    :language: C

We already explored actually loading the PE file it generates
in :ref:`this tutorial <tutorial_pe>`, but it invokes
the library function ``puts``, which will need extra handling.

You can build this into ``pe.amd64.pe`` using the following commands:

.. code-block:: bash

    cd smallworld/tests
    make pe/pe.amd64.pe

Let's take a look at the PE metadata, specifically regarding puts:

.. command-output:: x86_64-w64-mingw32-objdump -x pe.amd64.pe | grep -A 29 'msvcrt.dll'
    :shell:
    :cwd: ../../../tests/pe/

The function is imported from ``msvcrt.dll``.
We could load and harness an entire other library just to provide puts,
but we're not that interested in exercising the library.
Let's use a model instead.

To do that, we will need the following:

- An execution stack, to support the ``call`` opcode, as well as some local variables.
- A model of ``puts``.

Adding a Stack
--------------

Setting up a stack is covered in :ref:`this tutorial <tutorial_mapping>`.

Let's take a look at the disassembly for main:

.. command-output:: x86_64-w64-mingw32-objdump -d pe.amd64.pe | grep -A 10 '<main>:'
    :shell:
    :cwd: ../../../tests/pe

The concerning lines are the following:

.. code-block:: GAS
    
    mov     %ecx,0x10(%rbp)
    mov     %rdx,0x18(%rbp)

These are accessing memory above the starting stack pointer, 
so we'll need to allocate a little extra space:

.. code-block:: Python 

    # Create a stack and add it to the state
    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
    machine.add(stack)
    
    # Push some padding onto the stack
    stack.push_integer(0xFFFFFFFF, 8, "Padding")
    stack.push_integer(0xFFFFFFFF, 8, "Padding")
    
    # Push a return address onto the stack
    stack.push_integer(0x7FFFFFF8, 8, "fake return address")
    
    # Configure the stack pointer
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
            s = emulator.read_register("rcx")
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


Note that, unlike the other tutorials that dealt with System-V compatible binaries,
we reference the register ``rcx`` for our argument,
following the Windows cdecl ABI.

Linking the Puts Model
----------------------

We don't have a fixed address for ``puts``.  Normally, that would be up to the program loader.
Let's just make up a nice round number.

.. code-block:: python

    # Configure the puts model at an arbitrary address
    puts = PutsModel(code.address + 0x10000)
    # Add the puts model to the machine
    machine.add(puts)

We also need to do the program loader's job
and update our PE with the address of ``puts``:

.. code-block:: python

    # Relocate puts
    code.update_import("msvcrt.dll", "puts", puts._address)

Putting it All Together
-----------------------

Combined, this harness can be found in the script ``tests/pe/pe.amd64.py``

.. literalinclude:: ../../../tests/pe/pe.amd64.py
    :language: Python

This harness should print ``Hello, world!\n`` to the console.

Here is what running it looks like:

.. command-output:: python3 pe.amd64.py
    :cwd: ../../../tests/pe 

We do in fact see, ``Hello, world!\n`` printed to the console,
so we harnessed ``pe.amd64.pe`` successfully.
