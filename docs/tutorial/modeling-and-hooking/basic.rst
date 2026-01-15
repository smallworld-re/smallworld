.. _tutorial_hooking_basic:

Raw Function Hooking
====================

In this tutorial, you will be guided through the steps
to hook and model a function in an unstructured program,
such as an embedded device image.

Consider the example ``tests/hooking/hooking.amd64.s``:

.. literalinclude:: ../../../tests/hooking/hooking.amd64.s
    :language: NASM

You will need to run the following command to produce
``tests/hooking/hooking.amd64.bin``

.. code-block:: bash

    cd smallworld/tests
    make hooking/hooking.amd64.bin

Just by looking at the assembly, we can see that we have two
external function references to ``gets@PLT`` and ``puts@PLT``.

To successfully harness this program,
we will need the following:

- An execution stack, to support the ``call`` opcode and the stack buffer.
- Some implementation of ``gets`` and ``puts``.

We could find another binary that implements them,
but we're not actually interested in actuating library code,
or dealing with the insanity of configuring glibc.
Luckily, we can provide python models of these functions using SmallWorld.

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
    stack.push_integer(0xFFFFFFFF, 8, "fake return address")

    sp = stack.get_pointer()
    cpu.rsp.set(sp)

Adding Function Models
----------------------

There are two options for adding function models.
We can use SmallWorld's existing library of models,
or write our own.  For this tutorial, let's do both.

Adding ``gets``
***************

We can add a default ``gets`` model to our machine as follows:

.. code-block:: python

    # Configure gets model
    #
    # Lookup needs the following arguments:
    # - The name of the function, in this case "gets"
    # - The ABI.  In this case, we're compliant with ABI.SYSTEMV
    # - The address.  From the assembly, this will be the base address of the program plus 0x2800.
    gets = smallworld.state.models.Model.lookup(
        "gets", platform, smallworld.platforms.ABI.SYSTEMV, code.address + 0x2800
    )
    # Add the model to the machine
    machine.add(gets)

This will read a string from stdin,
convert it to a null-terminated byte string,
and write it to memory at the address specified in the argument register.

Adding ``puts``
***************

Let's write our own ``puts`` model.
We want to read a null-terminated string out of memory
at the address specified at the argument register,
and print it to stdout.

Let's be a little careful.  If someone feeds us an unterminate string,
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

    # Configure the puts model
    puts = PutsModel(code.address + 0x2808)
    # Add the puts model to the machine
    machine.add(puts)

Putting it All Together
-----------------------

Combined, this harness can be found in the script ``tests/hooking/hooking.amd64.py``

.. literalinclude:: ../../../tests/hooking/hooking.amd64.py
    :language: Python

This harness should take its input over stdin, and echo it back to the console.

Here is what running it looks like:

.. command-output:: echo "foobar" | python3 hooking.amd64.py
    :shell:
    :cwd: ../../../tests/hooking

We do in fact see "foobar" echoed back to the console,
so we harnessed ``hooking.amd64.bin`` successfully.
