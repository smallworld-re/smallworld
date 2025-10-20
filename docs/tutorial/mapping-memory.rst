Mapping Memory
--------------

In this tutorial, you will be guided through the steps
to harness a snippet of binary code that requires memory,
specifically a program stack.
This time, we've got a total of three lines of assembly.

.. literalinclude:: ../../tests/stack/stack.amd64.s
    :language: NASM

This example can be found in ``tests/square/square.amd64.s``.
You will need to run the following command
to produce ``tests/square/square.amd64.bin``::

    cd smallworld/tests
    make square/square.amd64.bin

As in the first tutorial, we will use ``basic_harness.py``
to get an initial look at what the harness requires:

.. command-output:: python3 examples/basic_harness.py tests/stack/stack.amd64.bin
    :cwd: ../../

This reports failures due to unmapped memory.
If we look back at our assembly, this makes sense.
The final instruction dereferences memory relative to the register ``rsp``.

SmallWorld does not make any assumptions about what memory is available to the program.
We have allocated code using ``Executable.from_filepath()``,
but ``basic_harness.py`` defines no other memory.

To successfully harness, we need to create an execution stack, and add it to our harness.
Details of this interface can be found in :ref:`memory`.

From the assembly, we know that our input is eight bytes wide,
and starts eight bytes after the stack pointer.
We need to push that value onto the stack, and set ``rsp`` appropriately.

We can create the script ``tests/stack.amd64.py`` to perform these changes:

.. literalinclude:: ../../tests/stack/stack.amd64.py
    :language: Python

This harness doesn't take arguments; it assigns fixed values 
``0x11111111``, ``0x22222222``, ``0x33333333``, and ``0x44444444`` to the relevant
registers and memory.

Here is what running the new harness looks like:

.. command-output:: python3 stack.amd64.py
    :cwd: ../../tests/stack/

The sum of the four input numbers is ``0xaaaaaaaa``, so we harnessed
``stack.amd64.bin`` completely.
