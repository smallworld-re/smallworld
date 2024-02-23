Harnessing a Simple Program
---------------------------

In this quick tutorial you will be guided through the steps to harness
a very simple snippet of binary code. Here it is, weighing in at only
two lines of x86 assembly.

.. literalinclude:: ../../tests/square.s
  :language: NASM

This example can be found in the ``tests`` directory of the
repository, in the file ``square.s``. There are a number of other
small assembly examples there along with it. There is also a
``Makefile`` in that directory and you will have to run ``make`` there
in order to generate the binary code used in this and other tutorials
involving those tests. Once you have run ``make``, the corresponding
binary, which we will analyze in this tutorial, will be in the file
``square.bin``.

A reasonable first step in harnessing is to run SmallWorld's basic
harness script which assumes nothing about the code:
``basic_harness.py`` (which also lives in the ``tests``
directory). That script is fairly simple, so let's have a look at it.

.. literalinclude:: ../../tests/basic_harness.py
  :language: Python

After the imports, the script sets up logging and hinting. Logging is
probably self-explanatory (change level to `logging.DEBUG`` to get
lots of low-level output). **Hinting** is a SmallWorld concept. Hints
are described in detail in :ref:`hinting` but the basic idea is that
SmallWorld includes various **analyses** that are intended to provide
hints that can guide the creation of a code harness. You can read more
about analyses in :ref:`analyses`.

Next in the script, a cpu state is created. This is another SmallWorld
concept described in :ref:`state` in detail. You can think of it as a
place to set up register and memory (stack and heap) with specific
values in a way that is agnostic to details about any particular
dynamic analysis employing a specific emulator or engine. So, the same
``state`` could be applied to a Unicorn emulator or a angr one or ...

In the script, we employ an **initializer** to zero out all the
registers in the state (initializers are another SmallWorld concept
described in :ref:`initalizer`) and then load the binary code from a
file and map it into the state.

Finally, the script analyzes the state (which includes the binary we
want to harness). This is the last line in the script and it is what
will generate hints that help build a harness.

Note that all of this setup performed is entirely generic; this script
assumes nothing about the binary to be harnessed. To run the script we just put the binary at the end of the commandline::

  python3 basic_harnesss.py square.bin

Here is what that outputs

.. command-output:: python3 basic_harness.py square.bin
    :cwd: ../../tests/

.. command-output:: python -V
		    
.. literalinclude:: ../../tests/square.py
  :language: Python

.. literalinclude:: ../../tests/square.py
  :language: Python
  :diff: ../../tests/basic_harness.py
