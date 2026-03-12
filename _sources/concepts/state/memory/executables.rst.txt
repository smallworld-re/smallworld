Executables
===========

An ``Executable`` is a subclass of ``Memory`` representing some form of code.

The basic ``Executable`` class represents unstructured code, such as a RAM dump or shell code.
It should be initialized using ``Executable.from_file()`` or ``Executable.from_filepath()``

.. caution::
   Some emulators and platforms handle code differently from data.
   Using an ``Exectuable`` instead of a more general ``Memory`` subclass
   is how a harness communicates this split to the emulator.

   - angr uses a different memory backend for code than it does for data.
     Specifying large (more than tens of MBs) of memory as data
     will make the execution engine unusably slow.
   - Ghidra and Panda can model architectures
     that use different address spaces when accessing code
     and data.  We don't support any yet, but this will be the mechanism for controlling
     which address space your memory lands in. 
