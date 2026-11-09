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
     and data.  For the one SmallWorld supports, the 8051, the spaces sit
     side by side in one flat address map, and an object's address decides
     which space it lands in; see :ref:`the 8051's support notes <platforms_support>`.

Intel HEX
---------

``Executable.from_ihex()`` loads an Intel HEX image, the usual output of
embedded toolchains such as SDCC.  Intel HEX records only bytes and the
addresses they go at, so the image is sparse: each run of contiguous bytes is
its own piece of the ``Executable``, and ``bounds`` covers them all.

The format has no symbols.  Pass the linker's map as ``map_file`` to look
them up with ``get_symbol_value()``, as with an ELF; maps from the ASxxxx
linker, which SDCC uses, are supported.  Intel HEX does not record the
platform either, and on the 8051 symbols need it to land in the right address
space: a symbol in a code area at its code address, one in an XDATA area in
XDATA, absolute XDATA areas included, and the rest in internal RAM.  Symbols
in other absolute areas, such as constants, and SFRs and other variables
placed with ``__at``, keep their values, since the map does not say which
space they are in.  An 8051 image must fit the 64 KiB of code space;
banked code, for parts with more flash, is not supported.

.. code-block:: python

    platform = Platform(Architecture.MCS51, Byteorder.BIG)
    with open("prog.ihx") as image, open("prog.map") as map_file:
        code = Executable.from_ihex(image, map_file=map_file, platform=platform)
    main = code.get_symbol_value("_main") 
