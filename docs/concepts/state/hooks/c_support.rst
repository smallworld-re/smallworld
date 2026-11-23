.. _models:

C Library Models
================

SmallWorld provides a number of function models for standard C functions.
Models are implemented as ABI-agnostic models,
and then paired with ABI-specific mixins to create platform-specific classes.

The SmallWorld model corpus is a work in progress.
This page lists the status of our model support

We are planning to have at least stub models for the following API standards:

- C99
- POSIX
- Win32

ABI Support
-----------

SmallWorld currently provides basic C calling convention definitions for the following ABIs:

- System V
    - aarch64
    - amd64
    - armel (arm v5t)
    - armhf (arm v7a)
    - i386
    - mips
    - mipsel
    - mips64
    - mips64el
    - powerpc
    - riscv64
- SDCC (``ABI.SDCC``, ``ABI.SDCCSTACKAUTO``)
    - mcs51 (8051)

SDCC's two 8051 conventions differ only in where arguments after the first
go.  Both pass the first argument in DPL, DPH, B and A, least significant byte
first (and R4-R7 too, for a long long), and return values the same way; both
pass every argument of a variadic function on the stack.  Under
``--stack-auto``, or for a ``__reentrant`` function (``ABI.SDCCSTACKAUTO``),
later arguments go on the stack.  By default (``ABI.SDCC``), they go in static
memory belonging to the function, ``_<function>_PARM_2`` and so on, whose
addresses the model cannot know: set the model's ``parameter_addresses`` to
their flat addresses, from the linker's map file.  A variadic 8051 model sets
``variadic``.

Models see SDCC's three-byte generic pointers as flat SmallWorld addresses
(``sdcc_pointer_to_flat`` and ``flat_to_sdcc_pointer`` in
``smallworld.state.models.mcs51.sdcc``), with the null pointer as 0, and read
and write data little-endian, as SDCC stores it.  SDCC's small, medium and
large memory models are tested, the medium one with the default convention
only, since SDCC has no medium-model library for the reentrant one; the huge
model's banked code is not modeled.  pdata, the medium model's home for
variables, is a page of XDATA, so a pdata pointer and an XDATA pointer can
name the same byte; a model that returns a pointer into a pdata pointer
argument's object - the nearest pointer argument at or below it, in the same
page - returns a pdata pointer.  As in SDCC's
library, a pdata pointer reaches the page the paging SFR - P2, or the SFR the
CPU's ``xpage_sfr`` names - holds at the time of the call.  Only the C99 functions
SDCC's library provides are modeled for the 8051.  ``qsort`` and ``bsearch``
call their comparator back with SDCC's reentrant convention, as SDCC's library
does; a program's comparator must be declared ``__reentrant``, which SDCC does
not check.  A model calling back into the program gets a function pointer with
the right convention from its calling context's ``function_pointer()``.
``memset``, ``strchr`` and ``strrchr`` take a ``char`` rather than an ``int``
on the 8051, as SDCC declares them.

The model API currently supports six arguments,
the maximum of any standard C function.
The underlying calling convention model supports arbitrary arguments.

The models support variadic arguments; 
see the `printf` or `scanf` models for examples on how to use these.

The models do not support returning structs or multiple values.

The models have no way of expressing struct arguments passed by value.

The models currently don't support `va_list` arguments.
These are opaque structs defined as compiler intrinsics,
making them annoying to model.

The System V i386 calling convention uses the x87 registers
to return floating-point values.  None of our emulators support this.

Function Support by Header
--------------------------

The following tables present the current status of the function models.
They are grouped by API standard, and then by header file.

The options for the "support" field mean the following:

- **Full:** Model is complete.
- **Imprecise:** Model missing critical behavior.  Will raise an exception unless otherwise configured.
- **N/I:** Not implemented, but planned.
- **None:** Not modeled.  Will raise an exception.

.. csv-table:: C99: string.h
    :file: c99_string.csv
    :header-rows: 1
    :stub-columns: 1
    :delim: ,

.. csv-table:: C99: stdlib.h
    :file: c99_stdlib.csv
    :header-rows: 1
    :stub-columns: 1
    :delim: ,

.. csv-table:: C99: stdio.h
    :file: c99_stdio.csv
    :header-rows: 1
    :stub-columns: 1
    :delim: ,
