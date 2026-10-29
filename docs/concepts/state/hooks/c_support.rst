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
    - aarch64 big-endian
    - aarch64 v8.5a
    - amd64
    - arm v4t (soft-float)
    - arm v5t (soft-float)
    - arm v4t and v5t big-endian (BE32, soft-float)
    - arm v6k (soft-float)
    - arm v6m (soft-float)
    - arm v7a (hard-float)
    - arm v7em (hard-float)
    - arm v7m (soft-float)
    - arm v7r (hard-float)
    - arm v8a (hard-float)
    - arm v8r (hard-float)
    - arm v6k big-endian (BE8, soft-float)
    - arm v7a, v7r, v8a and v8r big-endian (BE8, hard-float)
    - arm v8m (soft-float)
    - i386
    - mips
    - mipsel
    - mips64
    - mips64el
    - powerpc
    - riscv64

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
