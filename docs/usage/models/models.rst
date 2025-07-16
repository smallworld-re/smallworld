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
===========

SmallWorld currently provides basic C calling convention definitions for all supported ABIs.
This is currently limited to a maximum of six arguments and a single return value.

Variadic and `va_list` arguments are not currently supported.

Passing or returning structs by value is not currently supported.

i386 has a special problem where the System-V ABI uses the x87 registers
to return floating-point values.  x87 is not currently supported by SmallWorld.

Function Support by Header
==========================

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

.. csv-table:: C99: stdlib.h
    :file: c99_stlib.csv
    :header-rows: 1
    :stub-columns: 1

.. csv-table:: C99: stdio.h
    :file: c99_stdio.csv
    :header-rows: 1
    :header-columns: 1
