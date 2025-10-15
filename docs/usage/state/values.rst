.. _values:

Values in Smallworld
====================

All leaf-level machine state in SmallWorld is represented as ``Value`` objects.
Each ``Value`` represents a fixed-size sequence of bytes somewhere in the machine.

Contents
--------

A ``Value`` has contents.  This is the data that will get written into machine state
when the value is applied to an emulator.

If the contents are ``None``, the value is considered uninitialized.
Otherwise, the allowed data type depends on the specific part of machine state being modeled.
Generally, registers contain integers, and memory contains bytes.

Labels
------

A ``Value`` can have a label.  This allows harness authors to attach semantic meaning
to a particular ``Value``.  

Concrete emulators do not consider labels.
An ``Analysis`` based on a dynamic emulator can use them to mark interesting data,
but it otherwise has no meaning.

Symbolic executors use labels to create bound and unbound variables.
When a ``Value`` with a label is loaded into a symbolic executor,
the sequence of bytes tied to that ``Value`` are populated with a variable
named after the label.

If the ``Value`` also has contents, the executor "binds" that variable
to the contents, asserting that the variable must equal the contents of the value.

Data Types
----------

``Values`` can have data types, based off ``ctypes`` objects.

.. warning::
   This feature has not been exercised in a very long time,
   and will probably be removed.

Implementations
---------------

SmallWorld includes three basic ``Value`` classes:

    - ``BytesValue`` stores its contents as a ``bytes`` object.
    - ``IntegerValue`` stores its contents as an integer.
    - ``SymbolcValue`` has no contents; it's a placeholder for uninitialized data.

Registers are also ``Values``.  See :ref:`cpu` for more information.
