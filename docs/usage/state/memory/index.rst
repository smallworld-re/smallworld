.. _memory:

Memory Objects
==============

SmallWorld represents ``Memory`` objects as fixed-length sparse arrays of bytes.
Each ``Memory`` object includes a start address, a size, and an indication of the byte order.

.. caution::
   SmallWorld will allow you to add overlapping ``Memory`` objects to a harness.
   The results will be unpredictable, as the order in which they're applied
   is not guaranteed.



Values in Memory
----------------

Data within the ``Memory`` object is stored as a mapping
from starting offset to ``Value`` objects holding the actual data.

See :ref:`values` for more information on ``Value`` objects in general

The most precise mechanism for laying out a memory region
is to treat the ``Memory`` object as a ``Dict[int, Value]``,
mapping an offset into the ``Memory`` object to a ``Value``.

All ``Memory`` objects also support accessor methods to modify contents
without having to manually manipulate the ``Value`` mapping.

``Memory.read_bytes()`` extracts a sequence of bytes
from a ``Memory`` object.  It takes the absolute starting address of the byte sequence,
and its size in bytes. It returns a ``bytes`` object,
and raises an exception if the requested range is outside the
boundaries of the ``Memory`` object, if part of the range is symbolic,
or part of the range is uninitialized.

``Memory.write_bytes()`` modifies a sequence of bytes
in a ``Memory`` object.  It takes the absolute starting address of the range to modify,
and a ``bytes`` object containing the data to overwrite.
It will raise an exception if the requested sequence is outside the boundaries of the ``Memory`` object,
or if part of the existing contents is symbolic.

``Memory.read_int()`` and ``Memory.write_int()`` perform the same operations,
but with the output/input provided as integers.

Some sub-classes may support additional helpers beyond this set.

Implementations
---------------

SmallWorld provides a number of subclasses of ``Memory``
representing different kinds of structured and unstructured memory:

.. toctree::
   unstructured
   stack
   heap
   executables
   objects

