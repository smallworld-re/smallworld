Unstructured Memory
===================

A ``Memory`` object can represent unstructured memory.
This is useful if it's not clear how a piece of memory gets allocated in the program,
or if you simply don't care how the memory gets allocated.
The harness is responsible for creating and placing ``Value`` objects
to initialize data within the range covered by the ``Memory`` object.


The ``RawMemory`` class is a variant of ``Memory``
that simplifies loading a single concrete byte string that fills the entire region.

``RawMemory`` provides helpers for initializing an object directly from a file,
namely ``RawMemory.from_file()``, which uses a file handle,
and ``RawMemory.from_filepath()``, which uses a path string.
