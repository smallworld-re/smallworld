.. _tutorial_heap:

Local Types and the Heap
========================

Introduction
------------

In this tutorial, you will learn how to handle struct data types and
allocate heap memory in SmallWorld. To demonstrate, we will examine
the AMD64 assembly below. This code iterates over a doubly-linked list,
stops on the first node marked as empty, and overwrites its data with
a given input value. We will use SmallWorld to construct a doubly-linked
list on the heap as an input to this code. Then, we will observe the
output state to confirm that it worked as expected.

.. literalinclude:: ../../tests/struct/struct.amd64.s
  :language: NASM

Local Types
-----------

The example code defines a struct type ``node`` which may be chained
together to form a doubly-linked list. Each ``node`` contains some
integer ``data``, a pointer to the ``next`` element in the list, a
pointer to the ``prev`` element in the list, and an integer flag
to mark the node as ``empty``.

When analyzing this program, we may want to read or manipulate the
contents of nodes using their type interface. However, when the code
is compiled, this type information is replaced with hard-coded offsets
from the base address of a given ``node``. In order to interact with
structured data, we need to define its shape in our harness.

In SmallWorld, we accomplish this using the `ctypes`_ library. We
begin by creating a new class, ``StructNode``, which extends ctypes'
``LittleEndianStructure``. We set the ``_pack_`` field to 8 to
indicate that struct fields should be aligned to 8 bytes. Note that
the endianness and struct packing size are platform-dependent.

.. _ctypes: https://docs.python.org/3/library/ctypes.html

.. literalinclude:: ../../tests/struct/struct.amd64.py
  :language: python
  :lines: 20-21

Next, we define the fields of the ``node`` structure. Each field is
defined as a tuple consisting of the field's name and type. We include
a ``"padding_0x4"`` field after the 4-byte ``"data"`` field to ensure
that the ``"next"`` field is properly 8-byte aligned. For pointer types
(``"next"`` and ``"prev"``), we use the ``create_typed_pointer`` helper
function in SmallWorld.

.. literalinclude:: ../../tests/struct/struct.amd64.py
  :language: python
  :lines: 24-30

Now that we have our structure's memory layout defined, we can create
``StructNode`` objects and set their fields like any other
Python object. In the next section, we will learn how to allocate
these objects on the heap in SmallWorld.

Heap Allocators
---------------

When harnessing a binary, it may be expected that some memory has already
been allocated on the heap. In the case of our AMD64 example above,
each ``node`` of the doubly-linked list must already be allocated on the
heap with the ``prev`` and ``next`` fields pointing to its neighbors.
Additionally, the ``rdi`` register must point to the head of the list.

SmallWorld provides two interfaces for heap memory management.
The ``BumpAllocator`` provides a simple heap by placing each new
allocation in the next available slice. The ``CheckedBumpAllocator`` is
a more advanced heap which checks for memory errors. For this example, we
will use the ``BumpAllocator``.

The snippet below constructs a ``BumpAllocator`` heap. We give it an
address of ``0x4000`` and a size of ``0x4000``.

.. literalinclude:: ../../tests/struct/struct.amd64.py
  :language: python
  :lines: 32

We can use our heap to allocate ``StructNode`` objects in SmallWorld.
The ``heap.allocate`` method returns the address of the allocated object,
allowing us to point two nodes at each other as neighbors in the list.

.. literalinclude:: ../../tests/struct/struct.amd64.py
  :language: python
  :lines: 34-47

Completing Our Harness
----------------------

We have now defined the memory layout of our struct type, created a few
linked ``node`` objects, and allocated those objects into our heap.
The final step is to set the inputs of the function and observe the
outputs.

First, we set the ``rdi`` register to the address of node A, the head of
the linked list. Then, we set ``rsi`` to an arbitrary value, in this case
42, and expect it to appear in the data of the final node in our output
state.

.. literalinclude:: ../../tests/struct/struct.amd64.py
  :language: python
  :lines: 54-55

We add the lines below to step through our harness and observe the final
CPU state. We check ``rdi`` to ensure it points to node B and ``esi`` to
ensure it contains 42.

.. literalinclude:: ../../tests/struct/struct.amd64.py
  :language: python
  :lines: 62-66

Now, running our harness, we can see that ``rdi`` has been advanced to
point to node B instead of node A, and 42 was found in the output state
as expected. Our harness successfully operated on our structured data.

.. command-output:: python3 struct.amd64.py
    :cwd: ../../tests/struct/
