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

In SmallWorld, a ``Heap`` is a ``Memory`` object with an interface for
dynamic allocation. See :ref:`heaps` to learn more about heaps in SmallWorld.

For this example, we will use a ``BumpAllocator`` heap. The snippet below
constructs a new ``BumpAllocator`` with an address of ``0x4000`` and a size of
``0x4000``.

.. literalinclude:: ../../tests/struct/struct.amd64.py
  :language: python
  :lines: 32

We can use our heap to allocate ``StructNode`` objects in SmallWorld.
First, we convert our ``StructNode`` into a ``Value`` by using
``Value.from_ctypes()``. Then, we use ``heap.allocate()`` to place our
``Value`` on the heap. This method returns the memory address of the
allocated node, which can then be used to link the nodes together
through their ``next`` and ``prev`` pointers.

.. literalinclude:: ../../tests/struct/struct.amd64.py
  :language: python
  :lines: 34-47

Completing Our Harness
----------------------

We have now defined the memory layout of our struct type, created a few
linked ``node`` objects, and allocated those objects on our heap.
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
CPU state. We expect ``rdi`` to iterate through the list and point to node
B at the end. We also expect that the ``data`` field of node B will
contain 42. To verify this, we extract the heap memory from our emulator
and use ``ctypes`` to create a new ``StructNode`` from the bytes at node
B's address.

.. literalinclude:: ../../tests/struct/struct.amd64.py
  :language: python
  :lines: 59-67

Now, running our harness, we can see that ``rdi`` has been advanced to
point to node B and its ``data`` field has been set to 42. Our harness
successfully operated on our structured data.

.. command-output:: python3 struct.amd64.py
    :cwd: ../../tests/struct/
