.. _platforms:

Describing a Platform
=====================

SmallWorld harnesses and analyses need to make basic assumptions
about the machine language, hardware features, and basic
software interfaces they expect the target code to use;
a harness may need to specify which ISA to emulate,
which byte order data should get laid out in,
and which calling conventions library models should expect.

This is captured using the enumerations 
``Architecture``, ``Byteorder``, and ``ABI``.

Architecture and Byteorder
--------------------------

The core SmallWorld ``Platform`` class captures the minimum information necessary
to identify an emulation environment, namely architecture and byteorder.

An ``Architecture`` primarily identifies the machine language being interpreted.
It can also encode machine state extensions or optional features of a platform.

.. note::

   Some architectures have a lot of optional extensions,
   many of which are difficult to identify and which aren't expressly
   declared as supported or unsupported by emulators.
   SmallWorld's ``Architecture`` enumeration covers the few major,
   easily-identifiable cases we've encountered, but is by no means complete.


Some platforms can be functionally equivalent, but store numbers and code
in different byteorders.  A ``Byteorder`` specifies whether
this platform represents numbers and instructions as
"big-endian" (most-significant byte first) or "little-endian" (least-significant byte first).

Not only does this help configure the emulator, but it also helps
state and code model classes interact with the machine state presented by the emulator.

.. note::

   Some extremely old architectures use some unusual byte orders.
   None of SmallWorld's supported architectures use these extensively enough
   to make them first-class concepts in our platform representation
   or machine state interfaces.

ABI
---

Architecture and byteorder are sufficient for exercising a single, unified piece of code.
However, most architectures don't specify how functions, code modules, and privilege levels interact.

An Application Binary Interface, or ``ABI`` represents a software contract,
specifying how a program interacts with libraries, the OS, and the system at large.  

Basic SmallWorld harnesses don't need to specify an ABI.
Most of the features of an ABI are either handled directly by the harness,
or are too abstract for a micro-executio harness to care.

The one place ``ABI`` is important is when adding function models to a harness,
since the model and the harnessed code must use the same calling convention.

Platform Definitions
--------------------

A ``Platform`` implies a large amount of information about a machine,
which is typically very difficult to recover without reading technical manuals.
For ease of access, much of this information is collected and exposed through
the ``PlatformDef`` class.

The following is an example of accessing a ``PlatformDef``::

    from smallworld.platforms import Architecture, Byteorder, Platform, PlatformDef

    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    platdef = PlatformDef(platform)

    print(platdef.address_size) # 8
    print(platdef.pc_register)  # rip
    print(platdef.sp_register)  # rsp

See the documentation for ``PlatformDef`` for a full description of the information it contains.

