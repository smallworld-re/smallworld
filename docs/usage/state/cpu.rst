.. _cpu:

The CPU Object
==============

SmallWorld's ``CPU`` objects are responsible for storing register state.
Harnesses specify an initial CPU when 

CPUs are platform-specific, as each platform has its own set of registers.

Registers are exposed as properties of a ``CPU`` object for ease of access.

.. note::
   Currently, SmallWorld only allows a single ``CPU`` object per machine.
   In the future, it may support multi-processor systems,
   but none of the emulators currently have meaningful multi-processor support.

Registers
---------

A ``Register`` represents a specific CPU register, such as ``rdi``,
and specifies its name and its width in bytes. 

A ``Register``'s contents can be accessed using
``Register.get()`` or ``Register.set()``.

A register starts with no contents.
Concrete emulators will interpret this as a value of zero,
while symbolic executors will interpret this as uninitialized data.

A ``Register``'s contents can be an integer,
or a Claripy symbolic expression if it will be used
with a symbolic executor.

.. caution::
   Using a harness with symbolic values to populate a concrete emulator
   will raise an exception.

A ``Register``'s label can be accessed using
``Register.get_label()`` and ``Register.set_label()``.  
See :ref:`values` for more about how labels work.

The following is an example of setting the contents on a ``Register``::

    from smallworld.state import CPU
    from smallworld.platforms import Architecture, Byteorder, Platform
    
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)
    
    cpu.rax.set(0x1337d00d)
    print(cpu.rax)  # (rax,8)=0x1337d00d

Register Aliases
----------------

A ``RegisterAlias`` represents a named portion of a register.
For example, ``edi`` is an alias for the low four bytes of ``rdi``.

A ``RegisterAlias`` specifies its name, its parent ``Register``,
its offset in bytes into the parent register, and its size.

Accessing the contents of a ``RegisterAlias``
will transparently access the parent ``Register`` object.

Accessing a label on a ``RegisterAlias`` will access
the label for the entire parent ``Register``;
there is no way to specify a partial label on a ``Register``.

The following is an example of setting the contents on a ``Register`` and an associated ``RegisterAlias``::

    from smallworld.state import CPU
    from smallworld.platforms import Architecture, Byteorder, Platform
    
    # Create a CPU
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    cpu = CPU.for_platform(platform)
    
    # Set and check the parent register
    cpu.rax.set(0x1337d00d)
    print(cpu.rax)  # (rax,8)=0x1337d00d

    # Set the register alias
    # The parent should be partially rewritten
    cpu.ax.set(0xcafe)
    print(cpu.rax)  # (rax,8)=0x1337cafe
    print(cpu.ax)   # (ax,2)=0xcafe
    
    # Set the parent
    # The register alias should change
    cpu.rax.set(0xdeadbeef)
    print(cpu.rax)  # (rax,8)=0xdeadbeef
    print(cpu.ax)   # (ax,2)=0xbeef

Fixed Registers
---------------

A ``FixedRegister`` represents a register that's fixed to a specific value.
This helps model platforms with "zero" registers,
or platforms where certain registers must be initialized to specific values.

A ``FixedRegister`` works exactly like a ``Register``, except it
can only contain a single value.  It can be aliased as normal.

Attempts to set the register's contents or label will fail.
