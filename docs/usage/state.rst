.. _state:

State
-----

The State in SmallWorld is an object representing the values for registers and
memory for some particular CPU. It is used to to set up and initialize these
values prior to running an anlaysis or emulation, but also serves as a place
where final values after emulation can be copied into for inspection.  This
provides two benefits.

   1. The state has a generic interface that is not tied to any particular
      emulator or analytic back-end. So pre-emulation code such as
      initialization, and any post-emulation analysis or triage can be written
      to be generic.
   2. The state can be applied to (copied into) or loaded from (copied out of)
      any emulator meeting SmallWorld's :ref:`emulators` interface.


At the lowest level, there are the objects ``Register``, ``RegisterAlias``, and
``Memory``. These are subclasses of abstract class ``Value``.  All of these
objects have getters and setters to obtain and set values. They also include
methods for initialization, for **apply** -ing their values (writing them) into
an emulator and for **load** -ing them out of an emulator.

A ``Register`` represents a specific CPU register, such as ``edx`` and includes
a name, width in bytes, and a concrete value, if available.

A ``RegisterAlias`` is a convenience object allow one, e.g., to specify the 32
or 16-bit subregisters ``eax`` and `ax`` of the x86_64 base register ``rax``.

A ``Memory`` object represents a region of bytes in memory, and includes a
start address, a size, and an indication of the byte-ordering (big-endian or
litte-endian).
      
The state also includes ``Code`` as well as two subclasses of ``Memory``:
``Stack`` and ``Heap``.

``Code`` objects contain data representing executable code for analysis but
also include information about where to load and how to execute.

The ``Stack``, additionally, has additional methods for **push** -ing and
**pop** -ping values. This permits a natural interface for setting up or
accessing stack arguments and variables.

The ``Heap`` adds support for **malloc** and **free** simplifying the creation
of dynamic variables and structures in memory.

Finally, a ``State`` object is a container for one or more of the above, and,
thus, represents all mutable values in registers and memory. Heap and stack can
be **map** -ped into the state after being created.

Here is some example code using the ``State`` interface::

  import smallworld
  state = smallworld.cpus.AMD64CPUState()
  zero = smallworld.initializers.ZeroInitializer()
  state.initialize(zero)
  state.rax.set(0x11111111)
  stack = smallworld.state.Stack(address=0x2000, size=0x1000)
  stack.push(value=0x231, size=8)
  state.map(stack)
  state.rsp.set(stack.address)
  emu = smallworld.emulators.UnicornEmulator(state.arch, state.mode)
  state.apply(emu)

In this code we create a 64-bit x86 state, zero all of its registers, set a
value for ``rax``, create a stack, push a value to it, and set the stack
pointer in the state. Finally, we apply all of this constructed state to the
emulator.
