.. _taint:

Dynamic Taint Tracking
======================

Emulators can optionally track *dynamic taint*: which labeled inputs flowed
into each register and memory location as code executes. This reuses the
existing state-labeling mechanism as a way to mark taint sources, and surfaces
the result on the machine returned by :py:meth:`~smallworld.state.Machine.emulate`.

Taint tracking is **disabled by default**. Enable it per-emulator with the
``taint`` flag::

    import smallworld

    platform = ...  # your platform
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)
    # ... add code, set the program counter and an exit point ...

    # Mark a taint source using the ordinary label API:
    cpu.rdi.set(0x1000)
    cpu.rdi.set_label("secret")

    emulator = smallworld.emulators.UnicornEmulator(platform, taint=True)
    final = machine.emulate(emulator)

    # Query which sources reached a location:
    print(final.get_cpu().rax.get_taint())   # e.g. {"secret"}

Model
-----

* **Sources** are state labels. Any register or memory :py:class:`~smallworld.state.Value`
  that carries a label (via :py:meth:`~smallworld.state.Value.set_label`) becomes a
  taint source named by that label when taint tracking is enabled.
* **Propagation** is byte-granular. As each instruction executes, the union of
  the taint on its data inputs is applied to its outputs. A register or memory
  byte written from untainted data becomes untainted, so common zeroing idioms
  such as ``xor eax, eax`` clear taint.
* **Sinks / queries** are :py:meth:`~smallworld.state.Value.get_taint`, which
  returns the ``set`` of source labels that reached a value on the machine
  returned by ``emulate()``. The original ``label`` is left untouched.

Address taint
-------------

By default only *data* flows are tracked: loading or storing through a tainted
pointer does not, by itself, taint the accessed data. To additionally propagate
taint through addresses (base/index registers of a memory operand), construct
the emulator with ``taint_addresses=True``::

    emulator = smallworld.emulators.UnicornEmulator(
        platform, taint=True, taint_addresses=True
    )

Support and limitations
-----------------------

* Concrete propagation is available on the Unicorn and PANDA backends via the
  shared taint engine, across every architecture with capstone instruction
  support (x86-64, i386, AArch64, ARM, MIPS). The symbolic backends (angr,
  Ghidra) already propagate labels as symbolic variables; taint there is derived
  from the resulting expressions.
* Styx does not yet support taint tracking and raises if constructed with
  ``taint=True``; use Unicorn or PANDA for ARM taint.
* Enabling taint installs the emulator's "all instructions", "all memory reads",
  and "all memory writes" hooks, so those hooks are unavailable for other use
  while taint tracking is on.
* Concrete propagation follows each instruction's register accesses (explicit
  operands plus implicit registers such as the flags register) and its memory
  accesses. Flag-mediated flows are therefore tracked, but conservatively: the
  flags register is a single taint unit, so taint can over-approximate across
  independent condition codes.
* Flows through emulated library models are not tracked: a model writes state
  through the emulator API rather than by executing instructions, so the
  propagation hooks never observe it.
* On MIPS, capstone reports no per-operand access information, so the engine
  infers the destination as the first register operand (a RISC convention).
  This is correct for typical compiler output but imprecise for instructions
  that break the convention.
