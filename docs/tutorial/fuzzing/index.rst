.. _fuzzing:

Fuzzing
=======

Introduction
------------
In this tutorial you will be guided through building a simple fuzzing harness
and fuzzing it with `AFL++`_. It assumes you are already familiar with building
a SmallWorld harness and with `AFL++`_. For this tutorial we will be using a
very simple 32-bit ARM (armel) binary that reads four bytes (which we're going
to pretend is a size) and exits if they are 11 or less, then reads the next
four bytes and compares them one-by-one to the values 98, 97, 100, and 33
exiting if they are not equal. If it makes it through all of the compares it
crashes by writing to an unmapped address.

.. literalinclude:: fuzz.armel.s
  :language: NASM

.. _AFL++: https://aflplus.plus/

The source for this example is checked in next to this tutorial as
``fuzz.armel.s`` and ``fuzz.armel.bin`` (a copy of
``tests/fuzz/fuzz.armel.bin``). The assembly was produced by GCC; you can
regenerate the binary from source with ``arm-linux-gnueabi-as fuzz.armel.s
-o fuzz.armel.o && arm-linux-gnueabi-objcopy -O binary -j .text
fuzz.armel.o fuzz.armel.bin``.

Building Our Harness
--------------------

The complete standalone Unicorn harness lives next to this page as
``unicorn_fuzz.py``. We'll walk through it in four pieces. First we
initialise the platform, machine, CPU, and load the raw code at ``0x1000``:

.. literalinclude:: unicorn_fuzz.py
  :language: python
  :lines: 17-29

Next we need somewhere for our input to live. We use a bump-allocated heap and
seed it with an example 12-byte input (the four-byte little-endian size
followed by ``"goodgoodgood"``):

.. literalinclude:: unicorn_fuzz.py
  :language: python
  :lines: 31-40

Then we set the program counter to the entry of ``vuln()`` at ``0x1000`` and
point ``r0`` at the start of the heap-allocated buffer, then add everything to
the machine:

.. literalinclude:: unicorn_fuzz.py
  :language: python
  :lines: 42-48

Now for the part where most of the work happens. `AFL++`_ is going to generate
an input and hand it to our harness. However, that input is just a series of
bytes — we have to apply it to the machine ourselves. We do that with a
callback that loosely follows the shape `AFL++`_ uses for `Unicorn mode`_,
unified across SmallWorld's two fuzzing backends:
``(emulator, input_bytes, persistent_round, data)``. ``emulator`` is the
SmallWorld emulator instance — call methods like
``emulator.write_memory_content(addr, bytes)`` to apply the input.
``input_bytes`` is the input `AFL++`_ generated as a Python ``bytes``. Return
``False`` to skip an input that won't work for your case, or ``None`` to let
`AFL++`_ continue. Finally we build the emulator, install an exit point at the
``nop`` at the end of ``vuln()``, and hand control to ``machine.fuzz_with_file``:

.. literalinclude:: unicorn_fuzz.py
  :language: python
  :lines: 51-67

.. _Unicorn emulator object: https://www.unicorn-engine.org/docs/tutorial.html
.. _Unicorn mode: https://github.com/AFLplusplus/AFLplusplus/blob/stable/unicorn_mode/README.md

That is the whole harness. SmallWorld supports AFL-driven fuzzing on the
``UnicornEmulator`` and the ``StyxEmulator`` (covered below); the only
difference from a normal SmallWorld run is the call to
``machine.fuzz_with_file`` at the bottom, which detects the emulator type and
routes through ``unicornafl`` or ``styxafl`` automatically.

Running With AFL++
------------------
Run the standalone script under `AFL++`_ directly. The example below assumes
you have already entered the repository dev shell with ``nix develop`` and
``cd``-ed into this tutorial folder so the script can find ``fuzz.armel.bin``
and the ``inputs/`` seed directory:

.. code-block:: bash

   afl-fuzz -t 10000 -U -m none -i inputs -o outputs -- python3 unicorn_fuzz.py @@


You should see a TUI that looks like this:

.. literalinclude:: afl_output.txt
  :language: none

See the `AFL++`_ documentation for a more complete listing of the arguments
and options.

Breakdown of an Input
---------------------
Now, lets look at an input the crashed our program. Using ``xxd`` we have the
following::

  00000000: ff7f 0000 6261 6421                      ....bad!

As you can see, the first four bytes ``ff7f 0000`` are an integer greater
than 11. Then we have the bytes ``0x62`` (98), ``0x61`` (97), ``0x64`` (100),
and ``0x21`` (33) which spells ``bad!`` in ASCII. Note that this input
matches what was required as discussed in the introduction of this tutorial.

Fuzzing with the Styx Backend
-----------------------------

SmallWorld can also drive fuzzing through the `Styx`_ firmware-emulator
backend. The Styx variant is checked in alongside this page as
``styx_fuzz.py``. Because ``machine.fuzz_with_file`` dispatches based on the
emulator type and the input callback receives the SmallWorld ``emulator``
instance (not a backend-specific handle), the only line that has to change
between the two harnesses is the emulator construction itself:

.. literalinclude:: styx_fuzz.py
  :language: python
  :lines: 69-75

A couple of things to keep in mind:

1. **Architecture coverage.** Styx targets specific firmware platforms and
   currently exposes 32-bit ARM only. ``StyxEmulator`` accepts ``armhf``
   (mapped to a Cortex-A9 ``CycloneV`` target) and ``armel`` (Cortex-A9 for
   ``ARM_V5T``, Cortex-M4 ``Kinetis21`` for ``ARM_V6M``); constructing one
   with any other architecture raises ``ConfigurationError``. This tutorial
   uses ``ARM_V5T`` (armel); ``ARM_V7A`` (armhf) works the same way.

2. **Lazy build.** The Styx backend defers the underlying ``Processor``
   build until the first ``run()`` / ``step()`` call, so register/memory
   configuration done by ``machine.apply`` is replayed automatically when
   emulation begins. ``fuzz_with_file`` triggers the build for you before
   handing the ``Processor`` to ``styxafl``.

3. **Helper module.** :func:`smallworld.helpers.fuzz` accepts
   ``engine="styx"`` (or ``"unicorn"``) if you'd rather skip the explicit
   ``Machine`` construction.

.. _Styx: https://github.com/styx-emulator/styx-emulator

The full ``styx_fuzz.py`` is checked in next to this page.

Running with AFL++
~~~~~~~~~~~~~~~~~~

Once the harness is in place, the Styx variant runs under `AFL++`_ exactly
the same way as the Unicorn variant — only the script name changes:

.. code-block:: bash

   afl-fuzz -t 10000 -U -m none -i inputs -o outputs -- python3 styx_fuzz.py @@

The ``styxafl`` bridge also has a fallback mode: when ``__AFL_SHM_ID`` is
not set (i.e. you're running without ``afl-fuzz`` wrapping the harness),
it runs a single iteration of your ``input_callback`` against the file
you point it at and then exits. This is what the integration test
``fuzz_tutorial:styx:armel`` exercises — a useful smoke check for harness
correctness before plugging it into a real fuzzing campaign.

Known limitations of the Styx fuzz path:

* Styx has no 64-bit ARM and no x86_64 target. ``aarch64`` harnesses must
  continue using ``UnicornEmulator``.
* SmallWorld function hooks installed via ``QFunctionHookable`` (e.g. the
  ``hooking`` test family's ``gets``/``puts`` models) don't yet round-trip
  cleanly through Styx — the body-skip-via-PC-redirect heuristic doesn't
  match Styx's hook semantics. Stick to bare-metal harnesses for now.
* MMIO-dependent scenarios (``dma``) won't work out of the box because the
  CycloneV target's memory map doesn't include the addresses those tests
  use.

Next Steps
----------
If you are interested in a more in depth tutorial on using SmallWorld for
vulnerability research (including fuzzing), then checkout our in depth
tutorial on using SmallWorld to analyize an RTOS found in the repo under
`use_cases/rtos_demo`.
