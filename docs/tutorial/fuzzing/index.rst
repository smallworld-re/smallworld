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

The source for this example is in the SmallWorld repo in ``docs/tutorial/fuzzing`` as
``fuzz.armel.s`` and ``fuzz.armel.bin`` (a copy of
``tests/fuzz/fuzz.armel.bin``).

Building Our Harness
--------------------

The complete standalone Unicorn harness can be found in the SmallWorld repo in
``docs/tutorial/fuzzing/unicorn_fuzz.py``. We'll walk through it in four pieces. First we
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
``UnicornEmulator`` and the ``StyxEmulator`` (with a few changes covered below).

Running With AFL++
------------------
Run the standalone script under `AFL++`_ directly. The example below assumes:
  1. You have already have AFL++ setup (you can use are nix devshell if you want)
  2. ``cd``-ed into ``docs/tutorial/fuzzing`` so the script can find ``fuzz.armel.bin``
and the ``inputs/`` seed directory:
  3. Created a folder ``outputs/``
  
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
backend. The full Styx variant lives at
``docs/tutorial/fuzzing/styx_fuzz.py``. Because ``machine.fuzz_with_file``
dispatches based on the emulator type and the input callback receives the
SmallWorld ``emulator`` instance (not a backend-specific handle), the input
callback is byte-for-byte identical to the Unicorn one. The first change
is just swapping the emulator class:

.. literalinclude:: styx_fuzz.py
  :language: python
  :lines: 67-69

.. _Styx: https://github.com/styx-emulator/styx-emulator

Modelling the bug explicitly
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Unicorn harness gets crash detection "for free": writing to ``0x12345678``
hits unmapped memory and Unicorn faults. Styx's CycloneV target, on the
other hand, emulates an actual SoC — it pre-maps the full 4 GiB address
space so every physical address has memory backing it. The binary's intended
out-of-bounds write therefore succeeds silently, execution falls through
to the exit point, and AFL never sees a crash. Therefore bug detection
has to be modelled explicitly. The Styx harness does that with a
``hook_memory_write`` over the obviously out-of-bounds range:

.. literalinclude:: styx_fuzz.py
  :language: python
  :lines: 71-82

The hook fires from inside Styx whenever the guest writes to any address at
or above ``0x10000`` (well outside our intentional heap at ``0x2000–0x6000``
and code at ``0x1000–0x105c``). It just sets a Python flag — the write
itself still proceeds harmlessly into CycloneV's DDR3.

To turn that flag into something AFL records as a crash, the harness clears
it at the top of each iteration, then supplies a ``crash_callback`` that
reports the flag's state back to the styxafl bridge:

.. literalinclude:: styx_fuzz.py
  :language: python
  :lines: 85-111

Passing ``always_validate=True`` makes the bridge invoke ``validate_crash``
on every iteration (not just when the emulator itself reports a fatal
exit). When the callback returns ``True``, the bridge raises ``SIGABRT``
from the child process so AFL records the input as a crash.

Running with AFL++
~~~~~~~~~~~~~~~~~~

Once the harness is in place, the Styx variant runs under `AFL++`_ exactly
the same way as the Unicorn variant — only the script name changes:

.. code-block:: bash

   afl-fuzz -t 10000 -U -m none -i inputs -o outputs -- python3 styx_fuzz.py @@

Next Steps
----------
If you are interested in a more in depth tutorial on using SmallWorld for
vulnerability research (including fuzzing), then checkout our in depth
tutorial on using SmallWorld to analyize an RTOS found in the repo under
`use_cases/rtos_demo`.
