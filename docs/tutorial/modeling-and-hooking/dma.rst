Memory Hooking
==============

In this tutorial, you will be guided through the steps
to hook memory accesses, and model a basic DMA device.

Consider the example ``tests/dma/dma.amd64.s``:

.. literalinclude:: ../../../tests/dma/dma.amd64.s
    :language: NASM

The code here is very obtuse; it writes two values
at fixed addresses, and then reads back a value from another address.
None of these addresses are reasonable, as far as we know.

This is an example of Direct Memory Access,
where a piece of memory isn't backed by RAM,
but rather serves as an interface to a hardware peripheral or a software module.

In this case, our device is a hardware integer divisor,
and the addresses mean the following:

- ``0x50014000``: Numerator
- ``0x50014008``: Denominator
- ``0x50014010``: Quotient
- ``0x50014018``: Modulus (unused in this test).

Loading the denominator triggers the device
to update the values presented in the quotient and modulus registers.

(This may seem contrived, but it's actually common on arm32 boards,
since the ISA lacks an integer division instruction.)

To harness this piece of code, we need to do the following:

- Assign argument values to ``rdi`` (numerator) and ``rsi`` (denominator).
- Hook on reads and writes in the range ``[ 0x50014000 - 0x50014020 )``

To do this, we need a subclass of ``MemoryMappedModel``,
which will mimic the behavior described above.

Let's define that class.  To start, we will need to set up a little state.
We need to store the current state of the divisor device in our class,
and it would be nice to remember where each of the registers is
so we don't need to compute it every time:

.. code-block:: Python

    class HDivModel(smallworld.state.models.mmio.MemoryMappedModel):
        def __init__(self, address: int, nbytes: int):
            # This model starts at address, and extends for 4 nbytes-sized registers.
            super().__init__(address, nbytes * 4)
            self.reg_size = nbytes
            # Pre-compute the addresses of our registers
            self.num_addr = address
            self.den_addr = address + nbytes
            self.quo_addr = address + nbytes * 2
            self.rem_addr = address + nbytes * 3
            self.end_addr = address + nbytes * 4
    
            # Save the values of the registers as our denominators.
            self.numerator = 0
            self.denominator = 0
            self.quotient = 0
            self.remainder = 0


Next, we need to define the ``on_read`` and ``on_write`` handlers for our class.

let's consider the writes we need to hook.
We need to detect any writes into the ``nbytes`` bytes 
at the numerator and denominator registers.

We need to be careful, and handle partial writes to the registers.
Some ISAs won't be able to write large integers all at once,
and some emulators - particularly Unicorn - will break up
larger writes into multiple events.  Our ``on_write`` function should look something like this:

.. code-block:: Python
    
    def on_write(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        if addr >= self.num_addr and addr < self.den_addr:
            start = addr - self.num_addr
            end = start + size
            num_bytes = bytearray(self.numerator.to_bytes(self.reg_size, "little"))
            num_bytes[start:end] = value
            self.numerator = int.from_bytes(num_bytes, "little")
        elif addr >= self.den_addr and addr < self.quo_addr:
            start = addr - self.den_addr
            end = start + size
            den_bytes = bytearray(self.denominator.to_bytes(self.reg_size, "little"))
            den_bytes[start:end] = value
            self.denominator = int.from_bytes(den_bytes, "little")

            if self.denominator != 0:
                # TODO: I have no idea how the real thing handles DIV0
                self.quotient = self.numerator // self.denominator
                self.remainder = self.numerator % self.denominator
        else:
            raise smallworld.exceptions.AnalysisError(
                "Unexpected write to MMIO register {hex(addr)}"
            )

This example is based off a real device that didn't provide a full spec for this unit,
so some behaviors, like an explicit write of zero, are guesswork.

Now, let's consider hooking reads.
We need to handle reads to the quotient and modulus registers,
with the same concerns about partial reads as we had about partial writes.
Our ``on_read`` function should look something like this:


.. code-block:: Python

    def on_read(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, content: bytes
    ) -> bytes:
        if addr >= self.quo_addr and addr < self.rem_addr:
            self.numerator = 0
            self.denominator = 0
            start = addr - self.quo_addr
            end = start + size
            return self.quotient.to_bytes(self.reg_size, "little")[start:end]
        elif addr >= self.rem_addr and addr < self.end_addr:
            self.numerator = 0
            self.denominator = 0
            start = addr - self.rem_addr
            end = start + size
            return self.remainder.to_bytes(self.reg_size, "little")[start:end]
        else:
            raise smallworld.exceptions.AnalysisError(
                "Unexpected read from MMIO register {hex(addr)}"
            )

Finally, we need to initialize our model, and add it to the harness.
It's pretty clear from the assembly that our device
starts at ``0x50014000``, and that the DMA registers are eight bytes each.

.. code-block:: Python

    hdiv = HDivModel(0x50014000, 8)
    machine.add(hdiv)

All together, this harness can be found in ``tests/dma/dma.amd64.py``:

.. literalinclude:: ../../../tests/dma/dma.amd64.py
    :language: Python

If this works, we can feed it two numbers, and it should output the quotient.
Let's try it.

.. command-output:: python3 dma.amd64.py 10 2
    :cwd: ../../../tests/dma

Ten divided by two is in fact five,
so we have successfully harnessed ``dma.amd64.bin``.
