.. _initializers:

Initializers
------------

Initializers are a simple uniform way to set values for ``state`` in
SmallWorld. With it, one can set values that are

* random values, with or without seeds, printable or not
* zeroes

The top-level SmallWorld ``state`` representing, e.g., all the registers,
stack, and heap memory for an x86-64 machine, has an ``initialize`` method
which is passed an argument which is an initilizer which will be used to
initialize all parts of the state.  Thus, the following code::

  import smallworld
  state = smallworld.cpus.AMD64CPUState()
  printable = smallworld.initializers.RandomPrintableInitializer(seed=1234)
  state.initialize(printable)

will initialize all registers and memory in the x86-64 state with random bytes
all of which are printable to the console. The seed for the pseudo-random
number generator is 1234.
