import logging
import random
import sys

import smallworld

"""
Harness for weird logic in LB that takes output of C's `rand()` and uses it
to compute 1st argument to `calloc()`.

Input is in `rax` and is the return value of `rand()`
Output is in `rdi` and it is `nmemb` arg to calloc.
rsi is guaranteed to be 1, which is the `size` arg.

       void *calloc(size_t nmemb, size_t size);

Note: rand() returns a pseudo-random number between 0 and RAND_MAX.  For my
linux 64-bit system, RAND_MAX is 0x7fffffff.

In this harness, we micro-execute a number of times determined by argv[1].  For
each, rax is initialized with a plausible return value from `rand()`.  The
output in `rdi` is displayed.

"""

smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(verbose=True, stream=True, file=None)

# create a small world
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)
machine = smallworld.state.Machine()
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# load and map code into the state and set ip
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin").replace(".angr", "").replace(".panda", ""), 0x1000
)
machine.add(code)
cpu.rip.set(code.address)

RAND_MAX = 0x7FFFFFFF

for i in range(int(sys.argv[1])):
    randv = random.randint(0, RAND_MAX)
    print(f"randv = {randv}")

    cpu.eax.set(randv)
    print(cpu.eax.get())

    # now we can do a single micro-execution without error
    emulator = smallworld.emulators.UnicornEmulator(platform)
    final_machine = machine.emulate(emulator)
    final_cpu = final_machine.get_cpu()

    # read the result
    print(final_cpu.rdi.get())
