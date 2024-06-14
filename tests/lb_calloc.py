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

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.cpus.AMD64CPUState()

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath("lb_calloc.bin", base=0x1000, entry=0x1000)
state.map(code)
state.rip.value = code.entry

RAND_MAX = 0x7FFFFFFF

for i in range(int(sys.argv[1])):
    randv = random.randint(0, RAND_MAX)
    print(f"randv = {randv}")

    state.eax.value = randv
    print(state.eax.value)

    # now we can do a single micro-execution without error
    emulator = smallworld.emulators.UnicornEmulator(arch=state.arch, mode=state.mode)
    final_state = emulator.emulate(state)

    # read the result
    print(final_state.rdi)
