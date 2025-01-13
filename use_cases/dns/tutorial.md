# Deducing Struct Layout with Symbolic Execution

The goal of this tutorial is to determine the input format
accepted by the test program `dns.{arch}.elf`
without reading the source or resorting to manual RE.

We'll use memory labelling to lay out a hypothetical message structure
in our machine state, and then use `FieldDetectionAnalysis` to
detect inconsistencies between our hypothesis and how the code accesses the data.
By iterating this process, we will refine our hypothesis until it matches
what the code accepts.

## Setup and Motivation


You can build the example programs by running `make all` from this directory.
This requires the cross-compiler toolchains installed as part of the apt dependencies;
this analysis will work on any architecture supported by angr.

Let's test this program against the example input `examples/answer.dat`:

```
$> hexdump -C examples/answer.dat
00000000  ce 70 81 80 00 01 00 01  00 00 00 01 06 67 6f 6f  |.p...........goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01 c0 0c 00 01  |gle.com.........|
00000020  00 01 00 00 00 d2 00 04  8e fa 41 ce 00 00 29 04  |..........A...).|
00000030  c4 00 00 00 00 00 1c 00  0a 00 18 cb 6e 4b 21 27  |............nK!'|
00000040  ca a2 eb 8f fc 9f 64 67  85 5f 7f cf 3e 38 e4 56  |......dg._..>8.V|
00000050  80 72 f9                                          |.r.|
00000053

$> ./bin/dns.amd64.elf examples/answer.dat
DNS Message:
        TID:          ce70
        FLAGS:        0120
        # Questions:  1
        # Answers:    0
        # Auth. Rs:   0
        # Extra Rs:   1
Question:
        Name:         google.com
        Type:         1
        Class:        1
Record:
        Name:
        Type:         41
        Class:        1232
```

If it's not apparent yet, this program parses basic DNS messages.
However, the exact structure accepted by the parser isn't obvious.
I could decompile the binary and try to elicit the structure from there,
but I don't feel like reading.  Let's try something different.

## Harnessing the Parser

For sanity's sake, let's assume we know that the parser is implemented in `parse_dns_msg()`,
and that we roughly know its arguments from `main()`:

- **Arg 1:** `uint8_t *` pointing to an input buffer
- **Arg 2:** `size_t` holding its size
- **Arg 3:** `size_t *` pointing to a value starting at zero
- **Arg 4:** `struct *` pointing to an unknown struct

Our goal for this exercise is to figure out the structure of argument 1,
which we'll call `buf`, and argument 4, which we'll call `msg`.


First, we set up some smallworld boilerplate.
This configures logging, as well as the hinter
that will let us see the output from our analysis. 

```
import logging
import pathlib

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

log = logging.getLogger("smallworld")
```


Next, we create the basic machine state,
load our ELF file into a smallworld state object,
and add the code to the machine.

Since we don't expect a specific platform,
we can use the platform definition parsed out of the ELF headers.

Also, since this is the only ELF we're loading,
we can use its notion of program bounds
to define which memory the analysis can execute.

```
# Create a machine
machine = smallworld.state.Machine()

# Load the code
filepath = pathlib.Path(__file__).parent / "bin" / "dns.amd64.elf"
with open(filepath, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, 0x40000)
    machine.add(code)

# Apply the code's bounds to the machine
for bound in code.bounds:
    machine.add_bound(bound[0], bound[1])

# Use the ELF's notion of the platform
platform = code.platform
```

Now, our ELF needs a CPU to run against, and a stack for local variables.
Once we have the CPU, we can set our initial program counter.
We want to start at `parse_dns_message()`, rather than
the entrypoint for the entire program.
Fortunately, I left debug symbols in the file,
so we can recover its address from the ELF metadata.

```
# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Use lief to find the address of parse_dns_message
sym = code.get_symbol_value("parse_dns_message")
cpu.rip.set(sym)

# Add a blank stack
stack = smallworld.state.memory.stack.Stack.for_platform(
    platform, 0x7FFFFFFFC000, 0x4000
)
machine.add(stack)

# Add a default, bogus return address
stack.push_integer(0x01010101, 8, None)

# Configure the stack pointer
sp = stack.get_pointer()
cpu.rsp.set(sp)
```

Now that we have the program set up, we can start to model the inputs to `parse_dns_message()`.
We know we need a message struct, a memory buffer, and a `size_t`
that are all passed by reference.

For ease of modelling, let's just allocate them all as globals.

To start, we'll allocate `buf` and `msg` as blank swaths of memory.
As we learn more about their internal structure from the analysis,
we will come back and refine this part of our harness.

```
# Configure somewhere for arguments to live
gdata = smallworld.state.memory.Memory(0x6000, 0x1000)
machine.add(gdata)

# DNS message struct
# Sort of cheating that I know how big it is.
#
# **** NOTE ****
# For now, this is treated as one big empty space.
# We will fill it with fields later
gdata[0] = smallworld.state.EmptyValue(48, None, "msg")

# Input buffer
#
# **** NOTE ****
# For now, this is treated as one big empty space.
# We will fill it with fields later
gdata[48] = smallworld.state.EmptyValue(512, None, "buf")

# Offset into buffer
gdata[560] = smallworld.state.IntegerValue(0, 8, "off", False)
```

Next, we use what we know about the function signature to assign values to registers.
We know that the first arg points to `buf`, the second is the size of `buf`,
the third points to `off`, and the fourth points to `msg`.

```
# Configure arguments

# arg 0: pointer to buf
cpu.rdi.set(gdata.address + 48)
cpu.rdi.set_label("PTR buf")

# arg 1: buffer capacity
cpu.rsi.set(512)
cpu.rsi.set_label("cap")

# arg 2: pointer to off
cpu.rdx.set(gdata.address + 560)
cpu.rdx.set_label("PTR off")

# arg 3: pointer to msg
cpu.rcx.set(gdata.address)
cpu.rcx.set_label("PTR msg")
```

**Step 6:** Analyze!

```
machine.analyze(FieldDetectionAnalysis(platform))
```


# The 
