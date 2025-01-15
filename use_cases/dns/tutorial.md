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

At long last, we're reading to actually run our analysis.

```
machine.analyze(FieldDetectionAnalysis(platform))
```

The code we just wrote can be found in `dns_0.py`

# First Results

Running `dns_0.py` produces the following hint:

```
[*] Partial write to known field
[*]   pc:         0x41e73
[*]   address:    0x6010
[*]   size:       8
[*]   access:     write
[*]   guards:
[*]   field:      msg[16:24]
[*]   expr:       <BV64 0x0>
```

The code at `0x41e73` tried to write zero to byte 16 of `msg`.
Since we defined `msg` as 512 homogenous bytes, it didn't expect to see a field here.

We can redefine msg as the following

```
gdata[0] = smallworld.state.EmptyValue(16, None, "msg.unk-0x0")
gdata[16] = smallworld.state.EmptyValue(8, None, "msg.a")
gdata[24] = smallworld.state.EmptyValue(24, None, "msg.unk-0x18")
```

We're not sure what `msg.a` is, but we know it's very likely a field.
We're on our way!

Running our updated script gives a very similar hint to the first:

```
[*] Partial write to known field
[*]   pc:         0x41e7f
[*]   address:    0x6018
[*]   size:       8
[*]   access:     write
[*]   guards:
[*]   field:      msg.unk.0x18[0:8]
[*]   expr:       <BV64 0x0>
```

In fact, four iterations tell us the same thing;
the program writes zero to four 8-byte fields right next to each other:

```
gdata[0] = smallworld.state.EmptyValue(16, None, "msg.unk-0x0")
gdata[16] = smallworld.state.EmptyValue(8, None, "msg.a")
gdata[24] = smallworld.state.EmptyValue(8, None, "msg.b")
gdata[32] = smallworld.state.EmptyValue(8, None, "msg.c")
gdata[40] = smallworld.state.EmptyValue(8, None, "msg.d")
```

Some more iterations, and we start decoding both `buf` and `msg.unk-0x0`,
which I've decided to call `msg.hdr`, since I suspect it's the
part of the struct representing the DNS header:

```
gdata[0] = smallworld.state.EmptyValue(2, None, "msg.hdr.a")
gdata[2] = smallworld.state.EmptyValue(2, None, "msg.hdr.b")
gdata[4] = smallworld.state.EmptyValue(2, None, "msg.hdr.c")
gdata[6] = smallworld.state.EmptyValue(2, None, "msg.hdr.d")
gdata[8] = smallworld.state.EmptyValue(2, None, "msg.hdr.e")
gdata[10] = smallworld.state.EmptyValue(2, None, "msg.hdr.f")
# NOTE: 4 bytes of padding here; never referenced
gdata[16] = smallworld.state.EmptyValue(8, None, "msg.a")
gdata[24] = smallworld.state.EmptyValue(8, None, "msg.b")
gdata[32] = smallworld.state.EmptyValue(8, None, "msg.c")
gdata[40] = smallworld.state.EmptyValue(8, None, "msg.d")
# Input buffer
gdata[48] = smallworld.state.EmptyValue(2, None, "buf.a")
gdata[50] = smallworld.state.EmptyValue(2, None, "buf.b")
gdata[52] = smallworld.state.EmptyValue(2, None, "buf.c")
gdata[54] = smallworld.state.EmptyValue(2, None, "buf.d")
gdata[56] = smallworld.state.EmptyValue(2, None, "buf.e")
gdata[58] = smallworld.state.EmptyValue(2, None, "buf.f")
gdata[60] = smallworld.state.EmptyValue(500, None, "buf")
```

You've now made it to the code contained in `dns_1.py`.

# Adding malloc

If we run `dns_1.py`, it terminates with the following message:

```
[!] State at 0x1076 is out of bounds
```

We loaded our ELF at 0x40000; something's way off.
The last successful read was at 0x41ed2; let's look at what's in the code near there:

```
$> objdump -d -R ./bin/dns.amd64.elf
...
    1ed2:       0f b7 40 04             movzwl 0x4(%rax),%eax
    1ed6:       48 69 f8 08 01 00 00    imul   $0x108,%rax,%rdi
    1edd:       e8 8e f1 ff ff          call   1070 <malloc@plt>
...
```

Ah, an external call.  That would do it.

Now, we could just stub out `malloc()` and be done with it,
but I want to know what's inside the heap-allocated buffers, too.
Luckily, `FieldDetectionAnalysis` comes with a malloc model.
Let's update our harness:

```
# Configure malloc and free models
malloc = MallocModel(
    0x10000, heap, platform, analysis.mem_read_hook, analysis.mem_write_hook
)
machine.add(malloc)
machine.add_bound(malloc._address, malloc._address + 16)
```

This will invoke a function hook mimicking `malloc()` if we call address 0x10000.
If we were in a raw binary, we'd have to do some manual patching
to tell it where we put `malloc()`, but this is an ELF.
Let's use the relocation entries to our advantage:

```
# Apply relocations to malloc
code.update_symbol_value("malloc", malloc._address)
```

This brings us to `dns_2.py`.

Running our script now gives us this error:

```
[*] Capacity did not collapse to one value
[*] The following fields are lengths:
[*]    msg.hdr.c_27_16
[*] Concretize them to continue analysis
```

The analysis figured out that `msg.hdr.c`, loaded from `buf.c`,
is used to determine the numbe of items allocated in our buffer.
Unfortunately, the underlying analysis can't reason over
an array of undefined size; we'll need to assign a concrete value to `msg.hdr.c`
to continue:

```
gdata[52] = smallworld.state.BytesValue(b"\x00\x01", "buf.msg.hdr.c")
```

We now see the following output from the malloc:

```
[!] malloc: Alloc'd 264 bytes at 0x20010
[+] Storing 8 bytes at 0x20008
[!]   Length field msg.hdr.c not known
[+] 0x41ee6: WRITING 0x6010 - 0x6018 (msg.a)
[+]   <BV64 0x20010>
```

Let's take this one line at a time:

`malloc: Alloc'd 264 bytes at 0x20010`:  We assigned 0x1 to the length, so we know the struct is 264 bytes (the `malloc()` model would warn us if the length computation was more complex than "variable * magnitude".

`  Length field msg.hdr.c not known`: We haven't told the `malloc()` model that it should track structs allocated using `msg.hdr.c`, or what they should look like.

`0x41ee6: WRITING 0x6010 - 0x6018 (msg.a)`: The pointer to our new heap array is stored in `msg.a`, making `msg.hdr.c` the length of `msg.a`.

Let's update our harness:

```
gdata[4] = smallworld.state.EmptyValue(2, None, "msg.hdr.a.len")
...
gdata[52] = smallworld.state.BytesValue(b"\x00\x01", "buf.msg.hdr.msg.a.len")
```


