import logging
import typing

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
with open(
    __file__.replace(".py", ".elf")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", ""),
    "rb",
) as f:
    code = smallworld.state.memory.code.Executable.from_elf(
        f,
        platform=platform,
        address=0x10000,
    )
machine.add(code)

# Set the instruction pointer to the address of "main"
entrypoint = code.get_symbol_value("main")
cpu.pc.set(entrypoint)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Push a return address
stack.push_integer(0x00000000, 8, None)

# Configure the stack
cpu.rsp.set(stack.get_pointer())

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)

# Map the fake register
emulator.map_memory(0xC001, 2)


# General read hook
def mem_reads_hook(
    emulator: smallworld.emulators.Emulator, addr: int, size: int, data: bytes
) -> typing.Optional[bytes]:
    print(f"Read {size} bytes from {hex(addr)}")
    return None


emulator.hook_memory_reads(mem_reads_hook)


# General write hook
def mem_writes_hook(
    emulator: smallworld.emulators.Emulator, addr: int, size: int, data: bytes
) -> None:
    print(f"Write {size} bytes to {hex(addr)}")


emulator.hook_memory_writes(mem_writes_hook)


# Specific read hook
def mem_read_hook(
    emulator: smallworld.emulators.Emulator, addr: int, size: int, data: bytes
) -> typing.Optional[bytes]:
    print(f"Read {size} bytes from {hex(addr)}: {data!r}")
    if emulator.platform.byteorder == smallworld.platforms.Byteorder.BIG:
        data = 0xD00D.to_bytes(4, "big")
    else:
        data = 0xD00D.to_bytes(4, "little")

    return data


emulator.hook_memory_read(0xC001, 0xC001 + 8, mem_read_hook)

emulator.add_exit_point(cpu.rip.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(hex(cpu.eax.get()))
