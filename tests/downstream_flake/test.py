import logging
import sys
from importlib import metadata

import colorama

import smallworld

if len(sys.argv) > 2:
    print("Provide at most one numeric argument")
    sys.exit(1)

input_arg = 100
if len(sys.argv) == 2:
    try:
        input_arg = int(sys.argv[1])
    except ValueError:
        print("Provide a numeric argument")
        sys.exit(1)

# Set up logging
smallworld.logging.setup_logging(level=logging.INFO)
colorama.init(autoreset=True)
smallworld_version = metadata.version("smallworld-re")
print(colorama.Fore.GREEN + f"mkPython imports ok (smallworld-re {smallworld_version})")

# Define the platform. We support many platforms, but this is going to use a 32-bit PowerPC with bigendian byte order.
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.POWERPC32, smallworld.platforms.Byteorder.BIG
)

# Create a machine to hold all of our state
machine = smallworld.state.Machine()

# Create a CPU for our platform and add it to the machine
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the machine. These are just some raw bytes, but you can load from a file too. We also support loading from ELF and PE files. This code is a compares r3 against 100 and sets it to 1 if it's 100 and 0 otherwise.
raw_bytes = b"\x2c\x03\x00\x64\x40\x82\x00\x0c\x38\x60\x00\x01\x48\x00\x00\x08\x38\x60\x00\x00\x60\x00\x00\x00"
code = smallworld.state.memory.code.Executable.from_bytes(raw_bytes, address=0x1000)
machine.add(code)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# Initialize argument registers
cpu.r3.set(input_arg)

# We need to establish when we want to stop
machine.add_exit_point(cpu.pc.get() + code.get_capacity())


def assert_expected(name: str, result: int) -> None:
    if (input_arg == 100) and (result != 1):
        print(f"{name} produced r3={result}, expected 1")
        sys.exit(1)
    if (input_arg != 100) and (result != 0):
        print(f"{name} produced r3={result}, expected 0")
        sys.exit(1)


def check_emulator(name: str, emulator) -> None:
    print(f"\nTesting {name}\n")
    emulated_machine = machine.emulate(emulator)
    result = emulated_machine.get_cpu().r3.get()
    assert_expected(name, result)


# This mkPython downstream test should cover the emulator backends exposed by
# the helper: Panda, Ghidra, Unicorn, and angr when the interpreter supports it.

check_emulator("panda", smallworld.emulators.PandaEmulator(platform))
check_emulator("ghidra", smallworld.emulators.GhidraEmulator(platform))
check_emulator("unicorn", smallworld.emulators.UnicornEmulator(platform))

angr = smallworld.emulators.AngrEmulator(platform)
angr.enable_linear()
check_emulator("angr", angr)
