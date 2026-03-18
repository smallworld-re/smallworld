import logging
import pathlib
import sys
import warnings

import smallworld

warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    module=r"google\.protobuf\.runtime_version",
)

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

log = logging.getLogger("smallworld")

# Create a machine
machine = smallworld.state.Machine()

# Load the code
# Firmware from https://github.com/PAGalaxyLab/vxhunter/tree/master/example_firmware
default_path = pathlib.Path(__file__).parent / "bin" / "image_vx5_ppc_big_endian.bin"
filepath = sys.argv[1] if len(sys.argv) > 1 else default_path

with open(filepath, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_vxworks(f)
    machine.add(code)

# Apply the code's bounds to the machine
for bound in code.bounds:
    machine.add_bound(bound[0], bound[1])

# Use the image's notion of the platform
platform = code.platform

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)

# set entry point
cpu.pc.set(code.get_symbol_value("show_cpm"))

machine.add(cpu)

# Add a blank stack
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x7FFFC000, 0x4000)
machine.add(stack)

stack.push_integer(0x01010101, 8, None)

# Configure the stack pointer
sp = stack.get_pointer()
cpu.r1.set(sp)

# Emulate
# emulator = smallworld.emulators.AngrEmulator(platform)
# emulator = smallworld.emulators.GhidraEmulator(platform)
emulator = smallworld.emulators.UnicornEmulator(platform)
# emulator = smallworld.emulators.PandaEmulator(platform)

if isinstance(emulator, smallworld.emulators.AngrEmulator):
    emulator.enable_linear()


printf_model = smallworld.state.models.Model.lookup(
    "printf",
    platform,
    smallworld.platforms.ABI.SYSTEMV,
    code.get_symbol_value("printf"),
)
machine.add(printf_model)
printf_model.allow_imprecise = True

# Memory accessed during print statements
gdata = smallworld.state.memory.Memory(0x4800000, 0x1000)
machine.add(gdata)
# Modify specific values read, if desired, otherwise zero
gdata[0x99E] = smallworld.state.IntegerValue(
    1, 2, "reg count", code.platform.byteorder, False
)

# Specify where the emulator should exit
emulator.add_exit_point(code.get_function_end("show_cpm"))

machine.apply(emulator)
try:
    emulator.run()
except smallworld.exceptions.EmulationStop:
    pass

if isinstance(emulator, smallworld.emulators.AngrEmulator):
    for state in emulator.mgr.active:
        print(state)
        print(state.scratch.guard)

print("\n --------------------END OF HARNESS--------------------")
