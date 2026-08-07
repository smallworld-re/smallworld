import logging

import claripy

import smallworld

# Set up logging
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

# Inline-encoded amd64 binary:
#   call func   (e8 fb 27 00 00)  — calls absolute 0x3800 (= code.address + 0x2800)
#   add  rax, 7 (48 83 c0 07)
#   nop         (90)                — exit point lands here
code_bytes = bytes.fromhex("e8fb270000" "4883c007" "90")
code = smallworld.state.memory.code.Executable.from_bytes(code_bytes, address=0x1000)
machine.add(code)

# Stack just lets the CALL instruction push a return address somewhere; we
# don't rely on it for control flow.
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
machine.add(stack)

cpu.rip.set(code.address)
cpu.rsp.set(stack.get_pointer())


# Function hook at code.address + 0x2800: stand in for a function that
# returns a labeled symbolic value in rax. Mirrors the pattern of a getter
# returning an arbitrary user-controlled input.
class FuncModel(smallworld.state.models.Model):
    name = "func"
    platform = platform
    abi = smallworld.platforms.ABI.NONE

    def model(self, emulator: smallworld.emulators.Emulator) -> None:
        emulator.write_register_label("rax", "x")


func = FuncModel(code.address + 0x2800)
machine.add(func)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.add_exit_point(code.address + len(code_bytes) - 1)  # the nop
final_machine = machine.emulate(emulator)

# rax should now be the hook's labeled value plus 7.
cpu = final_machine.get_cpu()
print(cpu.rax)
rax = cpu.rax.get()

x = claripy.BVS("x", 64, explicit_name=True)

# x == 5 should make rax satisfy 12, and only 12.
if not emulator.satisfiable([x == claripy.BVV(5, 64), rax == claripy.BVV(12, 64)]):
    raise ValueError("Bad Unsat: x == 5 should allow rax == 12")
if emulator.satisfiable([x == claripy.BVV(5, 64), rax == claripy.BVV(13, 64)]):
    raise ValueError("Bad Sat: x == 5 should not allow rax == 13")

# x == 100 should make rax satisfy 107.
if not emulator.satisfiable([x == claripy.BVV(100, 64), rax == claripy.BVV(107, 64)]):
    raise ValueError("Bad Unsat: x == 100 should allow rax == 107")

# With no constraint on x, rax == 0 is satisfiable (with x = -7).
if not emulator.satisfiable([rax == claripy.BVV(0, 64)]):
    raise ValueError("Bad Unsat: rax == 0 should be satisfiable for some x")
