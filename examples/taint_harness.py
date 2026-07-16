"""Dynamic taint tracking example.

Marks a register as a taint source with the ordinary label API, emulates a
short amd64 snippet with taint tracking enabled, and prints which sources
reached each output. Taint tracking is disabled by default; it is turned on
here with ``taint=True``.
"""

import logging

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)

platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# A tiny program:
#   mov rax, rdi     ; rax <- rdi
#   add rax, rsi     ; rax <- rdi + rsi
#   xor rcx, rcx     ; clears rcx
code_bytes = bytes.fromhex("4889f8" "4801f0" "4831c9")

machine = smallworld.state.Machine()
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

code = smallworld.state.memory.code.Executable.from_bytes(code_bytes, address=0x1000)
machine.add(code)
cpu.rip.set(code.address)
machine.add_exit_point(code.address + code.get_capacity())

# Two taint sources and one register that starts tainted but gets cleared.
cpu.rdi.set(0x11)
cpu.rdi.set_label("input_a")
cpu.rsi.set(0x22)
cpu.rsi.set_label("input_b")
cpu.rcx.set(0x33)
cpu.rcx.set_label("scratch")

emulator = smallworld.emulators.UnicornEmulator(platform, taint=True)
final = machine.emulate(emulator)

fcpu = final.get_cpu()
print(f"rax taint = {sorted(fcpu.rax.get_taint())}")  # {'input_a', 'input_b'}
print(f"rcx taint = {sorted(fcpu.rcx.get_taint())}")  # {} -- cleared by xor
