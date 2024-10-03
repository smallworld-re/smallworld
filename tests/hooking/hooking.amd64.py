import smallworld
import logging
import copy

smallworld.logging.setup_logging(level=logging.INFO) #DEBUG) 

machine = smallworld.state.Machine()
code = smallworld.state.memory.code.Executable.from_filepath("hooking.amd64.bin", address=0x1000)
machine.add(code)

platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

cpu = smallworld.state.cpus.CPU.for_platform(platform)
cpu.rip.set(0x1000)

stack = smallworld.state.memory.Memory(address=0xFFFF0000, size=0x1000)
stack.set_content(b"\x00" * 0x1000)
cpu.rsp.set(stack.address)

gets = smallworld.state.models.model.Model.lookup("gets", platform, smallworld.platforms.ABI.SYSTEMV, 0x3800) 

def puts_model(emulator):
    s = emulator.read_register("rdi")
    read = emulator.read_memory(s, 0x100)
    read = read[: read.index(b"\x00")].decode("utf-8")
    print(read)

puts = smallworld.state.models.ImplementedModel(0x3808, puts_model)

machine.add(cpu)
machine.add(code)
machine.add(stack)
machine.add(gets)
machine.add(puts)

emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + 20)

machine.apply(emulator)

while True:
    try:
        emulator.step()
        #machine.emulate(emulator)
    except smallworld.exceptions.EmulationBounds:
        print("emulation complete; encountered exit point or went out of bounds")
        break
    except Exception as e:
        print(f"emulation ended; raised exception {e}")
        break

