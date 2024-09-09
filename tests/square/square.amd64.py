import sys
import smallworld

machine = smallworld.Machine()
code = smallworld.state.Code.from_filepath("square.amd64.bin", base=0x1000, entry=0x1000)
machine.add(code)

platform = smallworld.platform.Platform(smallworld.platform.Architecture.X86_64, smallworld.platform.Byteorder.LITTLE, smallworld.platform.ABI.SYSTEMV)
cpu = smallworld.state.CPU.for_platform(platform)
cpu.rip.set(0x1000)
cpu.edi.set(int(sys.argv[-1]))
machine.add(cpu)

emulator = smallworld.emulators.UnicornEmulator(platform)
final_machine = machine.emulate(emulator)

print(final_machine.cpu.eax.get())
