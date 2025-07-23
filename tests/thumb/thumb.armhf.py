import logging

import smallworld
from smallworld.state.cpus.arm import ARM

# setup logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(level=logging.DEBUG)

for arch in [
    smallworld.platforms.Architecture.ARM_V7A,
    smallworld.platforms.Architecture.ARM_V7M,
    smallworld.platforms.Architecture.ARM_V7R,
]:
    platform = smallworld.platforms.Platform(
        arch, smallworld.platforms.Byteorder.LITTLE
    )

    machine = smallworld.state.Machine()

    # create a CPU and add it to the machine
    cpu: ARM = smallworld.state.cpus.CPU.for_platform(platform)

    # create an executable and add it to the machine
    code = smallworld.state.memory.code.Executable.from_filepath(
        "thumb/thumb.armhf.bin", address=0x1000
    )
    machine.add(code)

    machine.add_exit_point(code.address + code.get_capacity())
    # set the instruction pointer to the entrypoint of our executable
    cpu.pc.set(code.address)

    machine.add(cpu)

    emulator = smallworld.emulators.UnicornEmulator(platform)

    for step in machine.step(emulator):
        pass

    cpu.r0.extract(emulator)
    print(f"{arch.name}={hex(cpu.r0.get())}")
    assert cpu.r0.get() == 6

    # test beginning execution in thumb code
    cpu.pc.set(code.address + 0x11)  # beginning of thumb code
    cpu.r0.set(0)
    machine = machine.emulate(emulator)
    cpu.r0.extract(emulator)
    print(f"{arch.name}={hex(cpu.r0.get())}")
    assert cpu.r0.get() == 4
