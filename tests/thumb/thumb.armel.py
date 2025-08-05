import logging

import smallworld
from smallworld.state.cpus.arm import ARM

# setup logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(level=logging.DEBUG)

THUMB_BLOCK_OFFSET = 0x10

for arch in [
    smallworld.platforms.Architecture.ARM_V5T,
    smallworld.platforms.Architecture.ARM_V6M,
]:
    # harness definition
    platform = smallworld.platforms.Platform(
        arch, smallworld.platforms.Byteorder.LITTLE
    )
    emulator = smallworld.emulators.UnicornEmulator(platform)
    machine = smallworld.state.Machine()
    cpu: ARM = smallworld.state.cpus.CPU.for_platform(platform)
    code = smallworld.state.memory.code.Executable.from_filepath(
        "thumb/thumb.armel.bin", address=0x1000
    )
    machine.add(cpu)
    machine.add(code)
    machine.add_exit_point(code.address + code.get_capacity())

    # test step_instruction starting with ARM
    cpu.pc.set(code.address)
    for step in machine.step(emulator):
        pass
    cpu.r0.extract(emulator)
    print(f"STEP_{arch.name}={hex(cpu.r0.get())}")

    # test step_instruction starting with Thumb
    cpu.pc.set(code.address + THUMB_BLOCK_OFFSET)
    emulator.set_thumb()
    cpu.r0.set(0)
    for step in machine.step(emulator):
        pass
    cpu.r0.extract(emulator)
    print(f"STEP_{arch.name}={hex(cpu.r0.get())}")

    # test step_block starting with ARM
    cpu.pc.set(code.address)
    cpu.r0.set(0)
    machine.apply(emulator)
    emulator.step_block()
    emulator.step_block()
    emulator.step_block()
    cpu.r0.extract(emulator)
    print(f"BLOCK_{arch.name}={hex(cpu.r0.get())}")

    # test step_block starting with Thumb
    cpu.pc.set(code.address + THUMB_BLOCK_OFFSET)
    emulator.set_thumb()
    cpu.r0.set(0)
    machine.apply(emulator)
    emulator.step_block()
    emulator.step_block()
    cpu.r0.extract(emulator)
    print(f"BLOCK_{arch.name}={hex(cpu.r0.get())}")

    # test run starting with ARM
    cpu.pc.set(code.address)
    cpu.r0.set(0)
    machine.emulate(emulator)
    cpu.r0.extract(emulator)
    print(f"RUN_{arch.name}={hex(cpu.r0.get())}")

    # test run starting with Thumb
    cpu.pc.set(code.address + THUMB_BLOCK_OFFSET)
    emulator.set_thumb()
    cpu.r0.set(0)
    machine.emulate(emulator)
    cpu.r0.extract(emulator)
    print(f"RUN_{arch.name}={hex(cpu.r0.get())}")

    # test mode change Thumb->ARM
    cpu.pc.set(code.address + THUMB_BLOCK_OFFSET)
    emulator.set_thumb()
    print(f"GET_THUMB_PRE1_{arch.name}={emulator.get_thumb()}")
    cpu.r0.set(0)
    machine.emulate(emulator)
    cpu.r0.extract(emulator)
    print(f"GET_THUMB_POST1_{arch.name}={emulator.get_thumb()}")

    # test mode change ARM->Thumb
    cpu.pc.set(code.address)
    print(f"GET_THUMB_PRE2_{arch.name}={emulator.get_thumb()}")
    machine.add_exit_point(code.address + 0x14)
    cpu.r0.set(0)
    machine.emulate(emulator)
    cpu.r0.extract(emulator)
    print(f"GET_THUMB_POST2_{arch.name}={emulator.get_thumb()}")
