import logging

import smallworld
from smallworld.state.cpus.arm import ARM

# setup logging and hinting
smallworld.logging.setup_logging(level=logging.DEBUG)

THUMB_BLOCK_OFFSET = 0x10

# The Unicorn version of this test, with a fresh emulator for each run: angr
# can't restart an emulator once its run is over. angr also leaves registers
# no one wrote symbolic, so r0 starts at 0 by hand.
for arch in [
    smallworld.platforms.Architecture.ARM_V8R,
]:
    # harness definition
    platform = smallworld.platforms.Platform(
        arch, smallworld.platforms.Byteorder.LITTLE
    )
    machine = smallworld.state.Machine()
    cpu: ARM = smallworld.state.cpus.CPU.for_platform(platform)
    code = smallworld.state.memory.code.Executable.from_filepath(
        "thumb/thumb.armv8r.bin", address=0x1000
    )
    machine.add(cpu)
    machine.add(code)
    machine.add_exit_point(code.address + code.get_capacity())

    # test step_instruction starting with ARM
    emulator = smallworld.emulators.AngrEmulator(platform)
    cpu.pc.set(code.address)
    cpu.r0.set(0)
    for step in machine.step(emulator):
        pass
    cpu.r0.extract(emulator)
    print(f"STEP_{arch.name}={hex(cpu.r0.get())}")

    # test step_instruction starting with Thumb
    emulator = smallworld.emulators.AngrEmulator(platform)
    cpu.pc.set(code.address + THUMB_BLOCK_OFFSET)
    emulator.set_isa_mode(1)
    cpu.r0.set(0)
    for step in machine.step(emulator):
        pass
    cpu.r0.extract(emulator)
    print(f"STEP_{arch.name}={hex(cpu.r0.get())}")

    # test step_block starting with ARM
    emulator = smallworld.emulators.AngrEmulator(platform)
    cpu.pc.set(code.address)
    cpu.r0.set(0)
    machine.apply(emulator)
    try:
        emulator.step_block()
        emulator.step_block()
        emulator.step_block()
    except smallworld.exceptions.EmulationStop:
        pass
    cpu.r0.extract(emulator)
    print(f"BLOCK_{arch.name}={hex(cpu.r0.get())}")

    # test step_block starting with Thumb
    emulator = smallworld.emulators.AngrEmulator(platform)
    cpu.pc.set(code.address + THUMB_BLOCK_OFFSET)
    emulator.set_isa_mode(1)
    cpu.r0.set(0)
    machine.apply(emulator)
    try:
        emulator.step_block()
        emulator.step_block()
    except smallworld.exceptions.EmulationStop:
        pass
    cpu.r0.extract(emulator)
    print(f"BLOCK_{arch.name}={hex(cpu.r0.get())}")

    # test run starting with ARM
    emulator = smallworld.emulators.AngrEmulator(platform)
    cpu.pc.set(code.address)
    cpu.r0.set(0)
    machine.emulate(emulator)
    cpu.r0.extract(emulator)
    print(f"RUN_{arch.name}={hex(cpu.r0.get())}")

    # test run starting with Thumb
    emulator = smallworld.emulators.AngrEmulator(platform)
    cpu.pc.set(code.address + THUMB_BLOCK_OFFSET)
    emulator.set_isa_mode(1)
    cpu.r0.set(0)
    machine.emulate(emulator)
    cpu.r0.extract(emulator)
    print(f"RUN_{arch.name}={hex(cpu.r0.get())}")

    # test ISA persistance across emulator instances, through cpsr
    emulator = smallworld.emulators.AngrEmulator(platform)
    emulator2 = smallworld.emulators.AngrEmulator(platform)
    cpu.pc.set(code.address + THUMB_BLOCK_OFFSET)
    emulator.set_isa_mode(1)
    cpu.r0.set(0)
    next(machine.step(emulator))
    machine.extract(emulator)
    for step in machine.step(emulator2):
        pass
    cpu.r0.extract(emulator2)
    print(f"PERSIST_THUMB_{arch.name}={hex(cpu.r0.get())}")

    # test mode change Thumb->ARM
    emulator = smallworld.emulators.AngrEmulator(platform)
    cpu.pc.set(code.address + THUMB_BLOCK_OFFSET)
    emulator.set_isa_mode(1)
    print(f"GET_THUMB_PRE1_{arch.name}={bool(emulator.get_isa_mode())}")
    cpu.r0.set(0)
    machine.emulate(emulator)
    cpu.extract(emulator)
    print(f"GET_THUMB_POST1_{arch.name}={bool(emulator.get_isa_mode())}")

    # test mode change ARM->Thumb
    cpu.pc.set(code.address)
    print(f"GET_THUMB_PRE2_{arch.name}={bool(emulator.get_isa_mode())}")
    emulator = smallworld.emulators.AngrEmulator(platform)
    machine.add_exit_point(code.address + 0x14)
    cpu.r0.set(0)
    machine.emulate(emulator)
    print(f"GET_THUMB_POST2_{arch.name}={bool(emulator.get_isa_mode())}")
