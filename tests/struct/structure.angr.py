import ctypes
import logging

import smallworld
from smallworld.analyses.unstable.angr_nwbt import AngrNWBTAnalysis

if __name__ == "__main__":
    smallworld.logging.setup_logging(level=logging.DEBUG)

    # Load the 'struct.bin' test.
    infile = "struct.amd64.bin"

    # Silence angr's logger; it's too verbose.
    logging.getLogger("angr").setLevel(logging.INFO)
    logging.getLogger("claripy").setLevel(logging.INFO)

    class StructNode(ctypes.LittleEndianStructure):
        _pack_ = 8

    StructNode._fields_ = [
        ("data", ctypes.c_int32),
        ("next", smallworld.extern.ctypes.create_typed_pointer(StructNode)),
        ("prev", smallworld.extern.ctypes.create_typed_pointer(StructNode)),
        ("empty", ctypes.c_int32),
    ]

    platform = smallworld.platforms.Platform(
        smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
    )

    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = smallworld.state.memory.code.Executable.from_filepath(infile, address=0x1000)
    machine.add(code)

    cpu.rdi.set_type(smallworld.extern.ctypes.create_typed_pointer(StructNode))
    cpu.rip.set(code.address)

    machine.add_bound(code.address, code.address + code.get_capacity())

    analysis = AngrNWBTAnalysis()
    analysis.run(machine)
