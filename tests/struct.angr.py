import ctypes as ct
import logging

from smallworld import cpus, ctypes, state, utils
from smallworld.analyses.angr_nwbt import AngrNWBTAnalysis

if __name__ == "__main__":
    # Load the 'struct.bin' test.
    infile = "struct.bin"
    fmt = "blob"
    arch = "x86"
    mode = "64"
    byteorder = "little"
    base = 0x1000
    entry = base

    utils.setup_logging(level=logging.DEBUG)
    # Silence angr's logger; it's too verbose.
    logging.getLogger("angr").setLevel(logging.INFO)
    logging.getLogger("claripy").setLevel(logging.INFO)
    utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

    target = state.Code.from_filepath(
        infile, format=fmt, arch=arch, mode=mode, base=base, entry=entry
    )

    class StructNode(ct.LittleEndianStructure):
        _pack_ = 8

    StructNode._fields_ = [
        ("data", ct.c_int32),
        ("next", ctypes.typed_pointer(StructNode)),
        ("prev", ctypes.typed_pointer(StructNode)),
        ("empty", ct.c_int32),
    ]

    cpu = cpus.AMD64CPUState()

    cpu.rdi.type = ctypes.typed_pointer(StructNode)
    cpu.map(target)
    cpu.rip.value = entry

    analysis = AngrNWBTAnalysis()
    analysis.run(cpu)
