import argparse
import logging
import pathlib

import smallworld
from smallworld.platforms.defs.mcs51 import (
    MCS51_IDATA_BASE,
    MCS51_SFR_BASE,
    MCS51_XDATA_BASE,
)

# The 8051 counterpart of runner.py, for the C99 tests built with SDCC; see
# mcs51_cc.sh --c99.
#
# The program runs from the reset vector, through SDCC's startup code, into
# main.  Every library function with a model for the ABI is replaced by it.
# A test succeeds by reading its sentinel: SDCC's 16-bit size_t truncates
# 0xdead0 to 0xead0, which as a generic pointer is in XDATA.  Returning from
# main, or calling exit, is a failure.
#
# SDCC links its library into the image, so a function left without a model
# would still run, as SDCC's own code.  The function the test is named for
# must have a model, and it must run.

parser = argparse.ArgumentParser()
parser.add_argument("path", help="the .ihx image, with its .map beside it")
parser.add_argument("abi", choices=["sdcc", "sdccstackauto"])
args = parser.parse_args()

smallworld.logging.setup_logging(level=logging.DEBUG)

platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MCS51, smallworld.platforms.Byteorder.BIG
)
abi = (
    smallworld.platforms.ABI.SDCC
    if args.abi == "sdcc"
    else smallworld.platforms.ABI.SDCCSTACKAUTO
)

machine = smallworld.state.Machine()
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

image = pathlib.Path(__file__).parent / args.path
with open(image) as file, open(image.with_suffix(".map")) as map_file:
    code = smallworld.state.memory.code.Executable.from_ihex(
        file, map_file=map_file, platform=platform
    )
machine.add(code)

# Reset state; SDCC's startup code sets SP and initializes memory.
cpu.pc.set(0)
cpu.sp.set(0x07)
for register in ("acc", "b", "psw", "dptr"):
    getattr(cpu, register).set(0)
for i in range(8):
    getattr(cpu, f"r{i}").set(0)

# Internal RAM, the SFRs, and the low half of XDATA for the program's data.
for base, size in (
    (MCS51_IDATA_BASE, 0x100),
    (MCS51_SFR_BASE, 0x100),
    (MCS51_XDATA_BASE, 0x8000),
):
    machine.add(smallworld.state.memory.RawMemory.from_bytes(b"\0" * size, base))

heap = smallworld.state.memory.heap.BumpAllocator(MCS51_XDATA_BASE + 0x8000, 0x1000)
machine.add(heap)

# Models' static buffers, such as strerror's, go after the heap.
static_address = MCS51_XDATA_BASE + 0x9000
static_size = 0x1000
machine.add(
    smallworld.state.memory.RawMemory.from_bytes(b"\0" * static_size, static_address)
)

# SDCC's string.h makes memcpy a macro for __memcpy.
aliases = {"___memcpy": "memcpy"}

# The function under test: c99/<function>/<function>.<variant>.mcs51.ihx.
under_test = image.name.split(".")[0]
modelled: set[str] = set()
called: set[str] = set()


def count_calls(name: str, model: smallworld.state.models.Model) -> None:
    run = model.model

    def model_and_count(emulator: smallworld.emulators.Emulator) -> None:
        called.add(name)
        run(emulator)

    model.model = model_and_count  # type: ignore[method-assign]


def parameter_addresses(function: str) -> list[int]:
    # Where SDCC's default convention puts the function's arguments after the
    # first; none under --stack-auto.
    names = set(code.get_symbol_names())
    addresses = []
    n = 2
    while f"{function}_PARM_{n}" in names:
        addresses.append(code.get_symbol_value(f"{function}_PARM_{n}"))
        n += 1
    return addresses


for symbol in code.get_symbol_names():
    name = aliases.get(symbol, symbol[1:] if symbol.startswith("_") else None)
    if name is None:
        continue
    try:
        model = smallworld.state.models.Model.lookup(
            name, platform, abi, code.get_symbol_value(symbol)
        )
    except ValueError:
        continue
    model.parameter_addresses = parameter_addresses(symbol)
    if hasattr(model, "heap"):
        model.heap = heap
    if model.static_space_required > 0:
        assert model.static_space_required <= static_size
        model.static_buffer_address = static_address
        static_address += model.static_space_required
        static_size -= model.static_space_required
    modelled.add(name)
    count_calls(name, model)
    machine.add(model)

if under_test not in modelled:
    raise Exception(f"{under_test} has no model for {abi}")


class SuccessExitException(Exception):
    pass


class DeadModel(smallworld.state.models.mmio.MemoryMappedModel):
    def __init__(self, address: int):
        super().__init__(address, 1)

    def on_read(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, content: bytes
    ) -> bytes:
        raise SuccessExitException()

    def on_write(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        pass


machine.add(DeadModel(MCS51_XDATA_BASE + 0xEAD0))

emulator = smallworld.emulators.GhidraEmulator(platform)
# SDCC's startup code ends `lcall _main`, then loops forever.
emulator.add_exit_point(code.get_symbol_value("__sdcc_program_startup") + 3)
emulator.add_exit_point(code.get_symbol_value("_exit"))

try:
    machine.emulate(emulator)
    raise Exception("Did not exit as expected")
except SuccessExitException:
    pass

if under_test not in called:
    raise Exception(f"the model of {under_test} never ran")
