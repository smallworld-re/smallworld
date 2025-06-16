import typing

import claripy
import jpype
from ghidra.pcode.emu import PcodeEmulator, PcodeThread
from ghidra.pcode.exec import PcodeExecutorStatePiece

from ... import exceptions, platforms, utils
from ..emulator import Emulator
from .machdefs import PcodeMachineDef


class GhidraEmulator(Emulator):
    name = "pcode-emulator"
    description = "Emulator based on pyghidra and pcode"
    version = "0.0.1"

    # Convert bytes into a JPype byte[]
    # bytes and bytearray are considered variants of String by JPype
    bytes_py_to_java = jpype.JByte[:]

    @staticmethod
    def bytes_java_to_py(val: jpype.JByte[:]):
        # Convert a JPype byte[] into a bytes object
        bytelist = list(
            map(lambda x: x.numerator if x.numerator >= 0 else 256 + x.numerator, val)
        )
        return bytes(bytelist)

    def __init__(self, platform: platforms.Platform):
        super().__init__(platform)
        self.platform: platforms.Platform = platform
        self.machdef: PcodeMachineDef = PcodeMachineDef.for_platform(platform)

        self.emu: PcodeEmulator = PcodeEmulator(self.machdef.language)

        self.memory_map = utils.RangeCollection()

    @property
    def thread(self) -> PcodeThread:
        return self.emu.getThread("main", True)

    def read_register_content(self, name: str) -> int:
        # Determine address and size of register
        if name == "pc":
            name = self.machdef.pc_reg
        reg = self.machdef.pcode_reg(name)

        # Get the thread's register state
        state = self.thread.getState()

        # Get the register value in bytes
        val = state.getVar(reg, PcodeExecutorStatePiece.Reason.INSPECT)

        if self.platform.byteorder is platforms.Byteorder.LITTLE:
            return int.from_bytes(val, "little")
        elif self.platform.byteorder is platforms.Byteorder.BIG:
            return int.from_bytes(val, "big")
        else:
            raise Exception("Unable to decode byteorder {self.platform.byteorder}")

    def write_register_content(
        self, name: str, value: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        # Determine address and size of register
        if name == "pc":
            name = self.machdef.pc_reg
        reg = self.machdef.pcode_reg(name)

        if value is None:
            return
        if not isinstance(value, int):
            raise TypeError("Pcode emulator can't support symbolic values")

        state = self.thread.getState()

        if self.platform.byteorder is platforms.Byteorder.BIG:
            val = value.to_bytes(reg.getMinimumByteSize(), "big")
        elif self.platform.byteorder is platforms.Byteorder.LITTLE:
            val = value.to_bytes(reg.getMinimumByteSize(), "little")
        else:
            raise Exception("Unable to encode byteorder {self.platform.byteorder}")

        state.setVar(reg, self.bytes_py_to_java(val))

    def read_memory_content(self, address: int, size: int) -> bytes:
        # Get the thread's memory state
        shared = self.emu.getSharedState()

        if self.platform.byteorder is platforms.Byteorder.BIG:
            addr_bytes = address.to_bytes(self.machdef.address_size, "big")
        elif self.platform.byteorder is platforms.Byteorder.LITTLE:
            addr_bytes = address.to_bytes(self.machdef.address_size, "little")
        else:
            raise Exception("Unable to encode byteorder {self.platform.byteorder}")

        # Get the data out of the default address space
        # NOTE: Ghidra can support machines with multiple address spaces.
        # SmallWorld does not.
        val = shared.getVar(
            self.machdef.language.getDefaultSpace(),
            self.bytes_py_to_java(addr_bytes),
            size,
            False,
            shared.Reason.INSPECT,
        )
        return self.bytes_java_to_py(val)

    def map_memory(self, address: int, size: int) -> None:
        region = (address, address + size)
        self.memory_map.add_range(region)

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        return list(self.memory_map.ranges)

    def write_memory_content(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ):
        if isinstance(content, claripy.ast.bv.BV):
            raise TypeError("Pcode emulator can't handle symbolic expressions")

        print(f"Writing {hex(len(content))} bytes at {hex(address)}")

        # Get the thread's memory state
        shared = self.emu.getSharedState()

        val = self.bytes_py_to_java(content)
        if self.platform.byteorder is platforms.Byteorder.BIG:
            addr_bytes = address.to_bytes(self.machdef.address_size, "big")
        elif self.platform.byteorder is platforms.Byteorder.LITTLE:
            addr_bytes = address.to_bytes(self.machdef.address_size, "little")
        else:
            raise Exception("Unable to encode byteorder {self.platform.byteorder}")

        # Get the data out of the default address space
        # NOTE: Ghidra can support machines with multiple address spaces.
        # SmallWorld does not.
        shared.setVar(
            self.machdef.language.getDefaultSpace(),
            self.bytes_py_to_java(addr_bytes),
            len(content),
            False,
            val,
        )

    def step_instruction(self) -> None:
        if not self.machdef.supports_single_step:
            raise exceptions.ConfigurationError(
                f"PcodeEmulator does not support single-instruction stepping for {self.platform}"
            )

        # Step!
        pc = self.read_register_content(self.machdef.pc_reg)
        pc_addr = self.machdef.language.getDefaultSpace().getAddress(pc)
        print(f"Stepping through {hex(pc)}")
        self.thread.overrideCounter(pc_addr)

        self.thread.stepInstruction()

        # Check exit points and bounds
        pc = self.read_register_content(self.machdef.pc_reg)

        if pc in self._exit_points:
            raise exceptions.EmulationExitpoint()
        if not self._bounds.is_empty() and not self._bounds.contains_value(pc):
            raise exceptions.EmulationBounds()

    def step_block(self) -> None:
        raise NotImplementedError("Not sure how to step by block.")

    def run(self) -> None:
        try:
            while True:
                self.step_instruction()
        except exceptions.EmulationStop:
            pass

    def __repr__(self) -> str:
        return "PcodeEmulator"
