from ..... import emulators, platforms
from ...cstd import CStdModel


class MIPSELSysVModel(CStdModel):
    """Base class for C models using the MIPS little-endian o32 ABI

    This is one System-V ABI for MIPS32;
    it uses four registers for arguments before
    it switches to stack.
    """

    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    def get_arg1(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("a0")

    def get_arg2(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("a1")

    def get_arg3(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("a2")

    def get_arg4(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("a3")

    def get_arg5(self, emulator: emulators.Emulator) -> int:
        sp = emulator.read_register("sp")
        val = emulator.read_memory(sp + 16, 4)
        return int.from_bytes(val, "little")

    def get_arg6(self, emulator: emulators.Emulator) -> int:
        sp = emulator.read_register("sp")
        val = emulator.read_memory(sp + 20, 4)
        return int.from_bytes(val, "little")

    def set_return_value(self, emulator: emulators.Emulator, val: int):
        emulator.write_register("v0", val)
