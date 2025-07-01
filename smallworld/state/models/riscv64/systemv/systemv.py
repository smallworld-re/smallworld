from ..... import emulators, platforms
from ...cstd import CStdModel


class RiscV64SysVModel(CStdModel):
    """Base class for C models using the RiscV64 System-V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
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
        return emulator.read_register("a4")

    def get_arg6(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("a5")

    def set_return_value(self, emulator: emulators.Emulator, val: int):
        emulator.write_register("a0", val)
