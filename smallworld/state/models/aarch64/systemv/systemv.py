from ..... import emulators, platforms
from ...cstd import CStdModel


class AArch64SysVModel(CStdModel):
    """Base class for C models using the AArch64 System-V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    def get_arg1(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("x0")

    def get_arg2(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("x1")

    def get_arg3(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("x2")

    def get_arg4(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("x3")

    def get_arg5(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("x4")

    def get_arg6(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("x5")

    def set_return_value(self, emulator: emulators.Emulator, val: int):
        emulator.write_register("x0", val)
