from ..... import emulators, platforms
from ...cstd import CStdModel


class ArmELSysVModel(CStdModel):
    """Base class for C models using the ARM32 GNU EABI

    This is a specific ARM System V ABI.
    It generally applies to ARMv5t or ARMv6.
    """

    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    def get_arg1(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r0")

    def get_arg2(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r1")

    def get_arg3(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r2")

    def get_arg4(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r3")

    def get_arg5(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r4")

    def get_arg6(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r5")

    def set_return_value(self, emulator: emulators.Emulator, val: int):
        emulator.write_register("r0", val)
