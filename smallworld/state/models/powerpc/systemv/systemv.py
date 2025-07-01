from ..... import emulators, platforms
from ...cstd import CStdModel


class PowerPCSysVModel(CStdModel):
    """Base class for C models using the PowerPC System-V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV

    def get_arg1(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r3")

    def get_arg2(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r4")

    def get_arg3(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r5")

    def get_arg4(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r6")

    def get_arg5(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r7")

    def get_arg6(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r8")

    def set_return_value(self, emulator: emulators.Emulator, val: int):
        emulator.write_register("r3", val)
