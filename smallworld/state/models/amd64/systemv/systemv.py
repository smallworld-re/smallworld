from ..... import emulators, platforms
from ...cstd import CStdModel


class AMD64SysVModel(CStdModel):
    """Base class for C models using the AMD64 System-V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    def get_arg1(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("rdi")

    def get_arg2(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("rsi")

    def get_arg3(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("rdx")

    def get_arg4(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("rcx")

    def get_arg5(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r8")

    def get_arg6(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("r9")

    def set_return_value(self, emulator: emulators.Emulator, val: int):
        emulator.write_register("rax", val)
