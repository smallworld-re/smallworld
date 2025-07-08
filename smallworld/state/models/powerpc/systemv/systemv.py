import typing

from ..... import emulators, exceptions, platforms
from ...cstd import ArgumentType, CStdModel


class PowerPCSysVModel(CStdModel):
    """Base class for C models using the PowerPC System-V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV

    _int_sign_mask = 0x80000000
    _int_inv_mask = 0xFFFFFFFF
    _long_sign_mask = 0x80000000
    _long_inv_mask = 0xFFFFFFFF
    _long_long_sign_mask = 0x8000000000000000
    _long_long_inv_mask = 0xFFFFFFFFFFFFFFFF

    _four_byte_types = {
        ArgumentType.INT,
        ArgumentType.UINT,
        ArgumentType.LONG,
        ArgumentType.ULONG,
        ArgumentType.SIZE_T,
        ArgumentType.SSIZE_T,
        ArgumentType.POINTER,
    }

    _eight_byte_types = {
        ArgumentType.LONGLONG,
        ArgumentType.ULONGLONG,
    }

    _argument_regs = [
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
    ]

    def __init__(self, address):
        super().__init__(address)
        reg_offset = 0
        stack_offset = 0

        self._on_stack = list()
        self._arg_offset = list()

        for i in range(0, len(self.argument_types)):
            t = self.argument_types[i]
            if t in self._four_byte_types or t == ArgumentType.FLOAT:
                if reg_offset == 8:
                    self._on_stack.append(True)
                    self._arg_offset.append(stack_offset)
                    stack_offset += 4
                else:
                    self._on_stack.append(False)
                    self._arg_offset.append(reg_offset)
                    reg_offset += 1
            elif t in self._eight_byte_types or t == ArgumentType.DOUBLE:
                if reg_offset >= 7:
                    reg_offset = 8
                    if stack_offset & 0x4 != 0:
                        stack_offset += 4
                    self._on_stack.append(True)
                    self._arg_offset.append(stack_offset)
                    stack_offset += 8
                else:
                    if reg_offset & 1 != 0:
                        reg_offset += 1
                    self._on_stack.append(False)
                    self._arg_offset.append(reg_offset)
                    reg_offset += 2
            else:
                raise exceptions.ConfigurationError(
                    f"{self.name} argument {i} has unknown type {t}"
                )

    def _get_argument(
        self, index: int, emulator: emulators.Emulator
    ) -> typing.Union[int, float]:
        t = self.argument_types[index]
        on_stack = self._on_stack[index]
        arg_offset = self._arg_offset[index]

        if t in self._four_byte_types:
            if on_stack:
                addr = emulator.read_register("sp") + arg_offset
                data = emulator.read_memory(addr, 4)
                return int.from_bytes(data, "little")
            else:
                return emulator.read_register(self._argument_regs[arg_offset])
        elif t in self._eight_byte_types:
            if on_stack:
                addr = emulator.read_register("sp") + arg_offset
                data = emulator.read_memory(addr, 8)
                return int.from_bytes(data, "little")
            else:
                hi = emulator.read_register(self._argument_regs[arg_offset])
                lo = emulator.read_register(self._argument_regs[arg_offset + 1])
                return (hi << 32) | lo
        elif t == ArgumentType.FLOAT:
            raise NotImplementedError("No support for the PPC32 FPU")
        elif t == ArgumentType.DOUBLE:
            raise NotImplementedError("No support for the PPC32 FPU")
        else:
            raise exceptions.ConfigurationError(
                f"{self.name} argument {index} has unknown type {t}"
            )

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        emulator.write_register("r3", val)

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        lo = val & self._int_inv_mask
        hi = val >> 32 & self._int_inv_mask

        emulator.write_register("r3", hi)
        emulator.write_register("r4", lo)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        raise NotImplementedError("No support for the MIPS32 FPU")

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        raise NotImplementedError("No support for the MIPS32 FPU")
