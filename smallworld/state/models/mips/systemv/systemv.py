import typing

from ..... import emulators, exceptions, platforms
from ...cstd import ArgumentType, CStdModel


class MIPSSysVModel(CStdModel):
    """Base class for C models using the MIPS o32 ABI"""

    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.BIG
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

    _argument_regs = ["a0", "a1", "a2", "a3"]

    def __init__(self, address):
        super().__init__(address)
        # - MIPS o32 allows for four argument registers: a0 - a3.
        #   - 4-byte int arguments take up one register.
        #   - 8-byte int arguments take up two registers, and must start on an even-numbered register.
        #     - Case: func(int a, long long b)
        #       - a0: holds 'a'
        #       - a1: unused
        #       - a2: holds 'b'
        #       - a3: holds 'b'
        # - Further arguments are stored on the stack.
        #   - 4-byte int arguments must be 4-byte aligned
        #   - 8-byte int arguments must be 8-byte aligned
        #   - Case: func(long long a, int b, long long c)
        #       - a0:       holds 'a'
        #       - a1:       holds 'a'
        #       - a2:       holds 'b'
        #       - a3:       unused
        #       - sp[0:8]:  holds 'c'
        #   - Case: func(long long a, long long b, int c, long long d)
        #       - a0:       holds 'a'
        #       - a1:       holds 'a'
        #       - a2:       holds 'b'
        #       - a3:       holds 'b'
        #       - sp[0:4]:  holds 'c'
        #       - sp[4:8]:  unused
        #       - sp[8:16]: holds 'd'
        reg_offset = 0
        stack_offset = 0

        self._on_stack = list()
        self._arg_offset = list()

        for i in range(0, len(self.argument_types)):
            t = self.argument_types[i]
            if t in self._four_byte_types or t == ArgumentType.FLOAT:
                if reg_offset == 4:
                    self._on_stack.append(True)
                    self._arg_offset.append(stack_offset)
                    stack_offset += 4
                else:
                    self._on_stack.append(False)
                    self._arg_offset.append(reg_offset)
                    reg_offset += 1
            elif t in self._eight_byte_types or t == ArgumentType.DOUBLE:
                if reg_offset >= 3:
                    reg_offset = 4
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
        self,
        index: int,
        kind: ArgumentType,
        emulator: emulators.Emulator,
        absolute: bool = False,
    ) -> typing.Union[int, float]:
        on_stack = self._on_stack[index]
        arg_offset = self._arg_offset[index]

        if kind in self._four_byte_types:
            if on_stack:
                addr = emulator.read_register("sp") + arg_offset
                data = emulator.read_memory(addr, 4)
                return int.from_bytes(data, "little")
            else:
                return emulator.read_register(self._argument_regs[arg_offset])
        elif kind in self._eight_byte_types:
            if on_stack:
                addr = emulator.read_register("sp") + arg_offset
                data = emulator.read_memory(addr, 8)
                return int.from_bytes(data, "little")
            else:
                hi = emulator.read_register(self._argument_regs[arg_offset])
                lo = emulator.read_register(self._argument_regs[arg_offset + 1])
                return (hi << 32) | lo
        elif kind == ArgumentType.FLOAT:
            raise NotImplementedError("No support for the MIPS32 FPU")
        elif kind == ArgumentType.DOUBLE:
            raise NotImplementedError("No support for the MIPS32 FPU")
        else:
            raise exceptions.ConfigurationError(
                f"{self.name} argument {index} has unknown type {kind}"
            )

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        emulator.write_register("v0", val)

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        lo = val & self._int_inv_mask
        hi = (val >> 32) & self._int_inv_mask

        emulator.write_register("v0", hi)
        emulator.write_register("v1", lo)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        raise NotImplementedError("No support for the MIPS32 FPU")

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        raise NotImplementedError("No support for the MIPS32 FPU")
