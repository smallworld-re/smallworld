import typing

from .emulator import (
    Emulator,
    FunctionHookable,
    InstructionHookable,
    InterruptHookable,
    MemoryReadHookable,
    MemoryWriteHookable,
)


def range_intersect(r1, r2):
    return range(max(r1.start, r2.start), min(r1.stop, r2.stop)) or None


def range_to_hex_str(r):
    return f"[{r.start:x}..{r.stop:x}]"


class QInstructionHookable(InstructionHookable):
    """Implementation of instruction hook data structure mgmt to be used by qemu-based emulators."""

    def __init__(self: typing.Any) -> None:
        super().__init__()
        self.instruction_hooks: typing.Dict[int, typing.Callable[[Emulator], None]] = {}
        self.all_instructions_hook: typing.Optional[
            typing.Callable[[Emulator], None]
        ] = None

    def hook_instructions(self, function: typing.Callable[[Emulator], None]) -> None:
        self.all_instructions_hook = function

    def unhook_instructions(self):
        self.all_instructions_hook = None

    def hook_instruction(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        if address in self.instruction_hooks:
            raise ValueError(
                f"can't hook instruction at {address:x} since already hooked"
            )
        self.instruction_hooks[address] = function

    def unhook_instruction(self, address: int) -> None:
        if address not in self.instruction_hooks:
            raise ValueError(
                f"can't unhook instruction at {address:x} since its not already hooked"
            )
        self.instruction_hooks.pop(address, None)

    def is_instruction_hooked(
        self, address: int
    ) -> typing.Optional[typing.Callable[[Emulator], None]]:
        if address in self.instruction_hooks:
            return self.instruction_hooks[address]
        else:
            return None


class QFunctionHookable(FunctionHookable):
    """Implementation of function hook data structure mgmt to be used by qemu-based emulators."""

    def __init__(self: typing.Any) -> None:
        super().__init__()
        self.function_hooks: typing.Dict[int, typing.Callable[[Emulator], None]] = {}

    def hook_function(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        if address in self.function_hooks:
            raise ValueError(f"can't hook function at {address:x} since already hooked")
        self.function_hooks[address] = function

    def unhook_function(self, address: int) -> None:
        if address not in self.function_hooks:
            raise ValueError(
                f"can't unhook function at {address:x} since its not already hooked"
            )
        self.function_hooks.pop(address, None)

    def is_function_hooked(
        self, address: int
    ) -> typing.Optional[typing.Callable[[Emulator], None]]:
        if address in self.function_hooks:
            return self.function_hooks[address]
        else:
            return None


class QMemoryReadHookable(MemoryReadHookable):
    """Implementation of memory read hook data structure mgmt to be used by qemu-based emulators."""

    def __init__(self: typing.Any) -> None:
        super().__init__()
        self.memory_read_hooks: typing.Dict[
            range, typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]]
        ] = {}
        self.all_reads_hook: typing.Optional[
            typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]]
        ] = None

    def hook_memory_reads(
        self,
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
    ) -> None:
        self.all_reads_hook = function

    def unhook_memory_reads(self):
        self.all_reads_hook = None

    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
    ) -> None:
        new_range = range(start, end)
        for r in self.memory_read_hooks:
            if range_intersect(r, new_range):
                raise ValueError(
                    f"can't hook memory read range {range_to_hex_str(new_range)} since that overlaps already hooked range {range_to_hex_str(r)}"
                )
        self.memory_read_hooks[new_range] = function

    def unhook_memory_read(self, start: int, end: int) -> None:
        unh_r = range(start, end)
        for r in self.memory_read_hooks:
            if unh_r == r:
                self.memory_read_hooks.pop(r, None)
                return
        raise ValueError(
            f"can't unhook memory read range {range_to_hex_str(unh_r)} since its not already hooked"
        )

    # def unhook_memory_read(address: int) -> None:
    #    if address not in self.memory_read_hooks:
    #        raise ValueError(
    #            f"can't unhook memory read range {range_to_hex_str(address)} since its not already hooked"
    #        )
    #    self.memory_read_hooks.pop(address, None)

    def is_memory_read_hooked(
        self, address: int
    ) -> typing.Optional[
        typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]]
    ]:
        for rng in self.memory_read_hooks:
            if address in rng:
                return self.memory_read_hooks[rng]
        return None


class QMemoryWriteHookable(MemoryWriteHookable):
    """Implementation of memory write hook data structure mgmt to be used by qemu-based emulators."""

    def __init__(self: typing.Any) -> None:
        super().__init__()
        self.memory_write_hooks: typing.Dict[
            range, typing.Callable[[Emulator, int, int, bytes], None]
        ] = {}
        self.all_writes_hook: typing.Optional[
            typing.Callable[[Emulator, int, int, bytes], None]
        ] = None

    def hook_memory_writes(
        self, function: typing.Callable[[Emulator, int, int, bytes], None]
    ) -> None:
        self.all_writes_hook = function

    def unhook_memory_writes(self):
        self.all_writes_hook = None

    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes], None],
    ) -> None:
        new_range = range(start, end)
        for r in self.memory_write_hooks:
            if range_intersect(r, new_range):
                raise ValueError(
                    f"can't hook memory write range {range_to_hex_str(new_range)} since that overlaps already hooked range {range_to_hex_str(r)}"
                )
        self.memory_write_hooks[new_range] = function

    def unhook_memory_write(self, start: int, end: int) -> None:
        unh_r = range(start, end)
        for r in self.memory_write_hooks:
            if unh_r == r:
                self.memory_write_hooks.pop(r, None)
                return
        raise ValueError(
            f"can't unhook memory write range {range_to_hex_str(unh_r)} since its not already hooked"
        )

    # def unhook_memory_write(self, address: int) -> None:
    #    if address not in self.memory_write_hooks:
    #        raise ValueError(
    #            f"can't unhook memory write range {range_to_hex_str(address)} since its not already hooked"
    #        )
    #    self.memory_write_hooks.pop(address, None)
    def is_memory_write_hooked(
        self, address: int
    ) -> typing.Optional[typing.Callable[[Emulator, int, int, bytes], None]]:
        for rng in self.memory_write_hooks:
            if address in rng:
                return self.memory_write_hooks[rng]
        return None


class QInterruptHookable(InterruptHookable):
    """Implementation of interrupt hook data structure mgmt to be used by qemu-based emulators."""

    def __init__(self: typing.Any) -> None:
        super().__init__()
        self.all_interrupts_hook: typing.Optional[
            typing.Callable[[Emulator, int], None]
        ] = None
        self.interrupt_hooks: typing.Dict[int, typing.Callable[[Emulator], None]] = {}

    def hook_interrupts(self, function: typing.Callable[[Emulator, int], None]) -> None:
        self.all_interrupts_hook = function

    def unhook_interrupts(self):
        self.all_interrupts_hook = None

    def hook_interrupt(
        self, intno: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        if intno in self.interrupt_hooks:
            raise ValueError(
                f"can't hook interrupt number {intno} since its already hooked"
            )
        self.interrupt_hooks[intno] = function

    def unhook_interrupt(self, intno: int) -> None:
        if intno not in self.interrupt_hooks:
            raise ValueError(
                f"asked to unhook interrupt {intno} which was not previously hooked"
            )
        self.interrupt_hooks.pop(intno, None)

    def is_interrupt_hooked(
        self, intno: int
    ) -> typing.Optional[typing.Callable[[Emulator], None]]:
        if intno in self.interrupt_hooks:
            return self.interrupt_hooks[intno]
        else:
            return None
