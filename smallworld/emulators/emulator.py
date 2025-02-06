from __future__ import annotations

import abc
import typing

import claripy

from .. import platforms, utils


class Emulator(utils.MetadataMixin, metaclass=abc.ABCMeta):
    """An emulation environment.

    Arguments:
        platform: Platform metadata for emulation.
    """

    def __init__(self, platform: platforms.Platform):
        self.platform: platforms.Platform = platform
        super().__init__()
        self._bounds: utils.RangeCollection = utils.RangeCollection()
        self._exit_points: typing.Set[int] = set()
        """Configured platform metadata."""

    @abc.abstractmethod
    def read_register_content(self, name: str) -> int:
        """Read the content of a register.

        Arguments:
            name: The name of the register.

        Returns:
            The register's content.

        Raises:
            SymbolicValueError: If the register contains a non-collapsible symbolic value
        """

        return 0

    def read_register_symbolic(self, name: str) -> claripy.ast.bv.BV:
        """Read the content of a register, allowing symbolic output.

        If the implementation of read_register_content()
        raises SymbolicValueError, this must be implemented.

        Arguments:
            name: The name of the register

        Returns:
            The register's content as a z3 expression
        """
        raise NotImplementedError("This emulator does not support symbolic values")

    def read_register_type(self, name: str) -> typing.Optional[typing.Any]:
        """Read the type of a register.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            name: The name of the register.

        Returns:
            The register's type
        """

        return None

    def read_register_label(self, name: str) -> typing.Optional[str]:
        """Read the label of a register.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            name: The name of the register.

        Returns:
            The register's label.
        """

        return None

    def read_register(self, name: str) -> int:
        """A helper to read the content of a register.

        Arguments:
            name: The name of the register.

        Returns:
            The register's content.
        """

        return self.read_register_content(name)

    @abc.abstractmethod
    def write_register_content(
        self, name: str, content: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        """Write some content to a register.

        Arguments:
            name: The name of the register to write.
            content: The content to write.

        Raises:
            SymbolicValueError: If content is a bitvector expression, and this emulator doesn't support them.
        """

        pass

    def write_register_type(
        self, name: str, type: typing.Optional[typing.Any] = None
    ) -> None:
        """Write the type of a register.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            name: The name of the register.
            type: The type of the register to write. To unset the register
                type, this may be set to None.
        """

        pass

    def write_register_label(
        self, name: str, label: typing.Optional[str] = None
    ) -> None:
        """Write the label of a register.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            name: The name of the register.
            label: The label of the register to write. To unset the register
                label, this may be set to None.
        """

        pass

    def write_register(
        self, name: str, content: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        """A helper to write the content of a register.

        Arguments:
            name: The name of the register.
            content: The content to write.

        Raises:
            TypeError: If content is a BV, and this emulator cannot handle bitvector expressions
        """

        return self.write_register_content(name, content)

    @abc.abstractmethod
    def read_memory_content(self, address: int, size: int) -> bytes:
        """Read memory content from a specific address.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region.

        Returns:
            `size` bytes read from `address`

        Raises:
            SymbolicValueError:  If the memory range contains a non-collapsible symbolic value
        """

        return b""

    def read_memory_symbolic(self, address: int, size: int) -> claripy.ast.bv.BV:
        """Read memory content from a specific address as a symbolic expression.

        If the implementation of read_register_content()
        raises SymbolicValueError, this must be implemented.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region.

        Returns:
            A z3 expression of `size * 8` bits read from `address`
        """
        raise NotImplementedError("This emulator does not support symbolic values")

    def read_memory_type(self, address: int, size: int) -> typing.Optional[typing.Any]:
        """Read memory type from a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region.

        Returns:
            The memory region's type.
        """

        return None

    def read_memory_label(self, address: int, size: int) -> typing.Optional[str]:
        """Read memory label from a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region.

        Returns:
            The memory region's label.
        """

        return None

    def read_memory(self, address: int, size: int) -> bytes:
        """A helper to read memory content from a specific address.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region.

        Returns:
            `size` bytes read from `address`.

        Raises:
            SymbolicValueError:  If the memory range contains a non-collapsible symbolic value
        """

        return self.read_memory_content(address, size)

    @abc.abstractmethod
    def map_memory(self, address: int, size: int) -> None:
        """Map memory of a given size.

        If the requested allocation overlaps with existing regions,
        this will fill in the gaps.

        Arguments:
            address: The requested address of the allocation.
            size: The size of the allocation.
        """

        pass

    @abc.abstractmethod
    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        """Retrieve the memory map as understood by the emulator.

        Returns:
            The list of tuples (start, end) of the mapped segments
        """

        return []

    @abc.abstractmethod
    def write_memory_content(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ) -> None:
        """Write content to memory at a specific address.

        Note:
            Written memory should already be mapped by some call to
            `map_memory()`.

        Arguments:
            address: The address of the memory region.
            content: The content to write.

        Raises:
            TypeError: If content is a BV, and this emulator can't handle them
        """

        pass

    def write_memory_type(
        self, address: int, size: int, type: typing.Optional[typing.Any] = None
    ) -> None:
        """Set the type of memory at a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region
            type: The type of the register to write. To unset the register
                type, this may be set to None.
        """

        pass

    def write_memory_label(
        self, address: int, size: int, label: typing.Optional[str] = None
    ) -> None:
        """Set the label of memory at a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region
            label: The label of the register to write. To unset the register
                label, this may be set to None.
        """

        pass

    def write_memory(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ) -> None:
        """A helper to write content to memory at a specific address.

        Note:
            Written memory should already be mapped by some call to
            `map_memory()`.

        Arguments:
            address: The address of the memory region.
            content: The content to write.

        Raises:
            SymbolicValueError: If `content` is a bitvector expression, and this emulator doesn't support them.
        """

        self.write_memory_content(address, content)

    def write_code(self, address: int, content: bytes) -> None:
        """Write executable memory at a specific address.

        Implementations can take advantage of this
        if they store code and memory differently.

        Otherwise, it should be identical to `write_memory()`.

        Note:
            Written memory should already be mapped by some call to
            `map_memory()`.

        Arguments:
            address: The address of the memory region.
            content: The content to write.

        """
        self.write_memory_content(address, content)

    def get_bounds(self) -> typing.List[typing.Tuple[int, int]]:
        """Get a list of all registered execution bounds.

        Returns:
            A list of registered execution bounds.
        """

        return list(self._bounds.ranges)

    def add_bound(self, start: int, end: int) -> None:
        """Add valid execution bounds.

        If execution leaves these bounds Emulators should raise
        EmulationBoundsError.

        If execution bounds are not specified, Emulators should allow execution
        anywhere.

        Arguments:
            start: The start address of a valid executable region.
            end: The end address of a valid executable region.
        """

        self._bounds.add_range((start, end))

    def remove_bound(self, start: int, end: int) -> None:
        self._bounds.remove_range((start, end))

    _exit_points: typing.Set[int] = set()

    def get_exit_points(self) -> typing.Set[int]:
        """Get a list of all registered exit points.

        Returns:
            A list of registered exit points.
        """

        return self._exit_points

    def add_exit_point(self, address: int) -> None:
        """Add an exit point.

        If execution reaches an exit point emulation should stop.

        Arguments:
            address: The address of the exit point.
        """

        self._exit_points.add(address)

    @abc.abstractmethod
    def step_instruction(self) -> None:
        """Single instruction step execution.

        Raises:
            EmulationBoundsError: if execution steps out of bounds.
        """

        pass

    @abc.abstractmethod
    def step_block(self) -> None:
        """Single block step execution.

        Raises:
            EmulationBoundsError: if execution steps out of bounds.
        """

        pass

    def step(self) -> None:
        """Helper for single instruction step execution.

        Raises:
            EmulationBoundsError: if execution steps out of bounds.
        """

        return self.step_instruction()

    @abc.abstractmethod
    def run(self) -> None:
        """Run execution indefinitely.

        Emulation should stop if an exit point is reached or execution leaves
        valid bounds.

        Raises:
            EmulationBoundsError: if execution steps out of bounds.
        """

        pass

    @abc.abstractmethod
    def __repr__(self) -> str:
        return ""


class InstructionHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports instruction hooking."""

    @abc.abstractmethod
    def hook_instruction(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        """Hook a specific instruction by address.

        Arguments:
            address: The address of the hook.
            function: The function to execute when the address is reached.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_instruction(self, address: int) -> None:
        """Unhook a specific instruction by address.

        Arguments:
            address: The address of the hook to remove.
        """

        pass

    @abc.abstractmethod
    def hook_instructions(self, function: typing.Callable[[Emulator], None]) -> None:
        pass

    @abc.abstractmethod
    def unhook_instructions(self) -> None:
        """Unhook all system interrupts."""

        pass


class FunctionHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports function hooking."""

    @abc.abstractmethod
    def hook_function(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        """Hook a specific function by address.

        After the hook function is called, the Emulator will step out of the
        current function so that the hook essentially replaces a function call
        to the given address.

        Arguments:
            address: The address of the hook.
            function: The function to execute when the address is reached.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_function(self, address: int) -> None:
        """Unhook a specific function by address.

        Arguments:
            address: The address of the hook to remove.
        """

        pass


class SyscallHookable(metaclass=abc.ABCMeta):
    """An emulator mixin that supports syscall hooking."""

    @abc.abstractmethod
    def hook_syscall(
        self, number: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        """Hook a specific syscall by number.

        This hook will fire if emulation hits a platform-specific syscall instruction
        invoking the specified syscall number.

        Emulation will resume at the instruction after the syscall.
        To change this, the handler should modify the PC register in the emulator.

        Arguments:
            number: The syscall number to handle
            function: The handler function for this syscall
        """
        pass

    @abc.abstractmethod
    def unhook_syscall(self, number: int) -> None:
        """Unhook a specific syscall by number.

        Arguments:
            number: The syscall number to unhook
        """
        pass

    @abc.abstractmethod
    def hook_syscalls(self, function: typing.Callable[[Emulator, int], None]) -> None:
        """Hook all syscalls

        This hook will fire if emulation hits a platform-specific syscall instruction.

        Emulation will resume at the instruction after the syscall.
        To change this, the handler should modify the PC register in the emulator.

        Arguments:
            function: The handler function for all syscalls
        """
        pass

    @abc.abstractmethod
    def unhook_syscalls(self) -> None:
        """Unhook all syscalls"""
        pass


class MemoryReadHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports memory read hooking."""

    @abc.abstractmethod
    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
    ) -> None:
        """Hook memory reads within a given range, handling concrete values

        Arguments:
            start: The start address of the memory range to hook.
            end: The end address of the memory range to hook.
            function: The function to execute when the memory region is read.

        Example:
            The hook function looks like::

                def hook(
                    emulator: Emulator,
                    address: int,
                    size: int,
                    content: bytes
                ) -> bytes:
                    # "content" represents the information the emulator would have fetched.
                    # The return value is what should be reported to the emulator.
                    # If return is "None", the original value of "content" will be reported.
                    ...

        """

        pass

    def hook_memory_read_symbolic(
        self,
        start: int,
        end: int,
        function: typing.Callable[
            [Emulator, int, int, claripy.ast.bv.BV], typing.Optional[claripy.ast.bv.BV]
        ],
    ) -> None:
        """Hook memory reads within a given range, handling symbolic values

        Arguments:
            start: The start address of the memory range to hook.
            end: The end address of the memory range to hook.
            function: The function to execute when the memory region is read.

        Raises:
            NotImplementedError: If this emulator doesn't support symbolic operations

        Example:
            The hook function looks like::

                def hook(
                    emulator: Emulator,
                    address: int,
                    size: int,
                    content: claripy.ast.bv.BV
                ) -> typing.Optional[claripy.ast.bv.BV]:
                    # "content" represents the information the emulator would have fetched.
                    # The return value is what should be reported to the emulator.
                    # If return is "None", the original value of "content" will be reported.
                    ...
        """
        raise NotImplementedError("This emulator doesn't support symbolic operations")

    @abc.abstractmethod
    def unhook_memory_read(self, start: int, end: int) -> None:
        """Unhook a specific memory region read by address range.

        Arguments:
            start: The start address of the memory read hook to remove.
            end: The end address of the memory read hook to remove.
        """

        pass

    @abc.abstractmethod
    def hook_memory_reads(
        self,
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
    ) -> None:
        """Hook all memory reads, handling concrete values

        Arguments:
            function: The function to execute when the memory region is read.

        Example:
            The hook function looks like::

                def hook(
                    emulator: Emulator,
                    address: int,
                    size: int,
                    data: bytes
                ) -> typing.Optional[bytes]:
                    # "data" represents the information the emulator would have fetched.
                    # The return value is what should be reported to the emulator.
                    # If return is "None", the original value of "content" will be reported.
                    ...
        """
        pass

    def hook_memory_reads_symbolic(
        self,
        function: typing.Callable[
            [Emulator, int, int, claripy.ast.bv.BV], typing.Optional[claripy.ast.bv.BV]
        ],
    ) -> None:
        """Hook all memory reads, handling concrete values

        Arguments:
            function: The function to execute when the memory region is read.

        Example:
            The hook function looks like::

                def hook(
                    emulator: Emulator,
                    address: int,
                    size: int,
                    content: claripy.ast.bv.BV
                ) -> typing.Optional[claripy.ast.bv.BV]:
                    # "data" represents the data fetched by the emulator
                    # The return value is what should be reported to the guest
                    ...
        """
        raise NotImplementedError("This emulator doesn't support symbolic operations")

    @abc.abstractmethod
    def unhook_memory_reads(self) -> None:
        """Unhook any 'all reads' handlers"""

        pass


class MemoryWriteHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports memory write hooking."""

    @abc.abstractmethod
    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes], None],
    ) -> None:
        """Hook memory writes within a given range, handling concrete values.

        Arguments:
            start: The start address of the memory range to hook.
            end: The end address of the memory range to hook.
            function: The function to execute when the memory region is written.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator, address: int, size: int, content: bytes) -> None:
                    # "content" is the value written by the guest.
                    # Hooks are responsible for completing the write to the emulator's state
                    ...
        """

        pass

    def hook_memory_write_symbolic(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, claripy.ast.bv.BV], None],
    ) -> None:
        """Hook memory writes within a given range, handling symbolic values

        Arguments:
            start: The start address of the memory range to hook.
            end: The end address of the memory range to hook.
            function: The function to execute when the memory region is written.

        Raises:
            NotImplementedError: If this emulator doesn't support symbolic operations

        Example:
            The hook function looks like::

                def hook(emulator: Emulator, address: int, size: int, content: claripy.ast.bv.BV) -> None:
                    # "content" is the value written by the guest.
                    # Hooks are responsible for completing the write to the emulator's state
                    ...
        """
        raise NotImplementedError("This emulator doesn't support symbolic operations")

    @abc.abstractmethod
    def unhook_memory_write(self, start: int, end: int) -> None:
        """Unhook a specific memory region write by address range.

        Arguments:
            start: The start address of the memory write hook to remove.
            end: The end address of the memory write hook to remove.
        """

        pass

    @abc.abstractmethod
    def hook_memory_writes(
        self, function: typing.Callable[[Emulator, int, int, bytes], None]
    ) -> None:
        """Hook all memory writes, handling concrete values.

        Arguments:
            function: The function to execute when the memory region is written.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator, address: int, size: int, content: bytes) -> None:
                    # "content" is the value written by the guest.
                    # Hooks are responsible for completing the write to the emulator's state
                    ...
        """

        pass

    def hook_memory_writes_symbolic(
        self,
        function: typing.Callable[[Emulator, int, int, claripy.ast.bv.BV], None],
    ) -> None:
        """Hook all memory writes, handling symbolic values

        Arguments:
            function: The function to execute when the memory region is written.

        Raises:
            NotImplementedError: If this emulator doesn't support symbolic operations

        Example:
            The hook function looks like::

                def hook(emulator: Emulator, address: int, size: int, content: claripy.ast.bv.BV) -> None:
                    # "content" is the value written by the guest.
                    # Hooks are responsible for completing the write to the emulator's state
                    ...
        """
        raise NotImplementedError("This emulator doesn't support symbolic operations")

    @abc.abstractmethod
    def unhook_memory_writes(self) -> None:
        """Unhook any global memory write hook."""

        pass


class InterruptHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports interrupt hooking."""

    @abc.abstractmethod
    def hook_interrupts(self, function: typing.Callable[[Emulator, int], None]) -> None:
        """Hook any system interrupts.

        Arguments:
            function: The function to execute when an interrupt is triggered.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator, interrupt: int) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_interrupts(self) -> None:
        """Unhook all system interrupts."""

        pass

    @abc.abstractmethod
    def hook_interrupt(
        self, interrupt: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        """Hook a specific system interrupt.

        Arguments:
            function: The function to execute when the interrupt is triggered.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_interrupt(self, interupt: int) -> None:
        """Unhook a specific system interrupt.

        Arguments:
            interrupt: The interrupt to unhook.
        """

        pass


class ConstrainedEmulator:
    """Emulator that supports constraints

    It must also support some means of evaluating constraints,
    probably an SMT solver or similar.
    """

    @abc.abstractmethod
    def add_constraint(self, expr: claripy.ast.bool.Bool) -> None:
        """Add a constraint to the emulator

        A constraint is an expression that
        this emulator will use to limit the possible values
        of unbound variables.
        It will only consider execution states
        where all constraints can evaluate to True.

        Constraints must be Boolean expressions;
        the easiest form is the equality or inequality
        of two bitvector expressions.

        Arguments:
            expr: The constraint expression to add
        """
        pass

    @abc.abstractmethod
    def get_constraints(self) -> typing.List[claripy.ast.bool.Bool]:
        """Retrieve all constraints applied to this emulator.

        Returns:
            A list of constraint expressions
        """
        raise NotImplementedError("Abstract method")

    @abc.abstractmethod
    def satisfiable(
        self,
        extra_constraints: typing.List[claripy.ast.bool.Bool] = [],
    ) -> bool:
        """Check if the current set of constraints is satisfiable

        This checks if there's a way to assign variables
        such that all constraint expressions evaluate to "True".
        If not, the state can't exist as described.

        The emulator tracks its own set of constraints,
        added by the harness or built up durring execution.
        The caller can provide additional constraints
        for testing. These are not permanently added to the emulator.

        Arguments:
            extra_constraints:  A list of additional constraints to consider.

        Returns:
            True if the constraint system is satisfiable.  False otherwise.
        """
        return False

    @abc.abstractmethod
    def eval_atmost(self, expr: claripy.ast.bv.BV, most: int) -> typing.List[int]:
        """Find a maximum number of solutions to a bitvector expression

        This attempts to find concrete solutions to `expr`
        given the constraints on the emulator.

        It will return between 1 and `most` solutions, inclusive.
        It will raise exceptions if there are no solutions,
        or more than requested.

        Arguments:
            expr: The expression to evaluate
            most: The inclusive upper limit on solutions

        Returns:
            A list of integer solutions to `expr`

        Raises:
            UnsatError: If there are no solutions for `expr` given constraints
            SymbolicValueError: If there are more than `most` solutions for `expr` given constraints
        """
        raise NotImplementedError("Abstract method")

    @abc.abstractmethod
    def eval_atleast(self, expr: claripy.ast.bv.BV, least: int) -> typing.List[int]:
        """Find a minimum number of solutions to a bitvector expression

        This attempts to find concrete solutions to `expr`
        given the constraints on the emulator.

        It will return `least` solutions.
        It will raise an exception if there are fewer than `least` solutions possible.

        Arguments:
            expr: The expression to evaluate
            least: The number of solutions to retrieve

        Returns:
            A list of integer solutions to `expr`

        Raises:
            UnsatError: If there are no solutions for `expr` given constraints
            SymbolicValueError: If there are fewer than `least` solutions for `expr` given constraints
        """
        raise NotImplementedError("Abstract method")


__all__ = [
    "Emulator",
    "InstructionHookable",
    "FunctionHookable",
    "MemoryReadHookable",
    "MemoryWriteHookable",
    "InterruptHookable",
    "ConstrainedEmulator",
]
