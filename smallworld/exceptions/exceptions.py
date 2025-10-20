import typing


class Error(Exception):
    """Common base class for all exceptions."""


class ConfigurationError(Error):
    """Raised when there is a problem with configuration."""

    pass


class EmulationError(Error):
    """Raised when emulation fails."""

    pass


class EmulationStop(EmulationError):
    """Base class for all emulation stopping exceptions."""

    pass


class EmulationBounds(EmulationStop):
    """Raised when execution goes out of bounds."""

    pass


class EmulationExitpoint(EmulationStop):
    """Raised when execution hits an exit point."""

    pass


class UnsupportedRegisterError(EmulationError):
    """Raised if you ask for a register unsupported by the emulator"""

    pass


class SymbolicValueError(EmulationError):
    """Raised if you try to collapse a symbolic value to a concrete one"""

    pass


class UnsatError(EmulationError):
    """Raised if a symbolic expression is unsatisfiable given constraints"""

    pass


class EmulationFailure(EmulationError):
    """Raised if the code being emulated faults somehow"""

    def __init__(self, msg: str, pc: int):
        super().__init__(msg)
        self.pc = pc


class EmulationExecFailure(EmulationFailure):
    """Raised if the current instruction failed to execute"""

    pass


class EmulationExecInvalidFailure(EmulationExecFailure):
    """Raised if the current instruction is invalid for this platform"""

    def __init__(self, msg: str, pc: int, instruction: typing.Optional[typing.Any]):
        super().__init__(msg, pc)
        self.instruction = instruction


class EmulationExecExceptionFailure(EmulationExecFailure):
    """Raised if the current instruction raised an unhandled trap, interrupt, or exception.

    The way different emulators report this is inconsistent.
    The number reported is NOT a platform-specific trap number.
    """

    pass


class EmulationMemoryFailure(EmulationFailure):
    """Raised if something went wrong accessing memory"""

    def __init__(
        self,
        msg: str,
        pc: int,
        operands: typing.Optional[typing.List[typing.Any]] = None,
        address: typing.Optional[int] = None,
    ):
        super().__init__(msg, pc)
        self.address = address
        self.operands = operands

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        msg = self.args[0]
        if self.address is not None:
            return f"{msg} pc={hex(self.pc)} address={hex(self.address)}"
        elif self.operands is not None:
            return f"{msg} pc={hex(self.pc)} operands=[{', '.join(map(lambda x: f'{x[0].expr_string()}: {hex(x[1])}', self.operands))}]"
        else:
            return msg


class EmulationReadFailure(EmulationMemoryFailure):
    """Raised if something went wrong reading memory"""

    pass


class EmulationReadUnmappedFailure(EmulationReadFailure):
    """Raised if the current instruction tried to read unmapped memory"""

    pass


class EmulationReadProtectedFailure(EmulationReadFailure):
    """Raised if the current instruction tried to read read-protected memory"""

    pass


class EmulationReadUnalignedFailure(EmulationReadFailure):
    """Raised if the current instruction tried to read an unaligned address"""

    pass


class EmulationWriteFailure(EmulationMemoryFailure):
    """Raised if something went wrong writing memory"""

    pass


class EmulationWriteUnmappedFailure(EmulationWriteFailure):
    """Raised if the current instruction tried to write to unmapped memory"""

    pass


class EmulationWriteProtectedFailure(EmulationWriteFailure):
    """Raised if the current instruction tried to write to write-protected memory"""

    pass


class EmulationWriteUnalignedFailure(EmulationWriteFailure):
    """Raised if the current instruction tried to write to an unaligned address"""

    pass


class EmulationFetchFailure(EmulationMemoryFailure):
    """Raised if something went wrong fetching an instruction"""

    pass


class EmulationFetchUnmappedFailure(EmulationFetchFailure):
    """Raised if an instruction fetch hit unmapped memory"""

    pass


class EmulationFetchProtectedFailure(EmulationFetchFailure):
    """Raised if an instruction fetch hit exec-protected memory"""

    pass


class EmulationFetchUnalignedFailure(EmulationFetchFailure):
    """Raised if an instruction fetch was for an unaligned address"""

    pass


class EmulationException(EmulationError):
    """Raised when the underlying emulator fails.

    This wraps known exceptions thrown by an Emulator.

    Arguments:
        exception: The original exception thrown.
    """

    def __init__(self, exception: Exception):
        self.exception = exception

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.exception})"


class AnalysisError(Error):
    """Some kind of error in analysis."""


__all__ = [
    "Error",
    "ConfigurationError",
    "EmulationError",
    "EmulationStop",
    "EmulationBounds",
    "EmulationExitpoint",
    "EmulationException",
    "SymbolicValueError",
    "UnsatError",
    "EmulationFailure",
    "EmulationExecFailure",
    "EmulationExecInvalidFailure",
    "EmulationExecExceptionFailure",
    "EmulationMemoryFailure",
    "EmulationReadFailure",
    "EmulationReadUnmappedFailure",
    "EmulationReadProtectedFailure",
    "EmulationReadUnalignedFailure",
    "EmulationWriteFailure",
    "EmulationWriteUnmappedFailure",
    "EmulationWriteProtectedFailure",
    "EmulationWriteUnalignedFailure",
    "EmulationFetchFailure",
    "EmulationFetchUnmappedFailure",
    "EmulationFetchProtectedFailure",
    "EmulationFetchUnalignedFailure",
    "UnsupportedRegisterError",
    "AnalysisError",
]
