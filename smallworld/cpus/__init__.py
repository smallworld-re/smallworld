import inspect
import typing

from ..state import CPU
from .amd64 import AMD64CPUState
from .i386 import i386CPUState
from .pcode import PcodeCPUState


def for_arch(arch: str, mode: str):
    """Find the appropriate CPU state for your architecture

    Arguments:
        arch: The Capstone architecture ID you want
        mode: The Capstone mode ID you want

    Returns:
        An instance of the appropriate CPU subclass

    Raises:
        ValueError: If no CPU subclass matches your request
    """

    # Traverse all subclasses of CPU.
    class_stack: typing.List[typing.Type[CPU]] = list(CPU.__subclasses__())
    while len(class_stack) > 0:
        impl: typing.Type[CPU] = class_stack.pop(-1)
        if inspect.isabstract(impl):
            # Avoid abstract base classes
            continue
        if impl.arch == arch and impl.mode == mode:
            return impl()
        # __subclasses__ is not transitive.
        # Need to do a full traversal.
        class_stack.extend(impl.__subclasses__())
    raise ValueError(f"No CPU model for {arch}:{mode}")


__all__ = [
    "for_arch",
    "i386CPUState",
    "AMD64CPUState",
    "PcodeCPUState",
    "Sparc64CPUState",
]
