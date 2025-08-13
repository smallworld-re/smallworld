import copy
from collections.abc import Callable
from dataclasses import dataclass
from typing import Dict, Type


@dataclass(frozen=True)
class Hint:
    """Base class for all Hints.

    Arguments:
        message: A message for this Hint.
    """

    message: str
    """A detailed description."""


class Hinter:
    def __init__(self) -> None:
        self.callbacks: Dict[Type[Hint], Callable[[Hint], None]] = {}

    def register(self, clazz: Type[Hint], callback: Callable[[Hint], None]):
        if clazz not in self.callbacks:
            self.callbacks[clazz] = []
        self.callbacks[clazz].append(callback)

    def send(self, hint: Hint) -> None:
        clazz = hint.__class__
        if clazz in self.callbacks:
            for callback in self.callbacks[clazz]:
                callback(copy.deepcopy(hint))


__all__ = ["Hint", "Hinter"]
