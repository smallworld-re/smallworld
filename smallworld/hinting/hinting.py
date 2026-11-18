import copy
import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Dict, List, Type

logger = logging.getLogger(__name__)


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
        self.callbacks: Dict[Type[Hint], List[Callable[[Hint], None]]] = {}

    def register(self, clazz: Type[Hint], callback: Callable[[Hint], None]):
        if clazz not in self.callbacks:
            self.callbacks[clazz] = []
        self.callbacks[clazz].append(callback)

    def send(self, hint: Hint) -> None:
        # send() is on the emulation/analysis hot path. Serializing the hint is
        # only needed for the DEBUG log line, so skip the asdict()/json.dumps()
        # work entirely unless DEBUG output is enabled.
        if logger.isEnabledFor(logging.DEBUG):
            try:
                logger.debug(json.dumps(asdict(hint)))
            except Exception:
                # Narrow to Exception so a KeyboardInterrupt/SystemExit raised
                # mid-serialization is not swallowed.
                logger.debug(hint.to_json())  # type: ignore

        clazz = hint.__class__
        if clazz in self.callbacks:
            for callback in self.callbacks[clazz]:
                callback(copy.deepcopy(hint))


__all__ = ["Hint", "Hinter"]
