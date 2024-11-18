import logging
import typing

from .. import hinting


class HintSubclassFilter(logging.Filter):
    """A custom logging filter based on Hint class."""

    def __init__(self, hint: typing.Type[hinting.Hint], *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.hint = hint

    def filter(self, record):
        return isinstance(record.msg, self.hint)


__all__ = ["HintSubclassFilter"]
