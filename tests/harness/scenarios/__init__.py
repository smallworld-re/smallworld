from __future__ import annotations

from typing import Optional, Sequence

from . import (
    branch,
    call,
    checked_heap,
    dma,
    exitpoint,
    fuzz,
    recursion,
    square,
    stack,
    static_buf,
    strlen,
    unmapped,
)


_HANDLERS = (
    square,
    branch,
    call,
    dma,
    recursion,
    stack,
    strlen,
    static_buf,
    exitpoint,
    unmapped,
    checked_heap,
    fuzz,
)


def maybe_run_registered_case(
    scenario: str,
    variant: str,
    args: Sequence[str],
) -> Optional[int]:
    for handler in _HANDLERS:
        if handler.can_run(scenario, variant):
            return handler.run_case(scenario, variant, args)
    return None
