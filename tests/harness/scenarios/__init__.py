from __future__ import annotations

from typing import Optional, Sequence

from .registry import HANDLERS


def maybe_run_registered_case(
    scenario: str,
    variant: str,
    args: Sequence[str],
) -> Optional[int]:
    for handler in HANDLERS:
        if handler.can_run(scenario, variant):
            return handler.run_case(scenario, variant, args)
    return None
