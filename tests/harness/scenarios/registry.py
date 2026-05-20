from __future__ import annotations

import importlib
import os
import pkgutil

_SCENARIOS_DIR = os.path.dirname(__file__)
_SELF_NAME = "registry"


def _discover() -> tuple[tuple[tuple[str, str, object], ...], tuple[object, ...]]:
    entries: list[tuple[str, str, object]] = []
    handlers_seen: list[object] = []
    names = sorted(info.name for info in pkgutil.iter_modules([_SCENARIOS_DIR]))
    for name in names:
        if name == _SELF_NAME:
            continue
        module = importlib.import_module(f"{__package__}.{name}")
        prefixes = getattr(module, "SCENARIO_PREFIXES", None)
        if not prefixes:
            continue
        for prefix, scenario in prefixes:
            entries.append((prefix, scenario, module))
        if module not in handlers_seen:
            handlers_seen.append(module)
    return tuple(entries), tuple(handlers_seen)


REGISTERED_SCENARIOS, HANDLERS = _discover()
