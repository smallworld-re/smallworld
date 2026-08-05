"""Shared helpers for the taint-tracking integration scenarios."""

from __future__ import annotations

from typing import Any, List

# Engine name -> emulator class attribute on ``smallworld.emulators``.
ENGINE_CLASS = {
    "unicorn": "UnicornEmulator",
    "panda": "PandaEmulator",
    "styx": "StyxEmulator",
    "angr": "AngrEmulator",
    "pcode_symbolic": "GhidraSymbolicEmulator",
}

# Backends that propagate taint concretely via the shared TaintTracker.
CONCRETE_ENGINES = ("unicorn", "panda", "styx")

# Backends where taint is derived from symbolic-expression variables. They
# handle a concrete pointer but complicate a symbolic (labeled) pointer.
SYMBOLIC_ENGINES = ("angr", "pcode_symbolic")


def make_taint_emulator(
    smallworld: Any,
    engine: str,
    platform: Any,
    *,
    taint: bool = True,
    taint_addresses: bool = False,
) -> Any:
    """Construct a taint-enabled emulator for ``engine``."""
    cls = getattr(smallworld.emulators, ENGINE_CLASS[engine])
    return cls(platform, taint=taint, taint_addresses=taint_addresses)


class Checker:
    """Accumulates pass/fail assertions and renders the harness's expected
    ``EXPECTED``/``UNEXPECTED`` lines, returning a process exit code."""

    def __init__(self) -> None:
        self.failures: List[str] = []

    def check(self, name: str, got: Any, want: Any) -> None:
        ok = got == want
        marker = "EXPECTED" if ok else "UNEXPECTED"
        print(f"{marker}  {name}: got={got!r} want={want!r}")
        if not ok:
            self.failures.append(name)

    def check_true(self, name: str, cond: bool, detail: str = "") -> None:
        marker = "EXPECTED" if cond else "UNEXPECTED"
        print(f"{marker}  {name}: {detail}")
        if not cond:
            self.failures.append(name)

    def result(self) -> int:
        if self.failures:
            print(f"UNEXPECTED  {len(self.failures)} failed: {self.failures}")
            return 1
        print("EXPECTED  No unexpected results")
        return 0
