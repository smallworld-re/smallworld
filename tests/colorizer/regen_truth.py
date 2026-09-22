#!/usr/bin/env python3
"""Regenerate the recorded expected results for colorizer scenarios.

    python regen_truth.py                     # every test_colorizer_*.py
    python regen_truth.py test_colorizer_1.py # just one

Re-runs a scenario and rewrites its `truth/<scenario>.json`. The
arguments to run with are read out of the scenario's own `test(...)`
call, so this cannot drift from what the test actually does, and a new
scenario is picked up with no edit here.

`all_pcs` -- the set of pcs the traces visit -- is reported but not
silently replaced: a change there means execution took a different
path, which is a different event from the hints about those
instructions changing, and worth looking at rather than absorbing.
Pass --allow-pc-change to record it anyway.
"""

import argparse
import ast
import glob
import os
import sys

os.environ.setdefault("PYTHONBREAKPOINT", "0")

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import truth_data  # noqa: E402
from colorizer_test import test  # noqa: E402

from smallworld.hinting.hints import (  # noqa: E402
    DynamicMemoryValueSummaryHint,
    DynamicRegisterValueSummaryHint,
    TraceExecutionHint,
)


def scenario_args(path):
    """The arguments a scenario passes to test(), read from its source."""
    tree = ast.parse(open(path).read())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "test"
        ):
            # Constant expressions like `0x80 + 1` are not literals, so
            # compile each argument rather than using literal_eval.
            return [
                eval(  # noqa: S307 - our own test source, constants only
                    compile(ast.Expression(a), path, "eval"), {"__builtins__": {}}
                )
                for a in node.args
            ]
    raise SystemExit(f"{path}: no test(...) call found")


def regenerate(path, allow_pc_change=False):
    scenario = os.path.splitext(os.path.basename(path))[0]
    args = scenario_args(path)
    print(f"{scenario}: running test{tuple(args)}")

    derivations, hints = test(*args)

    all_pcs = set()
    summ = {}
    for h in hints:
        if type(h) is TraceExecutionHint:
            for te in h.trace:
                all_pcs.add(te.pc)
        elif type(h) in (
            DynamicMemoryValueSummaryHint,
            DynamicRegisterValueSummaryHint,
        ):
            summ.setdefault(h.pc, []).append(h)

    try:
        old_pcs, _, _ = truth_data.load(scenario)
    except FileNotFoundError:
        old_pcs = all_pcs
    if old_pcs != all_pcs and not allow_pc_change:
        raise SystemExit(
            f"{scenario}: the trace itself changed -- "
            f"only in truth: {sorted(old_pcs - all_pcs)}, "
            f"only in this run: {sorted(all_pcs - old_pcs)}\n"
            f"Check that this is intended, then rerun with --allow-pc-change."
        )

    out = truth_data.save(scenario, all_pcs, summ, derivations)
    print(
        f"{scenario}: {len(all_pcs)} pcs, {sum(map(len, summ.values()))} hints, "
        f"{len(derivations)} derivations -> {os.path.relpath(out, HERE)}"
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenarios", nargs="*", help="scenario files (default: all)")
    ap.add_argument(
        "--allow-pc-change",
        action="store_true",
        help="record new expected results even if the trace's pcs changed",
    )
    args = ap.parse_args()

    paths = args.scenarios or sorted(
        glob.glob(os.path.join(HERE, "test_colorizer_*.py"))
    )
    for path in paths:
        regenerate(path, args.allow_pc_change)


if __name__ == "__main__":
    main()
