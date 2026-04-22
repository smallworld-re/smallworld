#!/usr/bin/env python3

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness.framework import (
    managed_output_logger,
    run_cases,
    stable_shards,
    summaries_json,
)
from harness.manifest import all_cases


def _matches(case_id: str, tags: tuple[str, ...], filters: list[str]) -> bool:
    if not filters:
        return True
    haystacks = [case_id, *tags]
    for pattern in filters:
        if any(pattern in haystack for haystack in haystacks):
            return True
        try:
            compiled = re.compile(pattern)
        except re.error:
            compiled = None
        if compiled and any(compiled.search(haystack) for haystack in haystacks):
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manifest-driven integration runner for SmallWorld.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Print each case as it runs"
    )
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        help="Substring or regex used to keep matching case ids or tags",
    )
    parser.add_argument(
        "--list", action="store_true", help="List cases instead of running them"
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for `--list`",
    )
    parser.add_argument(
        "--output-log",
        type=pathlib.Path,
        help="Write runner output and captured subprocess output to this file",
    )
    parser.add_argument("--shard-index", type=int, help="Shard to run, zero-based")
    parser.add_argument("--shard-count", type=int, help="Total number of shards")
    ns = parser.parse_args()
    log_path = ns.output_log.expanduser().resolve() if ns.output_log else None

    with managed_output_logger(log_path) as logger:
        cases = [
            case for case in all_cases() if _matches(case.id, case.tags, ns.filter)
        ]

        if ns.shard_index is not None or ns.shard_count is not None:
            if ns.shard_index is None or ns.shard_count is None:
                raise SystemExit(
                    "both --shard-index and --shard-count are required together"
                )
            if ns.shard_count <= 0:
                raise SystemExit("--shard-count must be greater than zero")
            if ns.shard_index < 0 or ns.shard_index >= ns.shard_count:
                raise SystemExit("--shard-index must be in [0, --shard-count)")
            shards = stable_shards(cases, ns.shard_count)
            cases = shards[ns.shard_index]

        if ns.list:
            if ns.format == "json":
                print(summaries_json(cases))
            else:
                for case in cases:
                    status = f" SKIP={case.skip_reason}" if case.skip_reason else ""
                    tags = ",".join(case.tags)
                    print(f"{case.id}\t{tags}{status}")
            return 0

        if not cases:
            print("No integration cases matched the current selection.")
            return 0

        return run_cases(cases, verbose=ns.verbose, output_logger=logger)


if __name__ == "__main__":
    raise SystemExit(main())
