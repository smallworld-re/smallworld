#!/usr/bin/env python3
import argparse
import logging

from smallworld import cpus, emulators, utils
from smallworld.analyses.angr_nwbt import AngrNWBTAnalysis


def parseint(val):
    if val.startswit("0x"):
        return int(val[2:], 16)
    else:
        return int(val)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--base", type=parseint, default=0x10000000)
    parser.add_argument("-e", "--entry", type=parseint)
    parser.add_argument("-A", "--arch", default="x86_64")
    parser.add_argument("-F", "--fmt", default="blob")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("infile")

    args = parser.parse_args()
    if args.fmt == "blob" and args.entry is None:
        # Blobs need entrypoints
        args.entry = 0
    if args.entry is not None:
        # Make entrypoints load-point relative
        args.entry += args.base
    return args


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        utils.setup_logging(level=logging.DEBUG)
        # Silence angr's logger; it's too verbose.
        logging.getLogger("angr").setLevel(logging.INFO)
    else:
        utils.setup_logging(level=logging.INFO)
    log = logging.getLogger("smallworld")

    target = emulators.Code.from_filepath(
        args.infile, type=args.fmt, arch=args.arch, base=args.base, entry=args.entry
    )

    # I want an ability to assign types to Values in the state.
    # How do I do this without making it cumbersome for everyone else?
    # How do I give benefit to anyone else?
    # How do I

    cpu = cpus.AMD64CPUState()

    analysis = AngrNWBTAnalysis()
    analysis.run(target, cpu)
