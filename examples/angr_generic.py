#!/usr/bin/env python3
import argparse
import logging
import pathlib
from smallworld.executors import AngrNWBTExecutor
from smallworld.utils import setup_logging


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
    parser.add_argument("infile", type=pathlib.Path)

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
        setup_logging(level=logging.DEBUG)
        # Silence angr's logger; it's too verbose.
        logging.getLogger("angr").setLevel(logging.INFO)
    else:
        setup_logging(level=logging.INFO)

    driver = AngrNWBTExecutor(args.fmt, args.arch)
    driver.load(args.infile.read_bytes(), args.base, entrypoint=args.entry)
    driver.run()
