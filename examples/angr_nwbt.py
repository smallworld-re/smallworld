#!/usr/bin/env python3
import argparse
import logging

from smallworld import executable
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
        setup_logging(level=logging.DEBUG)
        # Silence angr's logger; it's too verbose.
        logging.getLogger("angr").setLevel(logging.INFO)
    else:
        setup_logging(level=logging.INFO)
    log = logging.getLogger("smallworld")

    target = executable.Executable.from_filepath(
        args.infile, base=args.base, entry=args.entry
    )

    driver = AngrNWBTExecutor(args.arch)
    driver.load(target)

    environ = driver.entry.typedefs

    # Example of using an unnamed primitive type
    intdef = environ.create_primitive(None, 4)
    # Example of using a named primitive type
    longdef = environ.create_primitive("arg2", 8)
    # Example of a struct
    nodedef = environ.create_struct("node")
    # Example of a pointer
    ptrdef = environ.create_pointer(nodedef)

    # This example handles two of the test cases,
    # each with slightly different node structures.
    # Yes, this is a silly way to handle this.

    if args.infile.name == "struct.bin":
        nodedef.add_field("data", intdef)
        nodedef.add_field("padding", intdef)
        nodedef.add_field("prev", ptrdef)
        nodedef.add_field("next", ptrdef)
        nodedef.add_field("empty", intdef)
    elif args.infile.name == "tree.bin":
        nodedef.add_field("data", intdef)
        nodedef.add_field("padding", intdef)
        nodedef.add_field("lo", ptrdef)
        nodedef.add_field("hi", ptrdef)
    else:
        log.error(f"Test case {args.infile.name} not supported")
        log.error("Please use struct.bin or tree.bin")
        quit()

    environ.bind_register("rdi", ptrdef)
    environ.bind_register("rsi", longdef)

    driver.run()
