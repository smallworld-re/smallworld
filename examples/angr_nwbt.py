#!/usr/bin/env python3
import argparse
import logging

from smallworld import cpus, state, utils
from smallworld.analyses.angr_nwbt import AngrNWBTAnalysis


def parseint(val):
    if val.startswit("0x"):
        return int(val[2:], 16)
    else:
        return int(val)


def angr_init(analysis, entry):
    # Initialize type bindings for state.
    #
    # The way I currently have this set up,
    # it needs access to the entrypoint state
    # created by the AngrEmnulator class.
    #
    # TODO: Move this annotation into the State object.
    # This needs a good deal of though WRT how to integrate
    # without dumping a bunch of angr-specific code into State.

    environ = entry.typedefs
    # Example of using an unnamed primitive type
    intdef = environ.create_primitive(None, 4)
    # Example of using a named primitive type
    longdef = environ.create_primitive("arg2", 8)
    # Example of a struct
    nodedef = environ.create_struct("node")
    # Example of a pointer
    ptrdef = environ.create_pointer(nodedef)

    # Populate struct fields
    nodedef.add_field("data", intdef)
    nodedef.add_field("padding", intdef)
    nodedef.add_field("prev", ptrdef)
    nodedef.add_field("next", ptrdef)
    nodedef.add_field("empty", intdef)

    # Bind types to initial state
    environ.bind_register("rdi", ptrdef)
    environ.bind_register("rsi", longdef)


def parse_args(argvec):
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--base", type=parseint, default=0x10000000)
    parser.add_argument("-e", "--entry", type=parseint)
    parser.add_argument("-A", "--arch", default="x86_64")
    parser.add_argument("-F", "--fmt", default="blob")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("infile")

    if argvec is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(argvec)
    if args.fmt == "blob" and args.entry is None:
        # Blobs need entrypoints
        args.entry = 0
    if args.entry is not None:
        # Make entrypoints load-point relative
        args.entry += args.base
    return args


if __name__ == "__main__":
    # Load the 'struct.bin' test.  Default args.
    args = parse_args(["./tests/struct.bin"])
    if args.verbose:
        utils.setup_logging(level=logging.DEBUG)
        # Silence angr's logger; it's too verbose.
        logging.getLogger("angr").setLevel(logging.INFO)
    else:
        utils.setup_logging(level=logging.INFO)
    log = logging.getLogger("smallworld")

    target = state.Code.from_filepath(
        args.infile, type=args.fmt, arch=args.arch, base=args.base, entry=args.entry
    )

    # I want an ability to assign types to Values in the state.
    # How do I do this without making it cumbersome for everyone else?
    # How do I give benefit to anyone else?
    # How do I

    cpu = cpus.AMD64CPUState()
    cpu.map(target)

    analysis = AngrNWBTAnalysis(initfunc=angr_init)
    analysis.run(cpu)
