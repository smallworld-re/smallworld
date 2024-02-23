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
    arg1def = environ.create_primitive("arg1", 8)
    arg3def = environ.create_primitive("arg3", 8)
    arg5def = environ.create_primitive("arg5", 8)

    # Bind types to initial state
    environ.bind_register("rdi", arg1def)
    environ.bind_register("rdx", arg3def)
    environ.bind_register("r8", arg5def)


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
    args = parse_args(["./tests/stack.bin"])
    if args.verbose:
        utils.setup_logging(level=logging.DEBUG)
        # Silence angr's logger; it's too verbose.
        logging.getLogger("angr").setLevel(logging.INFO)
    else:
        utils.setup_logging(level=logging.INFO)
        utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

    log = logging.getLogger("smallworld")

    target = state.Code.from_filepath(
        args.infile, type=args.fmt, arch=args.arch, base=args.base, entry=args.entry
    )

    cpu = cpus.AMD64CPUState()
    cpu.map(target)
    analysis = AngrNWBTAnalysis(initfunc=angr_init)
    analysis.run(cpu)
