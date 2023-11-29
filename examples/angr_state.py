#!/usr/bin/env python3
import argparse
import logging
import pathlib
from smallworld.executors import AngrNWBTExecutor
from smallworld.state import Memory
from smallworld.cpus.amd64 import AMD64CPUState
from smallworld.initializer import OSRandomInitializer


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


class AngrAMD64State(AMD64CPUState):
    log = logging.getLogger("smallworld.state")

    def __init__(self, executor, stack_below=0x1000, stack_above=0x0, heap_size=0x1000):
        # Load control registers and other sensitive state from angr.
        # I really don't want to know what happens if you mess with these.
        self.fs.load(executor)
        self.gs.set(0)
        self.cr0.set(0)
        self.cr2.set(0)
        self.cr3.set(0)
        self.cr4.set(0)
        self.eflags.load(executor)

        # RSP is part of angr's stack model.
        # By default, let's load it from there.
        self.rsp.load(executor)

        stack_start = self.rsp.get() - stack_above
        stack_size = stack_below + stack_above
        self.log.debug(
            f"Stack allocated from {stack_start:x} to {stack_start + stack_size:x}"
        )
        self.stack = Memory(stack_start, stack_size)

        # Unfortunately, there is no nice register for the heap break.
        heap_start = executor.entry.heap.heap_base
        executor.entry.heap.allocate(heap_size)
        self.log.debug(
            f"Heap allocated from {heap_start:x} to {heap_start + heap_size:x}"
        )
        self.heap = Memory(heap_start, heap_size)
        super().__init__(stackaddress=stack_start, stacksize=stack_size)


if __name__ == "__main__":
    args = parse_args()
    log = logging.getLogger("smallworld")
    if args.verbose:
        log.setLevel("DEBUG")
    else:
        log.setLevel("INFO")

    devrandom = OSRandomInitializer()

    driver = AngrNWBTExecutor(**vars(args))

    state = AngrAMD64State(driver)
    state.initialize(devrandom)
    state.apply(driver)

    driver.run()
