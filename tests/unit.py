import contextlib
import copy
import ctypes
import importlib.util
import io
import json
import logging
import os
import pathlib
import re
import signal
import struct
import subprocess
import sys
import tempfile
import types
import typing
import unittest
from types import SimpleNamespace
from unittest import mock

import capstone
import claripy
import lief
import unicorn
from harness.coverage import wrap_python_command
from harness.framework import (
    CaseRunner,
    CaseSpec,
    DetailedCalledProcessError,
    managed_output_logger,
    run_cases,
    stable_shards,
    summaries_json,
)
from harness.scenarios import fuzz as fuzz_scenario
from harness.scenarios import static_buf as static_buf_scenario

from smallworld import emulators, exceptions, helpers, hinting, platforms, state, utils
from smallworld.analyses import trace_execution
from smallworld.analyses.colorizer_read_write import (
    ColorizerReadWrite,
    MemLvalDvKey,
    MemoryLvalInfo,
    RegDvKey,
    RegisterInfo,
    WRGraph,
)
from smallworld.analyses.colorizer_summary import ColorizerSummary
from smallworld.analyses.crash_triage.printer import CrashTriagePrinter
from smallworld.analyses.field_detection import field_analysis
from smallworld.analyses.field_detection.hints import UnknownFieldHint
from smallworld.analyses.field_detection.malloc import MallocModel
from smallworld.analyses.trace_execution_types import TraceElement, TraceRes
from smallworld.analyses.unstable.pointer_finder import PointerFinder
from smallworld.arch import amd64_arch
from smallworld.emulators.angr.exceptions import PathTerminationSignal
from smallworld.emulators.unicorn.machdefs.ppc import PPC64MachineDef, PPCMachineDef
from smallworld.extern.ctypes import TypedPointer, create_typed_pointer
from smallworld.hinting import (
    DynamicMemoryValueHint,
    DynamicRegisterValueHint,
    MemoryUnavailableHint,
    MemoryUnavailableSummaryHint,
)
from smallworld.hinting.hints import (
    MemoryPointerHint,
    MemoryPointsToHint,
    PointerHint,
    RegisterPointerHint,
    TraceExecutionHint,
)
from smallworld.instructions import Instruction, RegisterOperand
from smallworld.instructions.bsid import BSIDMemoryReferenceOperand
from smallworld.state.memory.code import Executable
from smallworld.state.memory.elf.rela.i386 import I386ElfRelocator
from smallworld.state.memory.elf.structs import ElfRela, ElfSymbol
from smallworld.state.memory.heap import BumpAllocator
from smallworld.state.memory.heap import BumpAllocator as _AnalysesBumpAllocator
from smallworld.state.memory.stack.amd64 import AMD64Stack
from smallworld.state.models.aarch64.systemv.systemv import AArch64SysVCallingContext
from smallworld.state.models.amd64.systemv.systemv import AMD64SysVCallingContext
from smallworld.state.models.c99.libc import C99Libc
from smallworld.state.models.c99.stdio import Freopen, Vsprintf, Vsscanf
from smallworld.state.models.c99.utils import _emu_memcmp, _emu_strncmp, _emu_strnlen
from smallworld.state.models.cstd import ArgumentType
from smallworld.state.models.filedesc import BytesIO as SWBytesIO
from smallworld.state.models.filedesc import FileDescriptorManager
from smallworld.state.models.mips64.systemv.systemv import MIPS64SysVCallingContext
from smallworld.state.models.mips64el.systemv.systemv import (
    MIPS64ELSysVCallingContext,
)
from smallworld.state.models.mips.systemv.systemv import MIPSSysVCallingContext
from smallworld.state.models.model import Model
from smallworld.state.models.posix.filedesc import SockaddrIn, SocketIO
from smallworld.state.models.posix.filedesc.sockaddr import SockaddrIn6
from smallworld.state.models.posix.procinfo import ProcInfoManager
from smallworld.state.models.riscv64.systemv.systemv import RiscV64SysVCallingContext

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)

TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent


def _load_local_module(module_name: str, filename: str) -> types.ModuleType:
    module_path = TESTS_DIR / filename
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Failed loading module spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MockConcreteEmulator(emulators.Emulator):
    pass


class assertTimeout:
    """Raise if the enclosed block takes longer than the given timeout.

    This should be used as a context manager.

    Arguments:
        timeout: Maximum time in seconds.
        message: Error message.

    Raises:
        `AssertionError` if the enclosed block takes longer than `timeout`
        seconds.
    """

    def __init__(self, timeout: int, message: typing.Optional[str] = None):
        if message is None:
            message = f"took too long (>{timeout}s)"

        self.timeout = timeout
        self.message = message

    def handle_timeout(self, signum, frame):
        raise AssertionError(self.message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.timeout)

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)


class StateTests(unittest.TestCase):
    def assertClaripyEqual(self, actual, expected, msg=None):
        if not isinstance(actual, claripy.ast.bv.BV):
            self.fail(msg=f"Actual value {actual} is not a bitvector expression")

        if not isinstance(expected, claripy.ast.bv.BV):
            self.fail(msg=f"Expected value {expected} is not a bitvector expression")
        if msg is None:
            msg = f"Expected {expected}, but got {actual}"
        return self.assertTrue(expected.structurally_match(actual), msg=msg)

    def test_register_assignment(self):
        foo = state.Register("foo", 4)
        foo_c = 0xAAAAAAAA
        foo_v = claripy.BVV(foo_c, 32)
        foo_s = claripy.BVS("foo", 32, explicit_name=True)
        bad_s = claripy.BVS("bad", 1)

        # Integer without label
        foo.set(foo_c)
        foo.set_label(None)
        self.assertEqual(foo.get(), foo_c)
        self.assertClaripyEqual(foo.to_symbolic(platforms.Byteorder.BIG), foo_v)

        # Integer with label
        foo.set(foo_c)
        foo.set_label("foo")
        self.assertEqual(foo.get(), foo_c)
        self.assertClaripyEqual(foo.to_symbolic(platforms.Byteorder.BIG), foo_s)

        # Symbolic without label
        foo.set(foo_v)
        foo.set_label(None)
        self.assertClaripyEqual(foo.get(), foo_v)
        self.assertClaripyEqual(foo.to_symbolic(platforms.Byteorder.BIG), foo_v)

        # Sybolic with label
        foo.set(foo_v)
        foo.set_label("foo")
        self.assertClaripyEqual(foo.get(), foo_v)
        self.assertClaripyEqual(foo.to_symbolic(platforms.Byteorder.BIG), foo_s)

        # Invalid symbolic value
        with self.assertRaises(ValueError):
            foo.set(bad_s)

    def test_register_aliasing(self):
        foo = state.Register("foo", 4)
        bar = state.RegisterAlias("bar", foo, 2, 2)
        foo_c = 0xAAAAAAAA
        bar_c = 0xBBBB
        foo_v = claripy.BVV(foo_c, 32)
        bar_v = claripy.BVV(bar_c, 16)
        foo_s = claripy.BVS("foo", 32)
        bar_s = claripy.BVS("bar", 16)

        # Test integer/integer
        foo.set(foo_c)
        bar.set(bar_c)
        self.assertEqual(foo.get(), (foo_c & 0xFFFF) | (bar_c << 16))
        self.assertEqual(bar.get(), bar_c)

        # Test symbol/integer
        foo.set(foo_s)
        bar.set(bar_c)
        res_s = claripy.Concat(bar_v, foo_s[15:0])

        self.assertClaripyEqual(res_s, foo.get())
        self.assertClaripyEqual(bar_v, bar.get())

        # Test integer/symbol
        foo.set(foo_c)
        bar.set(bar_s)
        res_s = claripy.Concat(bar_s, foo_v[15:0])

        self.assertClaripyEqual(res_s, foo.get())
        self.assertClaripyEqual(bar_s, bar.get())

        # Test symbol/symbol
        foo.set(foo_s)
        bar.set(bar_s)
        res_s = claripy.Concat(bar_s, foo_s[15:0])

        self.assertClaripyEqual(res_s, foo.get())
        self.assertClaripyEqual(bar_s, bar.get())

    def test_memory_write_bytes(self):
        # test write to entire segment
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abcdefgh", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"ABCDEFGH")

        # test write to sub-segment
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abcdefgh", None)
        memory.write_bytes(0x1003, b"DE")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"abcDEfgh")

        # test write split over 2 segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abcd", None)
        memory[4] = state.BytesValue(b"efgh", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"ABCDEFGH")

        # test memory split over 3 segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[3] = state.BytesValue(b"de", None)
        memory[5] = state.BytesValue(b"fgh", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"ABCDEFGH")

        # test write discontinuous
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[5] = state.BytesValue(b"fgh", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"ABCDEFGH")

        # test write discontinuous on ends
        memory = state.memory.Memory(0x1000, 0x8)
        memory[2] = state.BytesValue(b"cde", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"ABCDEFGH")

        # test write overlapping segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[1] = state.BytesValue(b"fgh", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(memory[0].get_content(), b"ABC")
        self.assertEqual(memory[1].get_content(), b"BCD")

        # test write out of bounds
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abcdefgh")
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.write_bytes(0x1000, b"abcdefghijklmnop"),
        )
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.write_bytes(0x0500, b"abcdefghijklmnop"),
        )
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.write_bytes(0x0FFC, b"abcdefgh"),
        )
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.write_bytes(0x1004, b"abcdefgh"),
        )

        # test overwrite IntegerValue bytes
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[3] = state.IntegerValue(0xDEADBEEF, 4, None, platforms.Byteorder.LITTLE)
        memory[7] = state.BytesValue(b"f", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(
            memory.read_bytes(0x1000, 0x8),
            b"ABCDEFGH",
        )

        # test overwrite CTypeValue bytes
        class TestStruct(ctypes.LittleEndianStructure):
            _pack_ = 4
            _fields_ = (("test_field", ctypes.c_int32),)

        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        struct = TestStruct()
        struct.test_field = 0xDEADBEEF
        memory[3] = state.Value.from_ctypes(struct, None)
        memory[7] = state.BytesValue(b"f", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(
            memory.read_bytes(0x1000, 0x8),
            b"ABCDEFGH",
        )
        self.assertEqual(
            memory[3].get_content().test_field, int.from_bytes(b"DEFG", "little")
        )

        # test overwrite SymbolicValue bytes
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[3] = state.SymbolicValue(2, None, None, None)
        memory[5] = state.BytesValue(b"fgh", None)
        self.assertRaises(
            exceptions.SymbolicValueError,
            lambda: memory.read_bytes(0x1000, 0x8),
        )

        # test to_bytes method
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[5] = state.BytesValue(b"fgh", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(memory.to_bytes(), b"ABCDEFGH")

    def test_memory_read_bytes(self):
        # test read entire segment
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abcdefgh", None)
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"abcdefgh")

        # test read sub-segment
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abcdefgh", None)
        self.assertEqual(memory.read_bytes(0x1001, 0x4), b"bcde")

        # test read split over 2 segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abcd", None)
        memory[4] = state.BytesValue(b"efgh", None)
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"abcdefgh")

        # test read split over 3 segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[3] = state.BytesValue(b"de", None)
        memory[5] = state.BytesValue(b"fgh", None)
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"abcdefgh")

        # test read with unused segments and sub-segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"a", None)
        memory[1] = state.BytesValue(b"bcd", None)
        memory[4] = state.BytesValue(b"efg", None)
        memory[7] = state.BytesValue(b"h", None)
        self.assertEqual(memory.read_bytes(0x1002, 0x4), b"cdef")

        # test read discontinuous
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[5] = state.BytesValue(b"fgh", None)
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.read_bytes(0x1000, 0x8),
        )

        # test read discontinuous on ends
        memory = state.memory.Memory(0x1000, 0x8)
        memory[2] = state.BytesValue(b"cde", None)
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.read_bytes(0x1000, 0x8),
        )

        # test read overlapping segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[1] = state.BytesValue(b"fgh", None)
        self.assertEqual(memory.read_bytes(0x1000, 0x4), b"abch")

        # test read out of bounds
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abcdefgh")
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.read_bytes(0x1000, 0x10),
        )
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.read_bytes(0x500, 0x8),
        )
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.read_bytes(0x0FFC, 0x8),
        )
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.read_bytes(0x1004, 0x8),
        )

        # test read IntegerValue bytes
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[3] = state.IntegerValue(0xDEADBEEF, 4, None, platforms.Byteorder.LITTLE)
        memory[7] = state.BytesValue(b"f", None)
        self.assertEqual(
            memory.read_bytes(0x1000, 0x8),
            b"abc\xef\xbe\xad\xdef",
        )

        # test read CTypeValue bytes
        class TestStruct(ctypes.LittleEndianStructure):
            _pack_ = 4
            _fields_ = (("test_field", ctypes.c_int32),)

        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        struct = TestStruct()
        struct.test_field = 0xDEADBEEF
        memory[3] = state.Value.from_ctypes(struct, None)
        memory[7] = state.BytesValue(b"f", None)
        self.assertEqual(
            memory.read_bytes(0x1000, 0x8),
            b"abc\xef\xbe\xad\xdef",
        )

        # test read SymbolicValue bytes
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[3] = state.SymbolicValue(2, None, None, None)
        memory[5] = state.BytesValue(b"fgh", None)
        self.assertRaises(
            exceptions.SymbolicValueError,
            lambda: memory.read_bytes(0x1000, 0x8),
        )

    def test_memory_read_int(self):
        addr = 0x1000
        memory = state.memory.Memory(addr, 4)
        memory.write_bytes(
            addr,
            int.to_bytes(0b11110000000011111111000000001111, 4, "big"),
        )

        self.assertEqual(memory.read_int(addr, 1, platforms.Byteorder.LITTLE), 240)
        self.assertEqual(memory.read_int(addr, 1, platforms.Byteorder.BIG), 240)
        self.assertEqual(memory.read_int(addr, 2, platforms.Byteorder.LITTLE), 4080)
        self.assertEqual(memory.read_int(addr, 2, platforms.Byteorder.BIG), 61455)
        self.assertEqual(
            memory.read_int(addr, 4, platforms.Byteorder.LITTLE), 267390960
        )
        self.assertEqual(memory.read_int(addr, 4, platforms.Byteorder.BIG), 4027576335)

    def test_memory_write_int(self):
        addr = 0x1000
        memory = state.memory.Memory(addr, 4)

        memory.write_int(addr, 240, 1, platforms.Byteorder.LITTLE)
        self.assertEqual(memory.read_bytes(addr, 1), b"\xf0")
        memory.write_int(addr, 240, 1, platforms.Byteorder.BIG)
        self.assertEqual(memory.read_bytes(addr, 1), b"\xf0")
        memory.write_int(addr, 4080, 2, platforms.Byteorder.LITTLE)
        self.assertEqual(memory.read_bytes(addr, 2), b"\xf0\x0f")
        memory.write_int(addr, 4080, 2, platforms.Byteorder.BIG)
        self.assertEqual(memory.read_bytes(addr, 2), b"\x0f\xf0")
        memory.write_int(addr, 4027576335, 4, platforms.Byteorder.LITTLE)
        self.assertEqual(memory.read_bytes(addr, 4), b"\x0f\xf0\x0f\xf0")
        memory.write_int(addr, 4027576335, 4, platforms.Byteorder.BIG)
        self.assertEqual(memory.read_bytes(addr, 4), b"\xf0\x0f\xf0\x0f")

    def test_memory_ranges_initialized(self):
        # empty memory has no initialized ranges
        memory = state.memory.Memory(0x1000, 0x8)
        self.assertEqual(memory.get_ranges_initialized(), [])

        # single memory region
        memory.write_bytes(memory.address + 1, b"\xff\xff")
        self.assertEqual(
            memory.get_ranges_initialized(),
            [range(memory.address + 1, memory.address + 2)],
        )

        # non-contiguous initialized regions
        memory.write_bytes(memory.address + 6, b"\xff\xff")
        self.assertEqual(
            memory.get_ranges_initialized(),
            [
                range(memory.address + 1, memory.address + 2),
                range(memory.address + 6, memory.address + 7),
            ],
        )

        # contiguous and non-contiguous initialized regions
        memory[3] = state.SymbolicValue(1, None, None, None)
        self.assertEqual(
            memory.get_ranges_initialized(),
            [
                range(memory.address + 1, memory.address + 3),
                range(memory.address + 6, memory.address + 7),
            ],
        )

        # fully initialized
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(
            memory.address,
            b"\xff\xff\xff\xff\xff\xff\xff\xff",
        )
        self.assertEqual(
            memory.get_ranges_initialized(),
            [range(memory.address, memory.address + 7)],
        )

    def test_memory_ranges_uninitialized(self):
        # empty memory has no initialized ranges
        memory = state.memory.Memory(0x1000, 0x8)
        self.assertEqual(
            memory.get_ranges_uninitialized(),
            [range(memory.address, memory.address + 7)],
        )

        # single memory region
        memory.write_bytes(memory.address + 1, b"\xff\xff")
        self.assertEqual(
            memory.get_ranges_uninitialized(),
            [
                range(memory.address, memory.address),
                range(memory.address + 3, memory.address + 7),
            ],
        )

        # non-contiguous initialized regions
        memory.write_bytes(memory.address + 6, b"\xff\xff")
        self.assertEqual(
            memory.get_ranges_uninitialized(),
            [
                range(memory.address, memory.address),
                range(memory.address + 3, memory.address + 5),
            ],
        )

        # contiguous and non-contiguous initialized regions
        memory[3] = state.SymbolicValue(1, None, None, None)
        self.assertEqual(
            memory.get_ranges_uninitialized(),
            [
                range(memory.address, memory.address),
                range(memory.address + 4, memory.address + 5),
            ],
        )

        # fully initialized
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(
            memory.address,
            b"\xff\xff\xff\xff\xff\xff\xff\xff",
        )
        self.assertEqual(
            memory.get_ranges_uninitialized(),
            [],
        )

    def test_memory_ranges_symbolic(self):
        # empty memory has no symbolic ranges
        memory = state.memory.Memory(0x1000, 0x8)
        self.assertEqual(memory.get_ranges_symbolic(), [])

        # single symbolic memory region
        memory[1] = state.SymbolicValue(2, None, None, None)
        self.assertEqual(
            memory.get_ranges_symbolic(),
            [range(memory.address + 1, memory.address + 2)],
        )

        # non-contiguous symbolic regions
        memory[6] = state.SymbolicValue(2, None, None, None)
        self.assertEqual(
            memory.get_ranges_symbolic(),
            [
                range(memory.address + 1, memory.address + 2),
                range(memory.address + 6, memory.address + 7),
            ],
        )

        # contiguous and non-contiguous symbolic regions
        memory[3] = state.SymbolicValue(1, None, None, None)
        self.assertEqual(
            memory.get_ranges_symbolic(),
            [
                range(memory.address + 1, memory.address + 3),
                range(memory.address + 6, memory.address + 7),
            ],
        )

        # gaps filled with bytes values
        memory.write_bytes(memory.address, b"\xff")
        memory.write_bytes(memory.address + 4, b"\xff\xff")
        self.assertEqual(
            memory.get_ranges_symbolic(),
            [
                range(memory.address + 1, memory.address + 3),
                range(memory.address + 6, memory.address + 7),
            ],
        )

        # fully symbolic
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.SymbolicValue(8, None, None, None)
        self.assertEqual(
            memory.get_ranges_symbolic(),
            [range(memory.address, memory.address + 7)],
        )

    def test_memory_ranges_concrete(self):
        # empty memory has no concrete ranges
        memory = state.memory.Memory(0x1000, 0x8)
        self.assertEqual(memory.get_ranges_concrete(), [])

        # single concrete memory region
        memory.write_bytes(memory.address + 1, b"\xff\xff")
        self.assertEqual(
            memory.get_ranges_concrete(),
            [range(memory.address + 1, memory.address + 2)],
        )

        # non-contiguous concrete regions
        memory.write_bytes(memory.address + 6, b"\xff\xff")
        self.assertEqual(
            memory.get_ranges_concrete(),
            [
                range(memory.address + 1, memory.address + 2),
                range(memory.address + 6, memory.address + 7),
            ],
        )

        # contiguous and non-contiguous concrete regions
        memory.write_bytes(memory.address + 3, b"\xff")
        self.assertEqual(
            memory.get_ranges_concrete(),
            [
                range(memory.address + 1, memory.address + 3),
                range(memory.address + 6, memory.address + 7),
            ],
        )

        # gaps filled with symbolic values
        memory[0] = state.SymbolicValue(1, None, None, None)
        memory[4] = state.SymbolicValue(2, None, None, None)
        self.assertEqual(
            memory.get_ranges_concrete(),
            [
                range(memory.address + 1, memory.address + 3),
                range(memory.address + 6, memory.address + 7),
            ],
        )

        # fully concrete initialized
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(
            memory.address,
            b"\xff\xff\xff\xff\xff\xff\xff\xff",
        )
        self.assertEqual(
            memory.get_ranges_concrete(),
            [range(memory.address, memory.address + 7)],
        )


class UtilsTests(unittest.TestCase):
    def test_range_collection_add(self):
        rc = utils.RangeCollection()
        a = (4, 9)
        b = (4, 6)  # entirely contained
        c = (9, 12)  # hitting right bound
        d = (2, 4)  # hitting left bound
        e = (1, 3)  # across left bound
        f = (10, 15)  # across right bound
        rc.add_range(a)
        compare = [(4, 9)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(b)
        compare = [(4, 9)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(c)
        compare = [(4, 12)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(d)
        compare = [(2, 12)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(e)
        compare = [(1, 12)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(f)
        compare = [(1, 15)]
        self.assertEqual(rc.ranges, compare)

        rc.add_value(18)
        self.assertEqual(rc.ranges, [(1, 15), (18, 19)])
        rc.add_value(16)
        self.assertEqual(rc.ranges, [(1, 15), (16, 17), (18, 19)])
        rc.add_value(15)
        self.assertEqual(rc.ranges, [(1, 17), (18, 19)])

    def test_range_collection_missing(self):
        rc = utils.RangeCollection()
        a = rc.get_missing_ranges((1, 3))
        self.assertEqual(a, [(1, 3)])

        start = [(22, 25), (2, 4), (8, 13), (19, 22), (13, 15), (29, 32)]
        for i in start:
            rc.add_range(i)

        self.assertEqual(rc.ranges, [(2, 4), (8, 15), (19, 25), (29, 32)])

        # Inside a range
        a = rc.get_missing_ranges((8, 15))
        self.assertEqual(a, [])
        a = rc.get_missing_ranges((8, 12))
        self.assertEqual(a, [])
        a = rc.get_missing_ranges((9, 15))
        self.assertEqual(a, [])
        a = rc.get_missing_ranges((9, 12))
        self.assertEqual(a, [])

        # Across a range
        a = rc.get_missing_ranges((10, 16))
        self.assertEqual(a, [(15, 16)])
        a = rc.get_missing_ranges((10, 19))
        self.assertEqual(a, [(15, 19)])
        a = rc.get_missing_ranges((10, 26))
        self.assertEqual(a, [(15, 19), (25, 26)])
        a = rc.get_missing_ranges((10, 40))
        self.assertEqual(a, [(15, 19), (25, 29), (32, 40)])

        a = rc.get_missing_ranges((16, 17))
        self.assertEqual(a, [(16, 17)])

    def test_range_collection_removal(self):
        pass

    def test_range_collection_find(self):
        # find closest
        rc = utils.RangeCollection()
        start = [(22, 25), (56, 70), (2, 4), (19, 22), (35, 41)]
        for i in start:
            rc.add_range(i)
        self.assertEqual(rc.ranges, [(2, 4), (19, 25), (35, 41), (56, 70)])

        a, b = rc.find_closest_range(3)
        self.assertEqual(a, (2, 4))
        self.assertEqual(b, True)
        a, b = rc.find_closest_range(8)
        self.assertEqual(a, (2, 4))
        self.assertEqual(b, False)
        a, b = rc.find_closest_range(19)
        self.assertEqual(a, (19, 25))
        self.assertEqual(b, True)
        a, b = rc.find_closest_range(25)
        self.assertEqual(a, (19, 25))
        self.assertEqual(b, False)
        a, b = rc.find_closest_range(1)
        self.assertEqual(a, (2, 4))
        self.assertEqual(b, False)

    def test_range_collection_update(self):
        rc = utils.RangeCollection()
        start = [(3, 4), (19, 25), (35, 41), (56, 70)]
        for i in start:
            rc.add_range(i)
        second = [(1, 2), (5, 10), (20, 26), (30, 36), (70, 72)]
        for i in second:
            rc.add_range(i)
        self.assertEqual(
            rc.ranges, [(1, 2), (3, 4), (5, 10), (19, 26), (30, 41), (56, 72)]
        )

    def test_range_collection_contains(self):
        rc = utils.RangeCollection()
        start = [(22, 25), (56, 70), (2, 4), (19, 22), (35, 41)]
        for i in start:
            rc.add_range(i)
        self.assertEqual(rc.ranges, [(2, 4), (19, 25), (35, 41), (56, 70)])

        a = rc.contains((0, 1))
        self.assertEqual(a, False)
        a = rc.contains((5, 6))
        self.assertEqual(a, False)

        a = rc.contains((1, 2))
        self.assertEqual(a, False)
        a = rc.contains((20, 27))
        self.assertEqual(a, True)
        a = rc.contains((20, 35))
        self.assertEqual(a, True)
        a = rc.contains((25, 27))
        self.assertEqual(a, False)


class CPUTests(unittest.TestCase):
    def run_test(self, platform):
        pdef = platforms.PlatformDef.for_platform(platform)
        cpu = state.cpus.CPU.for_platform(platform)

        all_regs = set(pdef.registers.keys())

        reg: state.Register
        for reg in cpu:
            # Check that the register is supposed to exist
            self.assertTrue(
                reg.name in pdef.registers,
                msg=f"CPU for {platform} has unknown register {reg.name}",
            )

            # Track that we've seen this register
            all_regs.remove(reg.name)

            # Check that CPU byteorder was assigned
            self.assertEqual(reg.byteorder, cpu.platform.byteorder)

            # Check that the name agrees with the CPU attribute
            attr_name = reg.name
            if reg.name[0] in list(map(str, range(0, 10))):
                attr_name = "_" + attr_name
            self.assertTrue(
                hasattr(cpu, attr_name),
                msg=f"Register {reg.name} for platform {platform} is not in the expected attribute",
            )
            actual_name = getattr(cpu, attr_name).name
            self.assertEqual(
                actual_name,
                reg.name,
                msg=f"Expected {reg.name} at CPU attribute {attr_name}, got {actual_name}",
            )

            regdef = pdef.registers[reg.name]

            # Check that the size matches what's expected
            self.assertEqual(
                reg.size,
                regdef.size,
                msg=f"Expected size {regdef.size} for register {reg.name} of platform {platform}; got {reg.size}",
            )
            if isinstance(reg, state.RegisterAlias):
                # Check that the alias should be an alias
                self.assertTrue(
                    isinstance(regdef, platforms.defs.RegisterAliasDef),
                    msg=f"CPU for {platform} defines register {reg.name} as an alias; platform def does not",
                )
                parent = reg.reference

                # Check that the parent matches and exists
                self.assertEqual(
                    parent.name,
                    regdef.parent,
                    msg=f"Expected {reg.name} of {platform} to have parent {regdef.parent}; got {parent.name}",
                )
                self.assertTrue(
                    parent.name in pdef.registers,
                    msg=f"Parent {parent.name} of {reg.name} of {platform} is unknown",
                )

                # Check that the offset is what's expected
                self.assertEqual(
                    reg.offset,
                    regdef.offset,
                    msg=f"Expected {reg.name} of {platform} to have offset {regdef.offset}; got {reg.offset}",
                )
            else:
                # Check that the base register should not be an alias
                self.assertTrue(
                    not isinstance(regdef, platforms.defs.RegisterAliasDef),
                    msg=f"CPU for {platform} defines register {reg.name} as a base; platform def thinks it's an alias",
                )
        self.assertEqual(
            len(all_regs),
            0,
            msg=f"CPU for {platform} did not include the following registers: {all_regs}",
        )

    def test_cpu_aarch64(self):
        platform = platforms.Platform(
            platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_amd64(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_amd64_avx512(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64_AVX512, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_armv5t(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_armv6m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_armv6m_thumb(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_armv7m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_armv7r(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_armv7a(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_i386(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_loongarch64(self):
        platform = platforms.Platform(
            platforms.Architecture.LOONGARCH64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_m68k(self):
        platform = platforms.Platform(
            platforms.Architecture.M68K, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_cpu_mips(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_cpu_mipsel(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_mips64(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_cpu_mips64el(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_msp430(self):
        platform = platforms.Platform(
            platforms.Architecture.MSP430, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_msp430x(self):
        platform = platforms.Platform(
            platforms.Architecture.MSP430X, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_ppc(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_cpu_ppc64(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_cpu_riscv64(self):
        platform = platforms.Platform(
            platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_tricore(self):
        platform = platforms.Platform(
            platforms.Architecture.TRICORE, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_cpu_xtensa(self):
        platform = platforms.Platform(
            platforms.Architecture.XTENSA, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)


class UnicornMachdefTests(unittest.TestCase):
    def run_test(self, platform):
        platdef = platforms.PlatformDef.for_platform(platform)
        machdef = emulators.unicorn.machdefs.UnicornMachineDef.for_platform(platform)

        regs_needed = set(platdef.registers.keys())
        regs_needed -= machdef._registers.keys()
        if platdef.pc_register != "pc":
            regs_needed -= set(["pc"])

        self.assertEqual(
            len(regs_needed),
            0,
            msg=f"Unicorn machine def for {platform} is missing registers {regs_needed}",
        )

        extra_regs = set(machdef._registers.keys())
        extra_regs -= platdef.registers.keys()

        self.assertEqual(
            len(extra_regs),
            0,
            msg=f"Unicorn machine def for {platform} has extra registers {extra_regs}",
        )

        emu = emulators.UnicornEmulator(platform)

        bad_regs = set()
        for reg in platdef.registers.keys():
            try:
                emu.read_register(reg)
            except exceptions.UnsupportedRegisterError:
                continue
            except Exception as e:
                print(f" {reg} {e}")
                bad_regs.add(reg)
        self.assertEqual(
            len(bad_regs),
            0,
            msg=f"Unicorn did not handle the following registers for {platform}: {bad_regs}",
        )

    def test_unicorn_aarch64(self):
        platform = platforms.Platform(
            platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_amd64(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_amd64_avx512(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64_AVX512, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_armv5t(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_armv6m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_armv6m_thumb(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_armv7m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_armv7r(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_armv7a(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_i386(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_m68k(self):
        platform = platforms.Platform(
            platforms.Architecture.M68K, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_unicorn_mips(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_unicorn_mipsel(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_mips64(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_unicorn_mips64el(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_ppc(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_unicorn_ppc64(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_unicorn_riscv64(self):
        platform = platforms.Platform(
            platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_tricore(self):
        platform = platforms.Platform(
            platforms.Architecture.TRICORE, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_unicorn_xtensa(self):
        platform = platforms.Platform(
            platforms.Architecture.XTENSA, platforms.Byteorder.LITTLE
        )
        # Not supported by unicorn
        self.assertRaises(ValueError, self.run_test, platform)


class AngrMachdefTests(unittest.TestCase):
    def run_test(self, platform):
        platdef = platforms.PlatformDef.for_platform(platform)
        machdef = emulators.angr.machdefs.AngrMachineDef.for_platform(platform)

        regs_needed = set(platdef.registers.keys())
        regs_needed -= machdef._registers.keys()
        if platdef.pc_register != "pc":
            regs_needed -= set(["pc"])

        self.assertEqual(
            len(regs_needed),
            0,
            msg=f"Angr machine def for {platform} is missing registers {regs_needed}",
        )

        extra_regs = set(machdef._registers.keys())
        extra_regs -= platdef.registers.keys()

        self.assertEqual(
            len(extra_regs),
            0,
            msg=f"Angr machine def for {platform} has extra registers {extra_regs}",
        )

        emu = emulators.AngrEmulator(platform)
        emu.write_code(0x1000, 0x1000 * b"\x00")
        emu.initialize()
        bad_regs = set()
        for reg in platdef.registers.keys():
            try:
                emu.read_register_symbolic(reg)
            except exceptions.UnsupportedRegisterError:
                continue
            except:
                bad_regs.add(reg)
        self.assertEqual(
            len(bad_regs),
            0,
            msg=f"Angr did not handle the following registers for {platform}: {bad_regs}",
        )

    def test_angr_aarch64(self):
        platform = platforms.Platform(
            platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_amd64(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_amd64_avx512(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64_AVX512, platforms.Byteorder.LITTLE
        )
        # Not supported by angr
        self.assertRaises(ValueError, self.run_test, platform)

    def test_angr_armv5t(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_armv6m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_armv6m_thumb(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_armv7m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_armv7a(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_armv7r(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE
        )
        # Not supported by angr
        self.assertRaises(ValueError, self.run_test, platform)

    def test_angr_i386(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_loongarch64(self):
        platform = platforms.Platform(
            platforms.Architecture.LOONGARCH64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_mips(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_angr_mipsel(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_mips64(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_angr_mips64el(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_msp430(self):
        platform = platforms.Platform(
            platforms.Architecture.MSP430, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_msp430x(self):
        platform = platforms.Platform(
            platforms.Architecture.MSP430X, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_ppc(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_angr_ppc64(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_angr_riscv64(self):
        platform = platforms.Platform(
            platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_tricore(self):
        platform = platforms.Platform(
            platforms.Architecture.TRICORE, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_angr_xtensa(self):
        platform = platforms.Platform(
            platforms.Architecture.XTENSA, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)


class PandaMachdefTests(unittest.TestCase):
    def run_test(self, platform):
        platdef = platforms.PlatformDef.for_platform(platform)
        machdef = emulators.panda.machdefs.PandaMachineDef.for_platform(platform)

        regs_needed = set(platdef.registers.keys())
        regs_needed -= machdef._registers.keys()
        regs_needed = set(filter(lambda x: not x.startswith("spr_"), regs_needed))
        if platdef.pc_register != "pc":
            regs_needed -= set(["pc"])

        self.assertEqual(
            len(regs_needed),
            0,
            msg=f"Panda machine def for {platform} is missing registers {regs_needed}",
        )

        extra_regs = set(machdef._registers.keys())
        extra_regs -= platdef.registers.keys()

        self.assertEqual(
            len(extra_regs),
            0,
            msg=f"Panda machine def for {platform} has extra registers {extra_regs}",
        )
        # Actually checking the Panda emulator can't happen here,
        # since I can't create multiple Panda emulators in one process
        cwd = os.path.abspath(os.path.dirname(__file__))
        script = cwd + os.sep + "unit-panda.py"
        cmd = ["python3", script, platform.architecture.name, platform.byteorder.name]
        failure = None
        try:
            subprocess.run(
                wrap_python_command(cmd),
                cwd=cwd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            failure = e.stderr.decode()
        if failure is not None:
            self.fail(f"Not all registers for {platform} handled by Panda:\n{failure}")

    def test_panda_aarch64(self):
        platform = platforms.Platform(
            platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_amd64(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_amd64_avx512(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64_AVX512, platforms.Byteorder.LITTLE
        )
        # Not supported by Panda
        self.assertRaises(ValueError, self.run_test, platform)

    def test_panda_armv5t(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_armv6m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_armv6m_thumb(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE
        )
        # Not supported by Panda
        self.assertRaises(ValueError, self.run_test, platform)

    def test_panda_armv7m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_armv7r(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE
        )
        # Not supported by Panda
        self.assertRaises(ValueError, self.run_test, platform)

    def test_panda_armv7a(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_i386(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_mips(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_panda_mipsel(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_mips64(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_panda_mips64el(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_ppc(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_panda_ppc64(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
        )
        # Not supported by Panda
        self.assertRaises(ValueError, self.run_test, platform)

    def test_panda_riscv64(self):
        platform = platforms.Platform(
            platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
        )
        # Not supported by Panda
        self.assertRaises(ValueError, self.run_test, platform)

    def test_panda_tricore(self):
        platform = platforms.Platform(
            platforms.Architecture.TRICORE, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_panda_xtensa(self):
        platform = platforms.Platform(
            platforms.Architecture.XTENSA, platforms.Byteorder.LITTLE
        )
        # Not supported by Panda
        self.assertRaises(ValueError, self.run_test, platform)


class GhidraMachdefTests(unittest.TestCase):
    def run_test(self, platform):
        platdef = platforms.PlatformDef.for_platform(platform)
        emu = emulators.ghidra.GhidraEmulator(platform)

        # Due to import issues, you can't access GhidraMachineDef directly
        machdef = emu.machdef

        regs_needed = set(platdef.registers.keys())
        regs_needed -= machdef._registers.keys()
        if platdef.pc_register != "pc":
            regs_needed -= set(["pc"])

        self.assertEqual(
            len(regs_needed),
            0,
            msg=f"Ghidra machine def for {platform} is missing registers {regs_needed}",
        )

        extra_regs = set(machdef._registers.keys())
        extra_regs -= platdef.registers.keys()

        self.assertEqual(
            len(extra_regs),
            0,
            msg=f"Ghidra machine def for {platform} has extra registers {extra_regs}",
        )

        bad_regs = set()
        for reg in platdef.registers.keys():
            try:
                emu.read_register(reg)
            except exceptions.UnsupportedRegisterError:
                continue
            except:
                bad_regs.add(reg)
        self.assertEqual(
            len(bad_regs),
            0,
            msg=f"Ghidra did not handle the following registers for {platform}: {bad_regs}",
        )

    def test_ghidra_aarch64(self):
        platform = platforms.Platform(
            platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_amd64(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_amd64_avx512(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64_AVX512, platforms.Byteorder.LITTLE
        )
        # Not supported by ghidra
        self.assertRaises(ValueError, self.run_test, platform)

    def test_ghidra_armv5t(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_armv6m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_armv6m_thumb(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE
        )
        # Not supported by ghidra
        self.assertRaises(ValueError, self.run_test, platform)

    def test_ghidra_armv7m(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_armv7a(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_armv7r(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE
        )
        # Not supported by ghidra
        self.assertRaises(ValueError, self.run_test, platform)

    def test_ghidra_i386(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_loongarch64(self):
        platform = platforms.Platform(
            platforms.Architecture.LOONGARCH64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_m68k(self):
        platform = platforms.Platform(
            platforms.Architecture.M68K, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_ghidra_mips(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_ghidra_mipsel(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_mips64(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_ghidra_mips64el(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_msp430(self):
        platform = platforms.Platform(
            platforms.Architecture.MSP430, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_msp430x(self):
        platform = platforms.Platform(
            platforms.Architecture.MSP430X, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_ppc(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_ghidra_ppc64(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
        )
        self.run_test(platform)

    def test_ghidra_riscv64(self):
        platform = platforms.Platform(
            platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_tricore(self):
        platform = platforms.Platform(
            platforms.Architecture.TRICORE, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)

    def test_ghidra_xtensa(self):
        platform = platforms.Platform(
            platforms.Architecture.XTENSA, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)


class CoverageHarnessTests(unittest.TestCase):
    def test_wrap_python_command_passthrough_when_coverage_disabled(self):
        argv = [sys.executable, "demo.py"]

        self.assertEqual(wrap_python_command(argv, env={}), argv)

    def test_wrap_python_command_skips_non_python_commands(self):
        env = {"SMALLWORLD_COVERAGE": "1"}
        argv = ["afl-showmap", "--help"]

        self.assertEqual(wrap_python_command(argv, env=env), argv)

    def test_wrap_python_command_skips_inline_code(self):
        env = {"SMALLWORLD_COVERAGE": "1"}
        argv = [sys.executable, "-c", "print('demo')"]

        self.assertEqual(wrap_python_command(argv, env=env), argv)

    def test_wrap_python_command_wraps_module_invocation(self):
        env = {
            "SMALLWORLD_COVERAGE": "1",
            "SMALLWORLD_COVERAGE_RCFILE": "/tmp/demo-coveragerc",
        }
        argv = [sys.executable, "-m", "demo.module", "arg"]

        self.assertEqual(
            wrap_python_command(argv, env=env),
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--parallel-mode",
                "--rcfile",
                "/tmp/demo-coveragerc",
                "-m",
                "demo.module",
                "arg",
            ],
        )

    def test_wrap_python_command_preserves_interpreter_flags(self):
        env = {"SMALLWORLD_COVERAGE": "1"}
        argv = [sys.executable, "-B", "-X", "dev", "demo.py", "arg"]

        self.assertEqual(
            wrap_python_command(argv, env=env),
            [
                sys.executable,
                "-B",
                "-X",
                "dev",
                "-m",
                "coverage",
                "run",
                "--parallel-mode",
                "demo.py",
                "arg",
            ],
        )

    def test_wrap_python_command_does_not_double_wrap_coverage(self):
        env = {"SMALLWORLD_COVERAGE": "1"}
        argv = [
            sys.executable,
            "-B",
            "-m",
            "coverage",
            "run",
            "--parallel-mode",
            "demo.py",
        ]

        self.assertEqual(wrap_python_command(argv, env=env), argv)


class FrameworkHarnessTests(unittest.TestCase):
    def test_command_shell_logs_successful_subprocess_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = pathlib.Path(temp_dir) / "shell.log"
            with managed_output_logger(log_path) as logger:
                runner = CaseRunner(output_logger=logger)
                runner.active_case_id = "demo:shell"
                result = runner.command_shell(
                    "printf 'shell stdout\\n'; printf 'shell stderr\\n' >&2"
                )

            self.assertEqual(result.stdout, "shell stdout\n")
            self.assertEqual(result.stderr, "shell stderr\n")

            log_text = log_path.read_text(encoding="utf-8")
            self.assertIn("case: demo:shell", log_text)
            self.assertIn(
                "command: printf 'shell stdout\\n'; printf 'shell stderr\\n' >&2",
                log_text,
            )
            self.assertIn("exit_code: 0", log_text)
            self.assertIn("shell stdout", log_text)
            self.assertIn("shell stderr", log_text)

    def test_command_shell_logs_failed_subprocess_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = pathlib.Path(temp_dir) / "shell-fail.log"
            with managed_output_logger(log_path) as logger:
                runner = CaseRunner(output_logger=logger)
                runner.active_case_id = "demo:shell-fail"
                with self.assertRaises(DetailedCalledProcessError):
                    runner.command_shell(
                        "printf 'shell stdout\\n'; printf 'shell stderr\\n' >&2; exit 2"
                    )

            log_text = log_path.read_text(encoding="utf-8")
            self.assertIn("case: demo:shell-fail", log_text)
            self.assertIn("exit_code: 2", log_text)
            self.assertIn("shell stdout", log_text)
            self.assertIn("shell stderr", log_text)

    def test_run_cases_reports_skips(self):
        cases = [
            CaseSpec(
                id="demo:skip",
                tags=("demo",),
                run=lambda runner: None,
                skip_reason="not today",
            )
        ]
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            result = run_cases(cases)

        self.assertEqual(result, 0)
        self.assertIn("Ran 1 cases", stdout.getvalue())
        self.assertIn("OK (skipped=1)", stdout.getvalue())

    def test_run_cases_reports_failures_and_continues(self):
        def fail(_: CaseRunner) -> None:
            raise AssertionError("boom")

        def succeed(_: CaseRunner) -> None:
            print("success path")

        cases = [
            CaseSpec(id="demo:bad", tags=("demo",), run=fail),
            CaseSpec(id="demo:good", tags=("demo",), run=succeed),
        ]
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            result = run_cases(cases, verbose=True)

        self.assertEqual(result, 1)
        output = stdout.getvalue()
        self.assertIn("RUN  demo:bad", output)
        self.assertIn("FAIL demo:bad", output)
        self.assertIn("boom", output)
        self.assertIn("RUN  demo:good", output)
        self.assertIn("PASS demo:good", output)
        self.assertIn("FAILED (failures=1, skipped=0)", output)

    def test_summaries_json_contains_case_metadata(self):
        cases = [
            CaseSpec(
                id="demo:meta",
                tags=("demo", "meta"),
                run=lambda runner: None,
                skip_reason="skip me",
                weight=3,
                description="demo case",
            )
        ]

        payload = json.loads(summaries_json(cases))
        self.assertEqual(
            payload,
            [
                {
                    "description": "demo case",
                    "id": "demo:meta",
                    "skip_reason": "skip me",
                    "tags": ["demo", "meta"],
                    "weight": 3,
                }
            ],
        )

    def test_stable_shards_is_deterministic(self):
        cases = [
            CaseSpec(id="demo:one", tags=("demo",), run=lambda runner: None, weight=4),
            CaseSpec(id="demo:two", tags=("demo",), run=lambda runner: None, weight=3),
            CaseSpec(
                id="demo:three", tags=("demo",), run=lambda runner: None, weight=2
            ),
            CaseSpec(id="demo:four", tags=("demo",), run=lambda runner: None, weight=1),
        ]

        first = stable_shards(cases, 2)
        second = stable_shards(cases, 2)

        self.assertEqual(
            [[case.id for case in shard] for shard in first],
            [[case.id for case in shard] for shard in second],
        )
        self.assertEqual(
            [sum(case.weight for case in shard) for shard in first],
            [5, 5],
        )

    def test_manifest_shards_remain_balanced(self):
        from harness.manifest import all_cases

        shards = stable_shards(all_cases(), 50)
        weights = [sum(case.weight for case in shard) for shard in shards]

        self.assertLessEqual(max(weights) - min(weights), 1)


class IntegrationHarnessTests(unittest.TestCase):
    def test_matches_supports_substrings_regexes_and_invalid_regexes(self):
        integration = _load_local_module("integration_matches_test", "integration.py")

        self.assertTrue(
            integration._matches("square:amd64", ("scenario", "square"), ["square"])
        )
        self.assertTrue(
            integration._matches("square:amd64", ("scenario",), ["^square:"])
        )
        self.assertTrue(integration._matches("demo[list]", ("scenario",), ["demo["]))
        self.assertFalse(
            integration._matches("square:amd64", ("scenario",), ["^strlen:"])
        )

    def test_main_validates_shard_arguments(self):
        integration = _load_local_module(
            "integration_validation_test", "integration.py"
        )

        scenarios = [
            (
                ["integration.py", "--shard-index", "0"],
                "both --shard-index and --shard-count are required together",
            ),
            (
                ["integration.py", "--shard-index", "0", "--shard-count", "0"],
                "--shard-count must be greater than zero",
            ),
            (
                ["integration.py", "--shard-index", "2", "--shard-count", "2"],
                "--shard-index must be in [0, --shard-count)",
            ),
        ]

        with mock.patch.object(integration, "all_cases", return_value=[]):
            for argv, message in scenarios:
                with self.subTest(argv=argv):
                    with mock.patch.object(sys, "argv", argv):
                        with self.assertRaises(SystemExit) as error:
                            integration.main()
                    self.assertEqual(str(error.exception), message)

    def test_list_json_outputs_machine_readable_metadata(self):
        integration = _load_local_module("integration_json_test", "integration.py")
        cases = [
            CaseSpec(
                id="demo:list",
                tags=("demo", "json"),
                run=lambda runner: None,
                skip_reason="skip",
                weight=2,
                description="json case",
            )
        ]
        stdout = io.StringIO()

        with mock.patch.object(integration, "all_cases", return_value=cases):
            with mock.patch.object(
                sys, "argv", ["integration.py", "--list", "--format", "json"]
            ):
                with contextlib.redirect_stdout(stdout):
                    result = integration.main()

        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            [
                {
                    "description": "json case",
                    "id": "demo:list",
                    "skip_reason": "skip",
                    "tags": ["demo", "json"],
                    "weight": 2,
                }
            ],
        )

    def test_main_reports_when_filters_match_nothing(self):
        integration = _load_local_module("integration_nomatch_test", "integration.py")
        cases = [CaseSpec(id="demo:list", tags=("demo",), run=lambda runner: None)]
        stdout = io.StringIO()

        with mock.patch.object(integration, "all_cases", return_value=cases):
            with mock.patch.object(
                sys, "argv", ["integration.py", "--filter", "^missing:"]
            ):
                with contextlib.redirect_stdout(stdout):
                    result = integration.main()

        self.assertEqual(result, 0)
        self.assertIn(
            "No integration cases matched the current selection.", stdout.getvalue()
        )


class HarnessLoggingTests(unittest.TestCase):
    def test_run_cases_logs_main_output_to_file_and_console(self):
        def run_case(_: CaseRunner) -> None:
            print("case stdout")
            print("case stderr", file=sys.stderr)

        cases = [
            CaseSpec(
                id="demo:ok",
                tags=("demo",),
                run=run_case,
            )
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = pathlib.Path(temp_dir) / "logs" / "integration.log"
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = run_cases(cases, verbose=True, log_path=log_path)

            self.assertEqual(result, 0)
            self.assertIn("RUN  demo:ok", stdout.getvalue())
            self.assertIn("PASS demo:ok", stdout.getvalue())
            self.assertIn("Ran 1 cases", stdout.getvalue())
            self.assertIn("OK", stdout.getvalue())
            self.assertIn("case stdout", stdout.getvalue())
            self.assertIn("case stderr", stderr.getvalue())

            log_text = log_path.read_text(encoding="utf-8")
            self.assertIn("RUN  demo:ok", log_text)
            self.assertIn("PASS demo:ok", log_text)
            self.assertIn("case stdout", log_text)
            self.assertIn("case stderr", log_text)

    def test_case_runner_logs_successful_subprocess_output(self):
        script = (
            "import sys; "
            "print('child stdout'); "
            "print('child stderr', file=sys.stderr)"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = pathlib.Path(temp_dir) / "subprocess.log"
            with managed_output_logger(log_path) as logger:
                runner = CaseRunner(output_logger=logger)
                runner.active_case_id = "demo:child"
                result = runner.command([sys.executable, "-c", script])

            self.assertEqual(result.stdout, "child stdout\n")
            self.assertEqual(result.stderr, "child stderr\n")

            log_text = log_path.read_text(encoding="utf-8")
            self.assertIn("case: demo:child", log_text)
            self.assertIn("exit_code: 0", log_text)
            self.assertIn("--- stdout ---\nchild stdout\n", log_text)
            self.assertIn("--- stderr ---\nchild stderr\n", log_text)

    def test_case_runner_logs_failed_subprocess_output(self):
        script = (
            "import sys; "
            "print('child stdout'); "
            "print('child stderr', file=sys.stderr); "
            "raise SystemExit(3)"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = pathlib.Path(temp_dir) / "failure.log"
            with managed_output_logger(log_path) as logger:
                runner = CaseRunner(output_logger=logger)
                runner.active_case_id = "demo:fail"
                with self.assertRaises(DetailedCalledProcessError):
                    runner.command([sys.executable, "-c", script])

            log_text = log_path.read_text(encoding="utf-8")
            self.assertIn("case: demo:fail", log_text)
            self.assertIn("exit_code: 3", log_text)
            self.assertIn("child stdout", log_text)
            self.assertIn("child stderr", log_text)

    def test_integration_list_writes_output_log(self):
        integration = _load_local_module(
            "integration_output_log_test",
            "integration.py",
        )

        cases = [
            CaseSpec(
                id="demo:list",
                tags=("demo", "list"),
                run=lambda runner: None,
            )
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = pathlib.Path(temp_dir) / "integration.log"
            log_path.write_text("stale data\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with mock.patch.object(integration, "all_cases", return_value=cases):
                with mock.patch.object(
                    sys,
                    "argv",
                    [
                        "integration.py",
                        "--list",
                        "--output-log",
                        str(log_path),
                    ],
                ):
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                    ):
                        result = integration.main()

            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertIn("demo:list\tdemo,list", stdout.getvalue())

            log_text = log_path.read_text(encoding="utf-8")
            self.assertNotIn("stale data", log_text)
            self.assertIn("demo:list\tdemo,list", log_text)


class RunCaseHarnessTests(unittest.TestCase):
    def test_script_path_for_case_returns_legacy_script(self):
        run_case = _load_local_module("run_case_legacy_test", "run_case.py")

        path = run_case.script_path_for_case("struct", "amd64")

        self.assertEqual(path, TESTS_DIR / "struct" / "struct.amd64.py")

    def test_script_path_for_case_falls_back_to_ghidra_script(self):
        run_case = _load_local_module("run_case_ghidra_test", "run_case.py")

        path = run_case.script_path_for_case("memhook", "amd64.pcode")

        self.assertEqual(path, TESTS_DIR / "memhook" / "memhook.amd64.ghidra.py")

    def test_script_path_for_case_reports_candidates_on_failure(self):
        run_case = _load_local_module("run_case_missing_test", "run_case.py")

        with self.assertRaises(FileNotFoundError) as error:
            run_case.script_path_for_case("missing.case", "amd64")

        message = str(error.exception)
        self.assertIn("no scenario entrypoint for `missing.case` / `amd64`", message)
        self.assertIn("Tried:", message)
        self.assertIn("tests/missing/case/case.amd64.py", message)

    def test_main_prefers_registered_scenarios(self):
        run_case = _load_local_module("run_case_registered_test", "run_case.py")

        with mock.patch.object(run_case, "maybe_run_registered_case", return_value=7):
            with mock.patch.object(sys, "argv", ["run_case.py", "square", "amd64"]):
                with mock.patch.object(run_case, "script_path_for_case") as script_path:
                    with mock.patch.object(
                        run_case.subprocess, "run"
                    ) as subprocess_run:
                        result = run_case.main()

        self.assertEqual(result, 7)
        script_path.assert_not_called()
        subprocess_run.assert_not_called()

    def test_main_executes_legacy_script_fallback(self):
        run_case = _load_local_module("run_case_fallback_test", "run_case.py")
        script = TESTS_DIR / "struct" / "struct.amd64.py"
        completed = types.SimpleNamespace(returncode=9)

        with mock.patch.object(
            run_case, "maybe_run_registered_case", return_value=None
        ):
            with mock.patch.object(
                run_case, "script_path_for_case", return_value=script
            ):
                with mock.patch.object(
                    run_case,
                    "wrap_python_command",
                    side_effect=lambda argv: ["wrapped", *argv],
                ) as wrap:
                    with mock.patch.object(
                        run_case.subprocess, "run", return_value=completed
                    ) as subprocess_run:
                        with mock.patch.object(
                            sys,
                            "argv",
                            ["run_case.py", "struct", "amd64", "arg1"],
                        ):
                            result = run_case.main()

        self.assertEqual(result, 9)
        wrap.assert_called_once_with([sys.executable, str(script), "arg1"])
        subprocess_run.assert_called_once_with(
            ["wrapped", sys.executable, str(script), "arg1"],
            cwd=TESTS_DIR,
            check=False,
        )


class FuzzScenarioTests(unittest.TestCase):
    def test_afl_registered_scenario_uses_forwarded_input_file(self):
        class FakeRegister:
            def __init__(self):
                self.value = None

            def set_content(self, value):
                self.value = value

        class FakeCPU:
            def __init__(self):
                self.pc = FakeRegister()
                self.a0 = FakeRegister()
                self.v0 = FakeRegister()

        class FakeHeap:
            def __init__(self, base, size):
                self.base = base
                self.size = size
                self.allocated_bytes = None

            def allocate_integer(self, *_args, **_kwargs):
                return 0x2345

            def allocate_bytes(self, value, _label):
                self.allocated_bytes = value

        class FakeMachine:
            last_instance = None

            def __init__(self):
                self.added = []
                self.fuzz_call = None
                FakeMachine.last_instance = self

            def add(self, member):
                self.added.append(member)

            def fuzz_with_file(
                self,
                emulator,
                input_callback,
                input_file_path,
                crash_callback=None,
                always_validate=False,
                iterations=1,
            ):
                self.fuzz_call = {
                    "emulator": emulator,
                    "input_callback": input_callback,
                    "input_file_path": input_file_path,
                    "crash_callback": crash_callback,
                    "always_validate": always_validate,
                    "iterations": iterations,
                }

        fake_smallworld = types.SimpleNamespace(
            logging=types.SimpleNamespace(setup_logging=lambda **_kwargs: None),
            platforms=types.SimpleNamespace(
                Byteorder={"LITTLE": object(), "BIG": object()}
            ),
            state=types.SimpleNamespace(
                Machine=FakeMachine,
                cpus=types.SimpleNamespace(
                    CPU=types.SimpleNamespace(for_platform=lambda _platform: FakeCPU())
                ),
                memory=types.SimpleNamespace(
                    heap=types.SimpleNamespace(BumpAllocator=FakeHeap),
                ),
            ),
        )

        fake_platform = object()
        fake_code = object()
        fake_emulator = types.SimpleNamespace(add_exit_point=lambda _addr: None)
        seed_path = "/tmp/seed-input"

        with mock.patch.dict(sys.modules, {"smallworld": fake_smallworld}):
            with mock.patch.object(
                fuzz_scenario, "make_platform", return_value=fake_platform
            ):
                with mock.patch.object(
                    fuzz_scenario, "_load_code", return_value=fake_code
                ):
                    with mock.patch.object(
                        fuzz_scenario, "_configure_argument"
                    ) as configure_argument:
                        with mock.patch.object(
                            fuzz_scenario, "make_emulator", return_value=fake_emulator
                        ):
                            with mock.patch.object(
                                sys,
                                "argv",
                                ["run_case.py", "fuzz.afl_fuzz", "mipsel", "@@"],
                            ):
                                result = fuzz_scenario.run_case(
                                    "fuzz.afl_fuzz", "mipsel", [seed_path]
                                )

        self.assertEqual(result, 0)
        self.assertIsNotNone(FakeMachine.last_instance)
        self.assertEqual(
            FakeMachine.last_instance.fuzz_call["input_file_path"],
            seed_path,
        )
        configure_argument.assert_called_once()


try:
    import styx_emulator as _styx_emulator  # noqa: F401

    _STYX_AVAILABLE = True
except Exception:
    _STYX_AVAILABLE = False


@unittest.skipUnless(_STYX_AVAILABLE, "styx_emulator not installed")
class StyxMachdefTests(unittest.TestCase):
    """Sanity checks on the SmallWorld Styx machine definitions.

    Mirrors the shape of :class:`UnicornMachdefTests` but only covers the
    architectures Styx supports (32-bit ARM and 32-bit PowerPC).
    """

    def _machdef_for(self, platform):
        return emulators.styx.machdefs.StyxMachineDef.for_platform(platform)

    def test_armhf_machdef_resolves(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
        )
        machdef = self._machdef_for(platform)
        # Core ARM registers should all be addressable.
        for name in ("r0", "r1", "r2", "sp", "lr", "pc", "cpsr"):
            self.assertTrue(
                machdef.has_register(name),
                msg=f"armhf machdef missing register '{name}'",
            )

    def test_armel_machdef_resolves(self):
        platform = platforms.Platform(
            platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
        )
        machdef = self._machdef_for(platform)
        for name in ("r0", "r1", "r2", "sp", "lr", "pc", "cpsr"):
            self.assertTrue(machdef.has_register(name))

    def test_ppc_machdef_resolves(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        machdef = self._machdef_for(platform)
        # Core PowerPC registers should all be addressable.
        for name in ("r0", "r1", "r3", "sp", "bp", "lr", "pc", "ctr", "cr0", "msr", "xer"):
            self.assertTrue(
                machdef.has_register(name),
                msg=f"ppc machdef missing register '{name}'",
            )
        # FPRs and cr1-cr6 are intentionally unmapped: the PPC405 Pcode register
        # file can't access them, and the map is shared with the MPC860 core.
        self.assertFalse(machdef.has_register("f0"))
        self.assertFalse(machdef.has_register("cr3"))

    def test_ppc64_raises_configuration_error(self):
        # Styx has no 64-bit PowerPC core, so POWERPC64 is unsupported.
        platform = platforms.Platform(
            platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
        )
        with self.assertRaises(exceptions.ConfigurationError):
            self._machdef_for(platform)

    def test_aarch64_raises_configuration_error(self):
        platform = platforms.Platform(
            platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
        )
        with self.assertRaises(exceptions.ConfigurationError):
            self._machdef_for(platform)

    def test_amd64_raises_configuration_error(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )
        with self.assertRaises(exceptions.ConfigurationError):
            self._machdef_for(platform)


@unittest.skipUnless(_STYX_AVAILABLE, "styx_emulator not installed")
class StyxEmulatorTests(unittest.TestCase):
    """Black-box behavioural tests for :class:`StyxEmulator`.

    These tests exercise the public Emulator surface (register/memory I/O,
    bounds/exit-point bookkeeping, hook registration plumbing) without
    requiring an actual styx Processor to step instructions. Tests that need
    instruction execution are gated by the ``_STYX_AVAILABLE`` skip above.
    """

    def setUp(self):
        self.platform = platforms.Platform(
            platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
        )
        self.emu = emulators.StyxEmulator(self.platform)

    def test_repr(self):
        self.assertIn("StyxEmulator", repr(self.emu))

    def test_map_memory_tracks_ranges(self):
        self.emu.map_memory(0x1000, 0x100)
        self.emu.map_memory(0x2000, 0x100)
        ranges = self.emu.get_memory_map()
        self.assertEqual(len(ranges), 2)

    def test_pending_register_writes_validate_name(self):
        # Unknown register names should fail eagerly even before _lazy_build.
        with self.assertRaises(exceptions.UnsupportedRegisterError):
            self.emu.write_register_content("not_a_real_register", 0)

    def test_symbolic_register_write_rejected(self):
        with self.assertRaises(exceptions.SymbolicValueError):
            self.emu.write_register_content("r0", claripy.BVS("x", 32))

    def test_symbolic_memory_write_rejected(self):
        with self.assertRaises(exceptions.SymbolicValueError):
            self.emu.write_memory_content(0x1000, claripy.BVS("x", 32))

    def test_exit_point_bookkeeping(self):
        self.emu.add_exit_point(0x4000)
        self.assertIn(0x4000, self.emu.get_exit_points())

    def test_hook_instruction_records_locally(self):
        called = []

        def cb(e):
            called.append(e)

        self.emu.hook_instruction(0x1000, cb)
        # The hookable mixin stores the function in ``instruction_hooks``.
        self.assertIs(self.emu.is_instruction_hooked(0x1000), cb)

    def test_ppc_cpu_model_selects_target(self):
        # The PowerPC machdef serves both Styx cores; cpu_model picks the
        # (Target, Backend) pair: PPC405 on Pcode, MPC860 on Unicorn.
        from styx_emulator.cpu import Backend
        from styx_emulator.processor import Target

        ppc = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        default = emulators.StyxEmulator(ppc)
        self.assertEqual(
            (default._target, default._backend), (Target.Ppc4xx, Backend.Pcode)
        )
        ppc405 = emulators.StyxEmulator(ppc, cpu_model="ppc405")
        self.assertEqual(
            (ppc405._target, ppc405._backend), (Target.Ppc4xx, Backend.Pcode)
        )
        mpc860 = emulators.StyxEmulator(ppc, cpu_model="mpc860")
        self.assertEqual(
            (mpc860._target, mpc860._backend), (Target.Mpc8xx, Backend.Unicorn)
        )

    def test_unknown_cpu_model_rejected(self):
        ppc = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        with self.assertRaises(exceptions.ConfigurationError):
            emulators.StyxEmulator(ppc, cpu_model="does-not-exist")


@unittest.skipUnless(_STYX_AVAILABLE, "styx_emulator not installed")
class StyxPowerPCExecutionTests(unittest.TestCase):
    """End-to-end execution checks for PowerPC on Styx.

    Loads the ``square`` test fixture (``mullw r3, r3, r3``) and runs it to an
    exit point, asserting the squared result lands back in ``r3``. The default
    core is the PPC405 (``Target.Ppc4xx``).
    """

    def _square_on(self, cpu_model, base=0x1000, value=5):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        emu = emulators.StyxEmulator(platform, cpu_model=cpu_model)
        code = (TESTS_DIR / "square" / "square.ppc.bin").read_bytes()
        emu.write_code(base, code)
        emu.write_register_content("pc", base)
        emu.write_register_content("r3", value)
        emu.add_exit_point(base + len(code))
        try:
            emu.run()
        except exceptions.EmulationExitpoint:
            pass
        return emu.read_register_content("r3")

    def test_ppc405_squares_argument(self):
        self.assertEqual(self._square_on(None), 25)

    def test_mpc860_squares_argument(self):
        # MPC860 runs on the Unicorn backend (its Pcode path is unimplemented).
        self.assertEqual(self._square_on("mpc860"), 25)

    def _run_fuzz(self, user_input):
        # Runs the styx fuzz program (tests/fuzz/fuzz.ppc.bin) on MPC860, whose
        # firmware memory map leaves the bad-write target (0x12345678) unmapped
        # so the "bad!" trigger faults (PPC405 maps the full 4 GiB instead).
        platform = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        emu = emulators.StyxEmulator(platform, cpu_model="mpc860")
        code = (TESTS_DIR / "fuzz" / "fuzz.ppc.bin").read_bytes()
        emu.write_code(0x1000, code)
        emu.write_memory_content(
            0x2000, len(user_input).to_bytes(4, "big") + user_input
        )
        emu.write_register_content("pc", 0x1000)
        emu.write_register_content("r3", 0x2000)
        emu.add_exit_point(0x1000 + 88)
        try:
            emu.run()
        except exceptions.EmulationExitpoint:
            pass
        return emu

    def test_mpc860_fuzz_benign_input_returns_zero(self):
        self.assertEqual(self._run_fuzz(b"goodgoodgood").read_register_content("r3"), 0)

    def test_mpc860_fuzz_trigger_input_crashes(self):
        # "bad!" + a 5th byte makes the program store to unmapped 0x12345678.
        with self.assertRaises(exceptions.EmulationError):
            self._run_fuzz(b"bad!AAAAAAAA")


@unittest.skipUnless(_STYX_AVAILABLE, "styx_emulator not installed")
class StyxFuzzScenarioTests(unittest.TestCase):
    """Mirror of :class:`FuzzScenarioTests` for the Styx fuzz scenario.

    Verifies that the registered ``styx.afl_fuzz`` scenario forwards the AFL
    input file path through to ``Machine.fuzz_with_file`` without actually
    invoking styxafl/afl-fuzz.
    """

    def test_afl_registered_scenario_uses_forwarded_input_file(self):
        try:
            from harness.scenarios import styx_fuzz as styx_fuzz_scenario
        except ImportError:
            self.skipTest("styx_fuzz scenario not registered")

        class FakeRegister:
            def __init__(self):
                self.value = None

            def set_content(self, value):
                self.value = value

        class FakeCPU:
            def __init__(self):
                self.pc = FakeRegister()
                self.r0 = FakeRegister()
                self.r1 = FakeRegister()

        class FakeHeap:
            def __init__(self, base, size):
                self.base = base
                self.size = size

            def allocate_integer(self, *_args, **_kwargs):
                return 0x2345

            def allocate_bytes(self, value, _label):
                pass

        class FakeMachine:
            last_instance = None

            def __init__(self):
                self.added = []
                self.fuzz_call = None
                FakeMachine.last_instance = self

            def add(self, member):
                self.added.append(member)

            def fuzz_with_file(
                self,
                emulator,
                input_callback,
                input_file_path,
                crash_callback=None,
                always_validate=False,
                iterations=1,
            ):
                self.fuzz_call = {
                    "emulator": emulator,
                    "input_callback": input_callback,
                    "input_file_path": input_file_path,
                    "crash_callback": crash_callback,
                    "always_validate": always_validate,
                    "iterations": iterations,
                }

        fake_smallworld = types.SimpleNamespace(
            logging=types.SimpleNamespace(setup_logging=lambda **_kwargs: None),
            platforms=types.SimpleNamespace(
                Byteorder={"LITTLE": object(), "BIG": object()}
            ),
            state=types.SimpleNamespace(
                Machine=FakeMachine,
                cpus=types.SimpleNamespace(
                    CPU=types.SimpleNamespace(for_platform=lambda _platform: FakeCPU())
                ),
                memory=types.SimpleNamespace(
                    heap=types.SimpleNamespace(BumpAllocator=FakeHeap),
                ),
            ),
        )

        fake_platform = object()
        fake_code = object()
        fake_emulator = types.SimpleNamespace(add_exit_point=lambda _addr: None)
        seed_path = "/tmp/seed-input-styx"

        with mock.patch.dict(sys.modules, {"smallworld": fake_smallworld}):
            with mock.patch.object(
                styx_fuzz_scenario, "make_platform", return_value=fake_platform
            ):
                with mock.patch.object(
                    styx_fuzz_scenario, "_load_code", return_value=fake_code
                ):
                    with mock.patch.object(
                        styx_fuzz_scenario, "_configure_argument"
                    ) as configure_argument:
                        with mock.patch.object(
                            styx_fuzz_scenario,
                            "make_emulator",
                            return_value=fake_emulator,
                        ):
                            with mock.patch.object(
                                sys,
                                "argv",
                                [
                                    "run_case.py",
                                    "styx.afl_fuzz",
                                    "armhf",
                                    "@@",
                                ],
                            ):
                                result = styx_fuzz_scenario.run_case(
                                    "styx.afl_fuzz", "armhf", [seed_path]
                                )

        self.assertEqual(result, 0)
        self.assertIsNotNone(FakeMachine.last_instance)
        self.assertEqual(
            FakeMachine.last_instance.fuzz_call["input_file_path"],
            seed_path,
        )
        configure_argument.assert_called_once()


class StaticBufferScenarioTests(unittest.TestCase):
    def test_riscv64_entry_offset_skips_compressed_breakpoint(self):
        code = (TESTS_DIR / "static_buf" / "static_buf.riscv64.bin").read_bytes()
        md = capstone.Cs(
            capstone.CS_ARCH_RISCV,
            capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC,
        )
        instructions = list(md.disasm(code, 0x1000))

        self.assertGreaterEqual(len(instructions), 2)
        self.assertEqual(instructions[0].mnemonic, "c.ebreak")
        self.assertEqual(instructions[1].address - instructions[0].address, 2)
        self.assertEqual(static_buf_scenario._SPECS["riscv64"].entry_offset, 2)


class DocumentationReferenceTests(unittest.TestCase):
    def test_documented_python_paths_exist(self):
        doc_files = [
            REPO_ROOT / "README.md",
            TESTS_DIR / "README.md",
            *sorted((REPO_ROOT / "docs").rglob("*.rst")),
            *sorted((REPO_ROOT / "docs").rglob("*.md")),
        ]
        missing: list[tuple[pathlib.Path, str]] = []

        for doc_file in doc_files:
            content = doc_file.read_text(encoding="utf-8")
            for match in sorted(
                set(re.findall(r"tests/[A-Za-z0-9_./-]+\.py", content))
            ):
                if not (REPO_ROOT / match).exists():
                    missing.append((doc_file, match))

        self.assertEqual(missing, [])


class _RawIntSizeValue(state.Value):
    """Minimal concrete Value with int content and an arbitrary size.

    Used to exercise Value.to_symbolic with sizes IntegerValue rejects.
    """

    def __init__(self, content: int, size: int) -> None:
        super().__init__()
        self._content = content
        self._size = size

    def get_size(self) -> int:
        return self._size

    def to_bytes(self) -> bytes:
        return b""


class RangeCollectionRemoveTests(unittest.TestCase):
    """Tests for utils.RangeCollection.remove_range."""

    def test_remove_range_clips_overhanging_range(self):
        # Removal starts inside an existing range but extends past its end;
        # the overlap must be clipped off the existing range.
        rc = utils.RangeCollection()
        rc.add_range((10, 20))
        rc.remove_range((15, 25))
        self.assertEqual(rc.ranges, [(10, 15)])

    def test_remove_range_exact_match(self):
        rc = utils.RangeCollection()
        rc.add_range((10, 20))
        rc.remove_range((10, 20))
        self.assertEqual(rc.ranges, [])

    def test_remove_range_interior_split(self):
        rc = utils.RangeCollection()
        rc.add_range((10, 30))
        rc.remove_range((15, 20))
        self.assertEqual(rc.ranges, [(10, 15), (20, 30)])

    def test_remove_range_spanning_multiple_ranges(self):
        # The low range must be clipped and the high range trimmed.
        rc = utils.RangeCollection()
        rc.add_range((10, 20))
        rc.add_range((30, 40))
        rc.remove_range((15, 35))
        self.assertEqual(rc.ranges, [(10, 15), (35, 40)])

    def test_remove_range_touching_end_is_noop(self):
        # Ranges are half-open; removing [20, 25) does not touch [10, 20).
        rc = utils.RangeCollection()
        rc.add_range((10, 20))
        rc.remove_range((20, 25))
        self.assertEqual(rc.ranges, [(10, 20)])


class SparseIOReadTests(unittest.TestCase):
    """Tests for utils.SparseIO.read."""

    def _make_sparse(self) -> utils.SparseIO:
        sio = utils.SparseIO()
        sio.seek(100)
        sio.write(b"ABCDEFGHIJ")
        return sio

    def test_read_window_inside_segment_is_clamped(self):
        # A read starting inside a segment and ending before its end must
        # return exactly the requested window, not the segment's whole tail.
        sio = self._make_sparse()
        sio.seek(102)
        data = sio.read(4)
        self.assertEqual(data, b"CDEF")
        self.assertEqual(len(data), 4)
        # The stream position must land at the end of the window.
        self.assertEqual(sio.read(2), b"GH")

    def test_read_window_overlapping_segment_end_zero_fills(self):
        sio = self._make_sparse()
        sio.seek(105)
        self.assertEqual(sio.read(10), b"FGHIJ" + b"\x00" * 5)

    def test_read_window_spanning_whole_segment_zero_fills(self):
        sio = self._make_sparse()
        sio.seek(95)
        self.assertEqual(sio.read(20), b"\x00" * 5 + b"ABCDEFGHIJ" + b"\x00" * 5)


class MemoryToBytesTests(unittest.TestCase):
    """Tests for state.memory.Memory.to_bytes."""

    def test_to_bytes_zero_fills_gaps(self):
        memory = state.memory.Memory(0x1000, 8)
        memory[1] = state.BytesValue(b"\xaa\xbb", None)
        memory[5] = state.IntegerValue(0x1122, 2, None, platforms.Byteorder.LITTLE)
        data = memory.to_bytes()
        self.assertEqual(data, b"\x00\xaa\xbb\x00\x00\x22\x11\x00")
        self.assertEqual(len(data), memory.get_capacity())

    def test_to_bytes_empty_memory_is_all_zeroes(self):
        memory = state.memory.Memory(0x1000, 4)
        self.assertEqual(memory.to_bytes(), b"\x00" * 4)


class MemoryRangeMergeTests(unittest.TestCase):
    """Tests for segment merging in Memory.get_ranges_*."""

    def test_ranges_initialized_merges_adjacent_multibyte_segments(self):
        memory = state.memory.Memory(0x1000, 0x10)
        memory[0] = state.BytesValue(b"\xff" * 4, None)
        memory[4] = state.BytesValue(b"\xee" * 4, None)
        self.assertEqual(
            memory.get_ranges_initialized(),
            [range(0x1000, 0x1007)],
        )

    def test_ranges_initialized_keeps_gapped_segments_separate(self):
        memory = state.memory.Memory(0x1000, 0x10)
        memory[0] = state.BytesValue(b"\xff" * 2, None)
        memory[6] = state.BytesValue(b"\xee" * 2, None)
        self.assertEqual(
            memory.get_ranges_initialized(),
            [range(0x1000, 0x1001), range(0x1006, 0x1007)],
        )

    def test_ranges_initialized_no_false_merge_on_overlap(self):
        # Old code merged when the previous stop + 1 equaled the next
        # segment's END; with these overlapping segments it collapsed
        # everything into range(0x1000, 0x1004).
        memory = state.memory.Memory(0x1000, 0x10)
        memory[0] = state.BytesValue(b"\xff" * 4, None)
        memory[2] = state.BytesValue(b"\xee" * 3, None)
        self.assertEqual(
            memory.get_ranges_initialized(),
            [range(0x1000, 0x1003), range(0x1002, 0x1004)],
        )

    def test_ranges_symbolic_merges_adjacent_multibyte_segments(self):
        memory = state.memory.Memory(0x1000, 0x10)
        memory[1] = state.SymbolicValue(2, None, None, None)
        memory[3] = state.SymbolicValue(2, None, None, None)
        self.assertEqual(
            memory.get_ranges_symbolic(),
            [range(0x1001, 0x1004)],
        )

    def test_ranges_concrete_merges_adjacent_multibyte_segments(self):
        memory = state.memory.Memory(0x1000, 0x10)
        memory[0] = state.BytesValue(b"\xff" * 3, None)
        memory[3] = state.BytesValue(b"\xee" * 3, None)
        # A symbolic segment must not join the concrete range.
        memory[6] = state.SymbolicValue(2, None, None, None)
        self.assertEqual(
            memory.get_ranges_concrete(),
            [range(0x1000, 0x1005)],
        )


class CheckedBumpAllocatorTests(unittest.TestCase):
    """Tests for state.memory.heap.CheckedBumpAllocator."""

    def _make_heap(self) -> state.memory.heap.CheckedBumpAllocator:
        return state.memory.heap.CheckedBumpAllocator(0x200000, 0x1000, 16)

    def test_checked_heap_free_of_allocated_address_succeeds(self):
        heap = self._make_heap()
        addr = heap.allocate_bytes(b"AAAA", "buf")
        self.assertEqual(addr, heap.address)
        # free() takes the absolute address returned by allocate().
        heap.free(addr)

    def test_checked_heap_double_free_raises(self):
        heap = self._make_heap()
        addr = heap.allocate_bytes(b"AAAA", "buf")
        heap.free(addr)
        with self.assertRaisesRegex(ValueError, "Invalid Free"):
            heap.free(addr)

    def test_checked_heap_free_of_unallocated_address_raises(self):
        heap = self._make_heap()
        heap.allocate_bytes(b"AAAA", "buf")
        with self.assertRaisesRegex(ValueError, "Invalid Free"):
            heap.free(heap.address + 1)

    def test_checked_heap_use_after_free_detected(self):
        heap = self._make_heap()
        addr = heap.allocate_bytes(b"AAAA", "buf")
        heap.free(addr)
        with self.assertRaisesRegex(ValueError, "Access freed memory"):
            heap.check_access(None, addr, 4, b"AAAA")

    def test_checked_heap_valid_access_allowed(self):
        heap = self._make_heap()
        heap.allocate_bytes(b"AAAA", "first")
        # Second allocation lands at a non-zero offset into the heap.
        addr = heap.allocate_bytes(b"BBBB", "second")
        self.assertGreater(addr, heap.address)
        self.assertEqual(heap.check_access(None, addr, 4, b"BBBB"), b"BBBB")

    def test_checked_heap_access_below_base_rejected(self):
        heap = self._make_heap()
        heap.allocate_bytes(b"AAAA", "buf")
        with self.assertRaisesRegex(ValueError, "Invalid access"):
            heap.check_access(None, heap.address - 4, 4, b"AAAA")

    def test_checked_heap_access_beyond_capacity_rejected(self):
        heap = self._make_heap()
        heap.allocate_bytes(b"AAAA", "buf")
        with self.assertRaisesRegex(ValueError, "Invalid access"):
            heap.check_access(None, heap.address + 0x1000 - 2, 4, b"AAAA")


class MachineReadMemoryTests(unittest.TestCase):
    """Tests for state.Machine.read_memory."""

    def test_read_memory_returns_slice_of_bytes_value(self):
        machine = state.Machine()
        memory = state.memory.Memory(0x1000, 0x10)
        memory[0] = state.BytesValue(b"\x01\x02\x03\x04\x05\x06\x07\x08", None)
        machine.add(memory)
        self.assertEqual(machine.read_memory(0x1002, 3), b"\x03\x04\x05")

    def test_read_memory_one_past_end_returns_none(self):
        machine = state.Machine()
        memory = state.memory.Memory(0x1000, 0x10)
        memory[0] = state.BytesValue(b"\x01\x02\x03\x04\x05\x06\x07\x08", None)
        machine.add(memory)
        # The value covers [0x1000, 0x1008); 0x1008 is one past the end.
        self.assertIsNone(machine.read_memory(0x1008, 1))

    def test_read_memory_of_integer_value_returns_bytes(self):
        machine = state.Machine()
        memory = state.memory.Memory(0x2000, 8)
        memory[0] = state.IntegerValue(
            0xDEADBEEF, 4, None, platforms.Byteorder.LITTLE, signed=False
        )
        machine.add(memory)
        self.assertEqual(machine.read_memory(0x2000, 4), b"\xef\xbe\xad\xde")
        self.assertEqual(machine.read_memory(0x2001, 2), b"\xbe\xad")


class ValueToSymbolicTests(unittest.TestCase):
    """Tests for state.Value.to_symbolic with integer content."""

    def test_to_symbolic_int_little_endian_no_byteswap(self):
        value = state.IntegerValue(0x11223344, 4, None, platforms.Byteorder.LITTLE)
        bv = value.to_symbolic(platforms.Byteorder.LITTLE)
        self.assertTrue(bv.structurally_match(claripy.BVV(0x11223344, 32)))

    def test_to_symbolic_int_big_endian(self):
        value = state.IntegerValue(0x1122, 2, None, platforms.Byteorder.BIG)
        bv = value.to_symbolic(platforms.Byteorder.BIG)
        self.assertTrue(bv.structurally_match(claripy.BVV(0x1122, 16)))

    def test_to_symbolic_negative_int_twos_complement(self):
        value = state.IntegerValue(-2, 4, None, platforms.Byteorder.LITTLE)
        bv = value.to_symbolic(platforms.Byteorder.LITTLE)
        self.assertTrue(bv.structurally_match(claripy.BVV(0xFFFFFFFE, 32)))

    def test_to_symbolic_size_zero_raises_configuration_error(self):
        value = _RawIntSizeValue(5, 0)
        with self.assertRaises(exceptions.ConfigurationError):
            value.to_symbolic(platforms.Byteorder.LITTLE)


AARCH64_LE_PLATFORM = platforms.Platform(
    platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
)
AMD64_LE_PLATFORM = platforms.Platform(
    platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
)

# The w-register aliases whose parents were wrong (w11/w12 pointed at x10,
# w21/w22 pointed at x20), plus a few neighbors that were always correct.
AARCH64_FIXED_W_ALIASES = [
    ("w11", "x11"),
    ("w12", "x12"),
    ("w21", "x21"),
    ("w22", "x22"),
]
AARCH64_SPOT_CHECK_W_ALIASES = [
    ("w10", "x10"),
    ("w13", "x13"),
    ("w20", "x20"),
    ("w23", "x23"),
]


class Amd64ArchInfoTests(unittest.TestCase):
    """The amd64 arch info dict mapped "gs" to the "fs" base register."""

    def test_gs_maps_to_gs_base_register(self):
        self.assertEqual(amd64_arch.info["gs"], ("gs", (0, 2)))

    def test_segment_registers_map_to_themselves(self):
        for seg in ("cs", "ds", "es", "fs", "gs"):
            with self.subTest(register=seg):
                base, (start, end) = amd64_arch.info[seg]
                self.assertEqual(base, seg)
                self.assertEqual((start, end), (0, 2))


class AArch64WAliasPlatformDefTests(unittest.TestCase):
    """w11/w12/w21/w22 alias defs pointed at the wrong parent registers."""

    def test_fixed_w_alias_parents(self):
        pdef = platforms.PlatformDef.for_platform(AARCH64_LE_PLATFORM)
        for alias, parent in AARCH64_FIXED_W_ALIASES:
            with self.subTest(alias=alias):
                regdef = pdef.registers[alias]
                self.assertIsInstance(regdef, platforms.defs.RegisterAliasDef)
                self.assertEqual(regdef.parent, parent)
                self.assertEqual(regdef.size, 4)
                self.assertEqual(regdef.offset, 0)

    def test_spot_check_w_alias_parents(self):
        pdef = platforms.PlatformDef.for_platform(AARCH64_LE_PLATFORM)
        for alias, parent in AARCH64_SPOT_CHECK_W_ALIASES:
            with self.subTest(alias=alias):
                self.assertEqual(pdef.registers[alias].parent, parent)


class AArch64WAliasCPUTests(unittest.TestCase):
    """The aarch64 CPU state had the same wrong-parent aliasing bug."""

    def setUp(self):
        self.cpu = state.cpus.CPU.for_platform(AARCH64_LE_PLATFORM)

    def test_w_alias_references(self):
        for alias, parent in AARCH64_FIXED_W_ALIASES + AARCH64_SPOT_CHECK_W_ALIASES:
            with self.subTest(alias=alias):
                self.assertEqual(getattr(self.cpu, alias).reference.name, parent)

    def test_w11_reads_low_half_of_x11(self):
        self.cpu.x10.set(0xAAAAAAAAAAAAAAAA)
        self.cpu.x11.set(0x1122334455667788)
        self.assertEqual(self.cpu.w11.get(), 0x55667788)

    def test_w21_reads_low_half_of_x21(self):
        self.cpu.x20.set(0xAAAAAAAAAAAAAAAA)
        self.cpu.x21.set(0x1122334455667788)
        self.assertEqual(self.cpu.w21.get(), 0x55667788)

    def test_w12_set_affects_x12_not_x10(self):
        self.cpu.x10.set(0x1111111122222222)
        self.cpu.x12.set(0x3333333344444444)
        self.cpu.w12.set(0xDEADBEEF)
        self.assertEqual(self.cpu.x12.get(), 0x33333333DEADBEEF)
        self.assertEqual(self.cpu.x10.get(), 0x1111111122222222)

    def test_w22_set_affects_x22_not_x20(self):
        self.cpu.x20.set(0x1111111122222222)
        self.cpu.x22.set(0x3333333344444444)
        self.cpu.w22.set(0xDEADBEEF)
        self.assertEqual(self.cpu.x22.get(), 0x33333333DEADBEEF)
        self.assertEqual(self.cpu.x20.get(), 0x1111111122222222)


class _ShadowRegister(state.Register):
    """A strict Register subclass, as some future CPU attribute might be."""

    pass


class _DeepCopyTestCPU(state.cpus.CPU):
    """Minimal CPU with one of each register flavor.

    The platform is deliberately a combination (x86_64 big-endian) that no
    real CPU model uses, so CPU.for_platform() lookups never match this class.
    """

    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.BIG
    )

    def __init__(self):
        super().__init__()
        self.base = state.Register("base", 8)
        self.add(self.base)
        self.shadow = _ShadowRegister("shadow", 8)
        self.add(self.shadow)
        self.baselo = state.RegisterAlias("baselo", self.base, 4, 0)
        self.add(self.baselo)
        self.zero = state.FixedRegister("zero", 8, 42)
        self.add(self.zero)


class CPUDeepCopyTests(unittest.TestCase):
    """CPU.__deepcopy__ dropped content of strict Register subclasses."""

    def test_deepcopy_preserves_subclassed_register_content_and_label(self):
        cpu = _DeepCopyTestCPU()
        cpu.shadow.set(0x1234567890ABCDEF)
        cpu.shadow.set_label("shadow-label")
        dup = copy.deepcopy(cpu)
        self.assertEqual(dup.shadow.get(), 0x1234567890ABCDEF)
        self.assertEqual(dup.shadow.get_label(), "shadow-label")

    def test_deepcopy_preserves_plain_register_content_and_label(self):
        cpu = _DeepCopyTestCPU()
        cpu.base.set(0xAABBCCDD)
        cpu.base.set_label("base-label")
        dup = copy.deepcopy(cpu)
        self.assertEqual(dup.base.get(), 0xAABBCCDD)
        self.assertEqual(dup.base.get_label(), "base-label")

    def test_deepcopy_alias_references_copied_parent(self):
        cpu = _DeepCopyTestCPU()
        cpu.base.set(0x1122334455667788)
        dup = copy.deepcopy(cpu)
        self.assertIsNot(dup.base, cpu.base)
        self.assertIs(dup.baselo.reference, dup.base)
        # Mutating the copy through its alias must not touch the original.
        dup.baselo.set(0xDEADBEEF)
        self.assertEqual(dup.base.get(), 0x11223344DEADBEEF)
        self.assertEqual(cpu.base.get(), 0x1122334455667788)

    def test_deepcopy_skips_fixed_registers_without_error(self):
        cpu = _DeepCopyTestCPU()
        dup = copy.deepcopy(cpu)
        self.assertEqual(dup.zero.get(), 42)


class MemoryPointsToHintTests(unittest.TestCase):
    """MemoryPointsToHint extended RegisterPointerHint instead of MemoryPointerHint."""

    def test_extends_memory_pointer_hint(self):
        self.assertTrue(issubclass(MemoryPointsToHint, MemoryPointerHint))
        self.assertFalse(issubclass(MemoryPointsToHint, RegisterPointerHint))

    def test_constructs_with_address_field(self):
        hint = MemoryPointsToHint(message="msg", address=0x1000, type="int")
        self.assertEqual(hint.address, 0x1000)
        self.assertEqual(hint.type, "int")
        self.assertIsInstance(hint, MemoryPointerHint)


class _TypedPointerTestStruct(ctypes.Structure):
    _fields_ = [("field", ctypes.c_int)]


class CreateTypedPointerTests(unittest.TestCase):
    """create_typed_pointer named every class "typePointer" (builtin type)."""

    def test_class_named_after_referenced_struct(self):
        ptr_cls = create_typed_pointer(_TypedPointerTestStruct)
        self.assertEqual(ptr_cls.__name__, "_TypedPointerTestStructPointer")
        self.assertIs(ptr_cls.type, _TypedPointerTestStruct)
        self.assertTrue(issubclass(ptr_cls, TypedPointer))

    def test_class_named_after_referenced_scalar(self):
        ptr_cls = create_typed_pointer(ctypes.c_int)
        self.assertEqual(ptr_cls.__name__, "c_intPointer")
        self.assertIs(ptr_cls.type, ctypes.c_int)

    def test_char_pointer_still_maps_to_c_char_p(self):
        self.assertIs(create_typed_pointer(ctypes.c_char), ctypes.c_char_p)


class SockaddrIn6ReprTests(unittest.TestCase):
    """SockaddrIn6.__repr__ shifted by (8 + next byte) due to precedence bug."""

    def test_repr_formats_sixteen_bit_groups(self):
        sockaddr = SockaddrIn6(addr=bytes(range(16)), port=80)
        self.assertEqual(
            repr(sockaddr),
            "AF_INET6:0001:0203:0405:0607:0809:0a0b:0c0d:0e0f:80",
        )

    def test_repr_of_loopback(self):
        sockaddr = SockaddrIn6(addr=b"\x00" * 15 + b"\x01", port=443)
        self.assertEqual(
            repr(sockaddr),
            "AF_INET6:0000:0000:0000:0000:0000:0000:0000:0001:443",
        )


class EmulatorInterfaceTests(unittest.TestCase):
    """SyscallHookable export and ConstrainedEmulator abstractness."""

    def test_syscall_hookable_exported(self):
        self.assertTrue(hasattr(emulators, "SyscallHookable"))
        self.assertIn("SyscallHookable", emulators.__all__)

    def test_constrained_emulator_is_abstract(self):
        with self.assertRaises(TypeError):
            emulators.ConstrainedEmulator()

    def test_constrained_emulator_trivial_subclass_is_abstract(self):
        class Incomplete(emulators.ConstrainedEmulator):
            pass

        with self.assertRaises(TypeError):
            Incomplete()


class ArmInstructionPlatformTests(unittest.TestCase):
    """ARMV5TInstruction claimed ARM_V6M; ARMV6MThumbInstruction was missing."""

    def test_armv5t_instruction_platform(self):
        from smallworld.instructions.arm import ARMV5TInstruction

        self.assertEqual(
            ARMV5TInstruction.platform.architecture, platforms.Architecture.ARM_V5T
        )

    def test_armv6m_instruction_platform(self):
        from smallworld.instructions.arm import ARMV6MInstruction

        self.assertEqual(
            ARMV6MInstruction.platform.architecture, platforms.Architecture.ARM_V6M
        )
        self.assertEqual(ARMV6MInstruction.cs_mode, capstone.CS_MODE_ARM)

    def test_armv6m_thumb_instruction(self):
        from smallworld.instructions.arm import ARMV6MThumbInstruction

        self.assertEqual(
            ARMV6MThumbInstruction.platform.architecture,
            platforms.Architecture.ARM_V6M_THUMB,
        )
        self.assertEqual(ARMV6MThumbInstruction.cs_mode, capstone.CS_MODE_THUMB)

    def test_from_bytes_decodes_thumb(self):
        thumb = platforms.Platform(
            platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE
        )
        # movs r0, #1 in thumb encoding
        insn = Instruction.from_bytes(b"\x01\x20", 0x1000, thumb)
        self.assertEqual(type(insn).__name__, "ARMV6MThumbInstruction")
        self.assertIn("movs", insn.disasm)


class X86ImmediateOperandTests(unittest.TestCase):
    """x86Instruction.reads hit `assert 1 == 0` on immediate operands."""

    def test_immediate_with_read_access_does_not_assert(self):
        # rcl byte ptr [rax] (rotate by an implicit 1): capstone models the
        # implicit immediate as an operand with read access, which used to
        # trip the `assert 1 == 0` in x86Instruction.reads.
        insn = Instruction.from_bytes(b"\xd0\x10", 0x1000, AMD64_LE_PLATFORM)
        self.assertIn("rcl", insn.disasm)
        reads = insn.reads
        writes = insn.writes
        self.assertIn(RegisterOperand("rax"), reads)
        self.assertGreaterEqual(len(writes), 1)

    def test_add_immediate_reads_and_writes(self):
        # add rax, 5
        insn = Instruction.from_bytes(b"\x48\x83\xc0\x05", 0x1000, AMD64_LE_PLATFORM)
        self.assertIn("add", insn.disasm)
        self.assertIn(RegisterOperand("rax"), insn.reads)
        self.assertIn(RegisterOperand("rax"), insn.writes)


class UnicornAmd64FpuRegisterTests(unittest.TestCase):
    """The unicorn amd64 machdef mapped fstat to the FPU control word."""

    def test_fstat_maps_to_fpsw(self):
        machdef = emulators.unicorn.machdefs.UnicornMachineDef.for_platform(
            AMD64_LE_PLATFORM
        )
        self.assertEqual(machdef.uc_reg("fstat"), unicorn.x86_const.UC_X86_REG_FPSW)

    def test_fctrl_still_maps_to_fpcw(self):
        machdef = emulators.unicorn.machdefs.UnicornMachineDef.for_platform(
            AMD64_LE_PLATFORM
        )
        self.assertEqual(machdef.uc_reg("fctrl"), unicorn.x86_const.UC_X86_REG_FPCW)


class AngrMipsRegisterMapTests(unittest.TestCase):
    """The angr MIPS machdef mapped register number 3 to nonexistent "v3"."""

    def run_test(self, byteorder):
        platform = platforms.Platform(platforms.Architecture.MIPS32, byteorder)
        machdef = emulators.angr.machdefs.AngrMachineDef.for_platform(platform)
        self.assertEqual(machdef._registers["3"], "v1")
        # "v3" is not a real MIPS register; angr_reg would raise for it.
        self.assertEqual(machdef.angr_reg("3"), machdef.angr_reg("v1"))

    def test_mips_be_register_3_is_v1(self):
        self.run_test(platforms.Byteorder.BIG)

    def test_mips_le_register_3_is_v1(self):
        self.run_test(platforms.Byteorder.LITTLE)


class UnicornPPC64InitTests(unittest.TestCase):
    """PPC64MachineDef.__init__ used `super(...)` without calling __init__."""

    def test_ppc64_machdef_calls_base_init(self):
        calls = []

        def record_init(self, *args, **kwargs):
            calls.append((args, kwargs))

        with self.assertLogs(
            "smallworld.emulators.unicorn.machdefs.ppc", level="WARNING"
        ):
            with mock.patch.object(PPCMachineDef, "__init__", record_init):
                PPC64MachineDef()
        self.assertEqual(calls, [((), {})])

    def test_ppc64_machdef_instantiates_with_registers(self):
        with self.assertLogs(
            "smallworld.emulators.unicorn.machdefs.ppc", level="WARNING"
        ):
            machdef = PPC64MachineDef()
        self.assertEqual(machdef.uc_reg("r0"), unicorn.ppc_const.UC_PPC_REG_0)


class SysVFloatArgRegisterTests(unittest.TestCase):
    """Calling conventions were missing trailing FP argument registers."""

    def test_amd64_fp_arg_regs_include_xmm6_xmm7(self):
        expected = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"]
        self.assertEqual(AMD64SysVCallingContext._float_arg_regs, expected)
        self.assertEqual(AMD64SysVCallingContext._double_arg_regs, expected)

    def test_aarch64_fp_arg_regs_are_s0_to_s7_and_d0_to_d7(self):
        self.assertEqual(
            AArch64SysVCallingContext._float_arg_regs,
            ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"],
        )
        self.assertEqual(
            AArch64SysVCallingContext._double_arg_regs,
            ["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"],
        )

    def test_riscv64_fp_arg_regs_are_fa0_to_fa7(self):
        expected = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"]
        self.assertEqual(RiscV64SysVCallingContext._float_arg_regs, expected)
        self.assertEqual(RiscV64SysVCallingContext._double_arg_regs, expected)

    def test_mips64el_fp_arg_regs_include_f18(self):
        expected = ["f13", "f14", "f15", "f16", "f17", "f18"]
        self.assertEqual(MIPS64ELSysVCallingContext._float_arg_regs, expected)
        self.assertEqual(MIPS64ELSysVCallingContext._double_arg_regs, expected)
        # The big-endian variant always had the full list; they should agree.
        self.assertEqual(
            MIPS64ELSysVCallingContext._float_arg_regs,
            MIPS64SysVCallingContext._float_arg_regs,
        )
        self.assertEqual(
            MIPS64ELSysVCallingContext._double_arg_regs,
            MIPS64SysVCallingContext._double_arg_regs,
        )


class _RegisterDictEmulator:
    """Just enough of an emulator to satisfy calling-context register I/O."""

    def __init__(self, regs=None):
        self.regs = dict(regs or {})

    def read_register(self, name):
        return self.regs[name]

    def write_register(self, name, value):
        self.regs[name] = value


class MipsReturnDoubleTests(unittest.TestCase):
    """MIPS o32 _read_return_double read f0 as the high word and f1 as low."""

    def test_read_return_double_word_order(self):
        ctx = MIPSSysVCallingContext()
        # 1.0 is 0x3FF0000000000000: f0 (low word) = 0, f1 (high) = 0x3FF00000.
        emu = _RegisterDictEmulator({"f0": 0x00000000, "f1": 0x3FF00000})
        self.assertEqual(ctx._read_return_double(emu), 1.0)

    def test_return_double_roundtrip(self):
        ctx = MIPSSysVCallingContext()
        emu = _RegisterDictEmulator()
        ctx._return_double(emu, -1234.5678)
        self.assertEqual(ctx._read_return_double(emu), -1234.5678)


MODELS_AMD64 = platforms.Platform(
    platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
)
MODELS_AARCH64 = platforms.Platform(
    platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
)
MODELS_SYSV = platforms.ABI.SYSTEMV

# Address at which models are nominally hooked; never executed.
MODELS_HOOK_ADDR = 0x40000


class ModelsMockUnmappedError(Exception):
    """Raised by ModelTestEmulator on access to unmapped memory."""


class ModelTestEmulator(emulators.Emulator):
    """Minimal concrete emulator backed by plain dicts.

    Registers are a name -> int dict (32-bit x86 register names alias
    their 64-bit base register; reads through a 32-bit name are masked,
    writes store the raw value so tests can observe exactly what a model
    wrote).  Memory is a dict of independently mapped segments; any read
    or write that is not contained in a single segment raises
    ModelsMockUnmappedError.
    """

    name = "model-test-emulator"
    description = "mock emulator for unit-testing function models"
    version = "0.0"

    _REG_ALIASES = {
        "eax": "rax",
        "edi": "rdi",
        "esi": "rsi",
        "edx": "rdx",
        "ecx": "rcx",
        "r8d": "r8",
        "r9d": "r9",
    }

    def __init__(self, platform: typing.Optional[platforms.Platform] = None):
        super().__init__(platform if platform is not None else MODELS_AMD64)
        self.registers: typing.Dict[str, int] = {}
        self.segments: typing.Dict[int, bytearray] = {}
        self.map_calls: typing.List[typing.Tuple[int, int]] = []

    # *** Registers ***

    def read_register_content(self, name: str) -> int:
        base = self._REG_ALIASES.get(name, name)
        if base not in self.registers:
            raise KeyError(f"register {name} was never written")
        value = self.registers[base]
        if name in self._REG_ALIASES:
            value &= 0xFFFFFFFF
        return value

    def write_register_content(self, name: str, content) -> None:
        base = self._REG_ALIASES.get(name, name)
        if content is None:
            content = 0
        if not isinstance(content, int):
            raise TypeError(f"mock emulator cannot store {type(content)}")
        self.registers[base] = content

    # *** Memory ***

    def _segment_for(self, address: int, size: int):
        for start, buf in self.segments.items():
            if start <= address and address + size <= start + len(buf):
                return start, buf
        raise ModelsMockUnmappedError(
            f"[{address:#x}, {address + size:#x}) is not mapped "
            "within a single segment"
        )

    def read_memory_content(self, address: int, size: int) -> bytes:
        start, buf = self._segment_for(address, size)
        offset = address - start
        return bytes(buf[offset : offset + size])

    def write_memory_content(self, address: int, content) -> None:
        if not isinstance(content, (bytes, bytearray)):
            raise TypeError(f"mock emulator cannot store {type(content)}")
        data = bytes(content)
        start, buf = self._segment_for(address, len(data))
        offset = address - start
        buf[offset : offset + len(data)] = data

    def map_memory(self, address: int, size: int) -> None:
        self.map_calls.append((address, size))
        try:
            self._segment_for(address, size)
            return
        except ModelsMockUnmappedError:
            pass
        self.segments[address] = bytearray(size)

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        return [(s, s + len(buf)) for s, buf in sorted(self.segments.items())]

    # *** Execution (unsupported) ***

    def step_instruction(self) -> None:
        raise NotImplementedError("mock emulator cannot execute")

    def step_block(self) -> None:
        raise NotImplementedError("mock emulator cannot execute")

    def run(self) -> None:
        raise NotImplementedError("mock emulator cannot execute")

    def __repr__(self) -> str:
        return "ModelTestEmulator"


def _models_bytes_file(
    name: str, data: bytes, readable: bool = True, writable: bool = False
) -> SWBytesIO:
    """A seekable BytesIO-backed file stream for the fd manager."""
    return SWBytesIO(name, readable, writable, True, True, False, data=io.BytesIO(data))


class ModelTestCase(unittest.TestCase):
    """Common scaffolding for model tests.

    Provides a fresh mock emulator and resets the FileDescriptorManager
    and ProcInfoManager quasi-singletons so file descriptors and process
    state never leak between tests.
    """

    def setUp(self):
        FileDescriptorManager._singletons.clear()
        ProcInfoManager._singleton = None
        self.emu = ModelTestEmulator()
        logging.disable(logging.ERROR)

    def tearDown(self):
        FileDescriptorManager._singletons.clear()
        ProcInfoManager._singleton = None
        logging.disable(logging.NOTSET)

    @staticmethod
    def lookup(name: str, platform: platforms.Platform = MODELS_AMD64):
        return Model.lookup(name, platform, MODELS_SYSV, MODELS_HOOK_ADDR)

    def map_bytes(self, address: int, data: bytes, size: typing.Optional[int] = None):
        if size is None:
            size = len(data)
        self.emu.map_memory(address, size)
        self.emu.write_memory(address, data)

    def call(self, model, *int_args):
        """Assign the SysV amd64 argument registers and run the model."""
        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        for reg, value in zip(regs, int_args):
            self.emu.write_register(reg, value)
        model.model(self.emu)
        return model.get_return_value(self.emu)


class Dup2ModelTests(ModelTestCase):
    """posix/unistd.py Dup2: takes two int args and reads the second."""

    def test_dup2_signature_has_two_ints(self):
        dup2 = self.lookup("dup2")
        self.assertEqual(dup2.argument_types, [ArgumentType.INT, ArgumentType.INT])

    def test_dup2_duplicates_onto_requested_fd(self):
        dup2 = self.lookup("dup2")
        fdmgr = dup2._fdmgr

        ret = self.call(dup2, 1, 7)
        self.assertEqual(ret, 7)

        # fd 7 must now exist and reference a duplicate of fd 1's stream
        self.assertIn(7, fdmgr._fds)
        self.assertEqual(fdmgr.get_fd(7).name, fdmgr.get_fd(1).name)
        self.assertTrue(fdmgr.get_fd(7).writable())


class NiceModelTests(ModelTestCase):
    """posix/unistd.py Nice: out-of-range increment fails cleanly."""

    def test_nice_out_of_range_returns_minus_one_and_keeps_value(self):
        nice = self.lookup("nice")
        nice._procmgr.nice = 39

        ret = self.call(nice, 10)
        self.assertEqual(ret, -1)
        self.assertEqual(nice._procmgr.nice, 39)

    def test_nice_in_range_updates_value(self):
        nice = self.lookup("nice")
        nice._procmgr.nice = 10

        ret = self.call(nice, 5)
        self.assertEqual(ret, -5)  # (10 + 5) - 20
        self.assertEqual(nice._procmgr.nice, 15)


class SbrkModelTests(ModelTestCase):
    """posix/unistd.py Sbrk: returns the previous program break."""

    def test_sbrk_returns_previous_break(self):
        sbrk = self.lookup("sbrk")
        sbrk._procmgr.brk = 0x100000

        ret = self.call(sbrk, 0x2000)
        self.assertEqual(ret, 0x100000)
        self.assertEqual(sbrk._procmgr.brk, 0x102000)
        self.assertIn((0x100000, 0x2000), self.emu.map_calls)


class SigismemberModelTests(ModelTestCase):
    """posix/signal.py Sigismember: actually computes membership."""

    SIGSET = 0x4000

    def setUp(self):
        super().setUp()
        # Signal 10 set: signals are 1-indexed, so bit 9 of word 0.
        word0 = 1 << 9
        self.map_bytes(self.SIGSET, word0.to_bytes(8, "little") + b"\0" * 8)
        self.model = self.lookup("sigismember")

    def test_member_signal_returns_one(self):
        self.assertEqual(self.call(self.model, self.SIGSET, 10), 1)

    def test_non_member_signal_returns_zero(self):
        self.assertEqual(self.call(self.model, self.SIGSET, 11), 0)

    def test_out_of_range_signals_return_minus_one(self):
        self.assertEqual(self.call(self.model, self.SIGSET, 0), -1)
        self.assertEqual(self.call(self.model, self.SIGSET, 65), -1)


class TtynameModelTests(ModelTestCase):
    """posix/unistd.py Ttyname/TtynameR: fd guard is 0 <= fd <= 2."""

    STATIC_BUF = 0x5000
    OUT_BUF = 0x5200

    def test_ttyname_stdout_returns_static_buffer_with_name(self):
        model = self.lookup("ttyname")
        model.allow_imprecise = True
        model.static_buffer_address = self.STATIC_BUF
        self.emu.map_memory(self.STATIC_BUF, 16)

        ret = self.call(model, 1)
        self.assertEqual(ret, self.STATIC_BUF)
        data = self.emu.read_memory(self.STATIC_BUF, 11)
        self.assertEqual(data, b"/dev/pty/0\0")

    def test_ttyname_non_tty_fd_returns_null(self):
        model = self.lookup("ttyname")
        model.allow_imprecise = True
        model.static_buffer_address = self.STATIC_BUF
        self.emu.map_memory(self.STATIC_BUF, 16)

        ret = self.call(model, 5)
        self.assertEqual(ret, 0)

    def test_ttyname_r_stdout_writes_buffer(self):
        model = self.lookup("ttyname_r")
        model.allow_imprecise = True
        self.emu.map_memory(self.OUT_BUF, 32)

        ret = self.call(model, 1, self.OUT_BUF, 32)
        self.assertEqual(ret, 0)
        self.assertEqual(self.emu.read_memory(self.OUT_BUF, 11), b"/dev/pty/0\0")

    def test_ttyname_r_non_tty_fd_fails(self):
        model = self.lookup("ttyname_r")
        model.allow_imprecise = True
        self.emu.map_memory(self.OUT_BUF, 32)

        ret = self.call(model, 5, self.OUT_BUF, 32)
        self.assertEqual(ret, -1)


class FDMgrAccessModelTests(ModelTestCase):
    """posix/unistd.py Write/Lseek: use fdmgr.get_fd (not nonexistent .get)."""

    def test_write_to_stdout_fd(self):
        model = self.lookup("write")
        backing = io.BytesIO()
        model._fdmgr._fds[1] = SWBytesIO(
            "stdout", False, True, True, True, False, data=backing
        )
        self.map_bytes(0x2000, b"hello")

        ret = self.call(model, 1, 0x2000, 5)
        self.assertEqual(ret, 5)
        self.assertEqual(backing.getvalue(), b"hello")

    def test_lseek_on_seekable_fd(self):
        model = self.lookup("lseek")
        fdmgr = model._fdmgr
        fdmgr.add_file("f.txt", b"abcdef")
        fd = fdmgr.open("f.txt", True, False, False, False, False)

        ret = self.call(model, fd, 4, 0)
        self.assertEqual(ret, 4)
        self.assertEqual(fdmgr.get_fd(fd).tell(), 4)


class CallocModelTests(ModelTestCase):
    """c99/stdlib.py Calloc: size_t overflow returns NULL."""

    HEAP_ADDR = 0x60000

    def _calloc(self):
        model = self.lookup("calloc")
        model.heap = BumpAllocator(self.HEAP_ADDR, 0x1000)
        self.emu.map_memory(self.HEAP_ADDR, 0x1000)
        return model

    def test_calloc_normal_allocation(self):
        model = self._calloc()
        ret = self.call(model, 4, 8)
        self.assertEqual(ret, self.HEAP_ADDR)
        self.assertEqual(self.emu.read_memory(ret, 32), b"\0" * 32)

    def test_calloc_size_t_overflow_returns_null(self):
        model = self._calloc()
        ret = self.call(model, 1 << 32, 1 << 32)
        self.assertEqual(ret, 0)


class SnprintfModelTests(ModelTestCase):
    """c99/stdio.py Snprintf: honors the size limit."""

    BUF = 0x2000
    FMT = 0x2100

    def setUp(self):
        super().setUp()
        self.map_bytes(self.BUF, b"\xaa" * 16)
        self.map_bytes(self.FMT, b"hello world!\0")
        self.model = self.lookup("snprintf")

    def test_snprintf_truncates_to_size(self):
        ret = self.call(self.model, self.BUF, 5, self.FMT)
        # Return value is the untruncated length
        self.assertEqual(ret, 12)
        data = self.emu.read_memory(self.BUF, 16)
        self.assertEqual(data[:5], b"hell\0")
        # Bytes past the size limit must be untouched
        self.assertEqual(data[5:], b"\xaa" * 11)

    def test_snprintf_size_zero_writes_nothing(self):
        ret = self.call(self.model, self.BUF, 0, self.FMT)
        self.assertEqual(ret, 12)
        self.assertEqual(self.emu.read_memory(self.BUF, 16), b"\xaa" * 16)


class GetcEOFModelTests(ModelTestCase):
    """c99/stdio.py Fgetc/Getc/Getchar: EOF returns -1, not IndexError."""

    def _set_stdin(self, data: bytes) -> None:
        fdmgr = FileDescriptorManager.for_platform(MODELS_AMD64, MODELS_SYSV)
        fdmgr._fds[0] = _models_bytes_file("stdin", data)

    def test_getchar_returns_data_then_eof(self):
        self._set_stdin(b"A")
        model = self.lookup("getchar")
        model.model(self.emu)
        self.assertEqual(model.get_return_value(self.emu), ord("A"))
        model.model(self.emu)
        self.assertEqual(model.get_return_value(self.emu), -1)

    def test_fgetc_at_eof_returns_minus_one(self):
        self._set_stdin(b"")
        model = self.lookup("fgetc")
        ret = self.call(model, model._fdmgr.stdin_filestar)
        self.assertEqual(ret, -1)

    def test_getc_at_eof_returns_minus_one(self):
        self._set_stdin(b"")
        model = self.lookup("getc")
        ret = self.call(model, model._fdmgr.stdin_filestar)
        self.assertEqual(ret, -1)


class FreopenSignatureTests(unittest.TestCase):
    """c99/stdio.py Freopen: takes three pointer arguments."""

    def test_freopen_argument_types(self):
        self.assertEqual(
            Freopen.argument_types,
            [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.POINTER],
        )


class VsscanfNameTests(ModelTestCase):
    """c99/stdio.py Vsscanf: named vsscanf, not colliding with Vsprintf."""

    def test_vsscanf_class_name(self):
        self.assertEqual(Vsscanf.name, "vsscanf")

    def test_vsprintf_lookup_resolves_to_vsprintf(self):
        model = self.lookup("vsprintf")
        self.assertIsInstance(model, Vsprintf)
        self.assertNotIsInstance(model, Vsscanf)

    def test_vsscanf_lookup_resolves_to_vsscanf(self):
        model = self.lookup("vsscanf")
        self.assertIsInstance(model, Vsscanf)


class EmuStrnlenTests(ModelTestCase):
    """c99/utils.py _emu_strnlen: never reads past the n-byte window."""

    def test_strnlen_does_not_read_past_limit(self):
        # Exactly 16 non-NUL bytes; the byte at addr + 16 is unmapped, so
        # reading past the window raises in the mock emulator.
        self.map_bytes(0x7000, b"A" * 16)
        self.assertEqual(_emu_strnlen(self.emu, 0x7000, 16), 16)

    def test_strnlen_stops_at_nul(self):
        self.map_bytes(0x7000, b"AB\0" + b"C" * 13)
        self.assertEqual(_emu_strnlen(self.emu, 0x7000, 16), 2)


class EmuMemcmpStrncmpTests(ModelTestCase):
    """c99/utils.py _emu_memcmp/_emu_strncmp: bulk path plus fallback."""

    def setUp(self):
        super().setUp()
        self.map_bytes(0x9000, b"abcdefgh" + b"\0" * 8)
        self.map_bytes(0x9100, b"abcdefgh" + b"\0" * 8)
        self.map_bytes(0x9200, b"abcdefgz" + b"\0" * 8)
        self.map_bytes(0x9300, b"abc\0defg" + b"\0" * 8)
        self.map_bytes(0x9400, b"abc\0xyzw" + b"\0" * 8)

    def test_memcmp_equal_and_differing(self):
        self.assertEqual(_emu_memcmp(self.emu, 0x9000, 0x9100, 8), 0)
        self.assertLess(_emu_memcmp(self.emu, 0x9000, 0x9200, 8), 0)
        self.assertGreater(_emu_memcmp(self.emu, 0x9200, 0x9000, 8), 0)

    def test_strncmp_equal_differing_and_nul_stop(self):
        self.assertEqual(_emu_strncmp(self.emu, 0x9000, 0x9100, 8), 0)
        self.assertLess(_emu_strncmp(self.emu, 0x9000, 0x9200, 8), 0)
        # Both strings end at index 3; bytes beyond the NUL must not matter
        self.assertEqual(_emu_strncmp(self.emu, 0x9300, 0x9400, 8), 0)

    def _map_straddling(self, data: bytes) -> int:
        """Write 8 bytes across two adjacent-but-separate segments.

        Bulk reads of the full range fail in the mock emulator while
        single-byte reads succeed, forcing the byte-wise fallback.
        """
        self.emu.map_memory(0x8000, 8)
        self.emu.map_memory(0x8008, 8)
        self.emu.write_memory(0x8004, data[:4])
        self.emu.write_memory(0x8008, data[4:])
        return 0x8004

    def test_memcmp_falls_back_on_bulk_read_failure(self):
        ptr1 = self._map_straddling(b"abcdefgh")
        with self.assertRaises(ModelsMockUnmappedError):
            self.emu.read_memory(ptr1, 8)
        self.assertEqual(_emu_memcmp(self.emu, ptr1, 0x9000, 8), 0)
        self.assertLess(_emu_memcmp(self.emu, ptr1, 0x9200, 8), 0)

    def test_strncmp_falls_back_on_bulk_read_failure(self):
        ptr1 = self._map_straddling(b"abcdefgh")
        with self.assertRaises(ModelsMockUnmappedError):
            self.emu.read_memory(ptr1, 8)
        self.assertEqual(_emu_strncmp(self.emu, ptr1, 0x9000, 8), 0)
        self.assertLess(_emu_strncmp(self.emu, ptr1, 0x9200, 8), 0)


class StringSearchModelTests(ModelTestCase):
    """c99/string.py Strstr/Memchr/Strchr/Strrchr rewritten with find/rfind."""

    HAY = 0x2000
    NEEDLE = 0x2100
    EMPTY = 0x2200
    ABS = 0x2300
    ABC = 0x2400

    def setUp(self):
        super().setUp()
        self.map_bytes(self.HAY, b"hello world\0")
        self.map_bytes(self.NEEDLE, b"lo w\0")
        self.map_bytes(self.EMPTY, b"\0")
        self.map_bytes(self.ABS, b"zq\0")
        self.map_bytes(self.ABC, b"abcabc\0")

    def test_strstr_finds_substring(self):
        model = self.lookup("strstr")
        self.assertEqual(self.call(model, self.HAY, self.NEEDLE), self.HAY + 3)

    def test_strstr_absent_needle_returns_null(self):
        model = self.lookup("strstr")
        self.assertEqual(self.call(model, self.HAY, self.ABS), 0)

    def test_strstr_empty_haystack_returns_null(self):
        model = self.lookup("strstr")
        self.assertEqual(self.call(model, self.EMPTY, self.NEEDLE), 0)

    def test_memchr_within_n(self):
        model = self.lookup("memchr")
        self.assertEqual(self.call(model, self.ABC, ord("b"), 6), self.ABC + 1)

    def test_memchr_respects_n_and_absent_value(self):
        model = self.lookup("memchr")
        self.assertEqual(self.call(model, self.ABC, ord("c"), 2), 0)
        self.assertEqual(self.call(model, self.ABC, ord("z"), 6), 0)

    def test_strchr_returns_first_occurrence(self):
        model = self.lookup("strchr")
        self.assertEqual(self.call(model, self.ABC, ord("b")), self.ABC + 1)

    def test_strrchr_returns_last_occurrence(self):
        model = self.lookup("strrchr")
        self.assertEqual(self.call(model, self.ABC, ord("b")), self.ABC + 4)


class SetArgumentEncodingTests(ModelTestCase):
    """cstd.py set_argument: negative values encode by the ARG type."""

    def test_negative_int_argument_uses_four_byte_encoding(self):
        # write() has a 4-byte INT first arg but an 8-byte SSIZE_T return
        # type; the two's complement must follow the argument type.
        model = self.lookup("write")
        model.set_argument(0, self.emu, -1)
        self.assertEqual(self.emu.registers["rdi"], 0xFFFFFFFF)

    def test_negative_ssize_t_argument_with_void_return(self):
        # swab() returns void; encoding a negative SSIZE_T argument must
        # not consult the return type at all.
        model = self.lookup("swab")
        model.set_argument(2, self.emu, -5)
        self.assertEqual(self.emu.registers["rdx"], (1 << 64) - 5)


class TlsGetAddrModelTests(ModelTestCase):
    """c99/stdlib.py TlsGetAddr: stable per-(module, offset) storage."""

    TI1 = 0x4000
    TI2 = 0x4010

    def setUp(self):
        super().setUp()
        self.emu.map_memory(0x4000, 32)
        # tls_index structs: {module, offset} as two 8-byte words
        self.emu.write_memory(
            self.TI1, (1).to_bytes(8, "little") + (0x10).to_bytes(8, "little")
        )
        self.emu.write_memory(
            self.TI2, (2).to_bytes(8, "little") + (0x10).to_bytes(8, "little")
        )
        self.model = self.lookup("__tls_get_addr")

    def test_requires_heap(self):
        self.emu.write_register("rdi", self.TI1)
        with self.assertRaises(exceptions.ConfigurationError):
            self.model.model(self.emu)

    def test_stable_and_distinct_addresses(self):
        self.model.heap = BumpAllocator(0x60000, 0x4000)

        first = self.call(self.model, self.TI1)
        self.assertNotEqual(first, 0)

        again = self.call(self.model, self.TI1)
        self.assertEqual(again, first)

        other = self.call(self.model, self.TI2)
        self.assertNotEqual(other, first)


class ErrnoLocationModelTests(ModelTestCase):
    """posix/unistd.py ErrnoLocation: returns its static buffer address."""

    def test_returns_static_buffer_address(self):
        model = self.lookup("__errno_location")
        self.assertEqual(model.static_space_required, 8)
        model.static_buffer_address = 0x5100
        ret = self.call(model)
        self.assertEqual(ret, 0x5100)


class ScanfScansetTests(ModelTestCase):
    """c99/fmt_scan.py handle_constrained: non-negated scansets work."""

    SRC = 0x3000
    FMT = 0x3100
    OUT = 0x3200

    def test_sscanf_non_negated_scanset(self):
        self.map_bytes(self.SRC, b"abcd\0")
        self.map_bytes(self.FMT, b"%[abc]\0")
        self.emu.map_memory(self.OUT, 16)

        model = self.lookup("sscanf")
        ret = self.call(model, self.SRC, self.FMT, self.OUT)
        self.assertEqual(ret, 1)
        self.assertEqual(self.emu.read_memory(self.OUT, 4), b"abc\0")

    def test_sscanf_negated_scanset(self):
        self.map_bytes(self.SRC, b"xyzc\0")
        self.map_bytes(self.FMT, b"%[^abc]\0")
        self.emu.map_memory(self.OUT, 16)

        model = self.lookup("sscanf")
        ret = self.call(model, self.SRC, self.FMT, self.OUT)
        self.assertEqual(ret, 1)
        self.assertEqual(self.emu.read_memory(self.OUT, 4), b"xyz\0")


class C99LibcConstructionTests(ModelTestCase):
    """c99/libc.py + library.py: unbound names skipped, region sized right."""

    LIB_ADDR = 0x100000

    def test_aarch64_construction_skips_unbound_models(self):
        # __tls_get_addr is only bound on amd64; the aarch64 library must
        # still construct, simply omitting the unbound model.
        lib = C99Libc(self.LIB_ADDR, MODELS_AARCH64, MODELS_SYSV)
        self.assertNotIn("__tls_get_addr", lib.models)
        self.assertIn("malloc", lib.models)

    def test_amd64_construction_includes_tls_get_addr(self):
        lib = C99Libc(self.LIB_ADDR, MODELS_AMD64, MODELS_SYSV)
        self.assertIn("__tls_get_addr", lib.models)

    def test_static_buffers_fit_within_region(self):
        lib = C99Libc(self.LIB_ADDR, MODELS_AMD64, MODELS_SYSV)
        region_end = lib.address + lib.get_capacity()
        checked = 0
        for model in lib.models.values():
            if model.static_space_required > 0:
                self.assertIsNotNone(model.static_buffer_address)
                self.assertLessEqual(
                    model.static_buffer_address + model.static_space_required,
                    region_end,
                    f"static buffer of {model.name} overflows the region",
                )
                checked += 1
        self.assertGreater(checked, 0)


class SwabModelTests(ModelTestCase):
    """posix/unistd.py Swab: bulk byte-pair swapping."""

    SRC = 0x2000
    DST = 0x2100

    def setUp(self):
        super().setUp()
        self.map_bytes(self.SRC, b"abcdef\xee\xee")
        self.model = self.lookup("swab")

    def _reset_dst(self):
        self.map_bytes(self.DST, b"\xcc" * 8)

    def test_swab_even_size(self):
        self._reset_dst()
        self.call(self.model, self.SRC, self.DST, 4)
        self.assertEqual(self.emu.read_memory(self.DST, 8), b"badc" + b"\xcc" * 4)

    def test_swab_odd_size_touches_rounded_up_range(self):
        self._reset_dst()
        self.call(self.model, self.SRC, self.DST, 5)
        self.assertEqual(self.emu.read_memory(self.DST, 8), b"badcfe" + b"\xcc" * 2)

    def test_swab_size_zero_writes_nothing(self):
        self._reset_dst()
        self.call(self.model, self.SRC, self.DST, 0)
        self.assertEqual(self.emu.read_memory(self.DST, 8), b"\xcc" * 8)

    def test_swab_negative_size_writes_nothing(self):
        self._reset_dst()
        self.call(self.model, self.SRC, self.DST, (1 << 64) - 3)
        self.assertEqual(self.emu.read_memory(self.DST, 8), b"\xcc" * 8)


class _ModelsRecvSocket(SocketIO):
    """SocketIO with a canned datagram and peer for recvfrom tests."""

    def __init__(self, data: bytes, peer: SockaddrIn):
        super().__init__("Socket", 2, 1, 0, True)
        self._data = data
        self._peer = peer

    def on_recv(self):
        return (self._data, self._peer)


class RecvfromModelTests(ModelTestCase):
    """posix/sys/socket.py Recvfrom: writes the length to addrlen."""

    BUF = 0x2000
    ADDR = 0x2100
    ADDRLEN = 0x2200

    def test_recvfrom_writes_addr_and_addrlen_separately(self):
        model = self.lookup("recvfrom")
        peer = SockaddrIn(0x7F000001, 5555)
        model._fdmgr._fds[5] = _ModelsRecvSocket(b"ping", peer)

        self.emu.map_memory(self.BUF, 16)
        self.emu.map_memory(self.ADDR, 16)
        self.emu.map_memory(self.ADDRLEN, 4)

        ret = self.call(model, 5, self.BUF, 16, 0, self.ADDR, self.ADDRLEN)
        self.assertEqual(ret, 4)
        self.assertEqual(self.emu.read_memory(self.BUF, 4), b"ping")
        # The sockaddr goes to addr...
        self.assertEqual(self.emu.read_memory(self.ADDR, 16), peer.to_bytes("little"))
        # ...and its LENGTH goes to addrlen, not on top of addr.
        self.assertEqual(
            self.emu.read_memory(self.ADDRLEN, 4), (16).to_bytes(4, "little")
        )


def _make_symbol(value: int, baseaddr: int) -> ElfSymbol:
    return ElfSymbol(
        idx=0,
        dynamic=False,
        name="test_symbol",
        type=0,
        bind=0,
        visibility=0,
        shndx=1,
        defined=True,
        value=value,
        size=0,
        baseaddr=baseaddr,
    )


class _FakeElf:
    def __init__(self, address: int):
        self.address = address


class AMD64StackInitTests(unittest.TestCase):
    def test_argv_pointers_are_absolute_addresses(self):
        # Each argv[i] pointer on the stack must be the absolute address
        # of the pushed string, not its stack-relative offset.
        argv = [b"foo\0", b"barbaz\0"]
        s = AMD64Stack.initialize_stack(argv, 0x71000000, 0x1000)

        strings = {}
        pointers = {}
        for offset, value in s.items():
            label = value.get_label()
            for i, arg in enumerate(argv):
                if label == f"argv[{i}]":
                    strings[i] = s.address + offset
                elif label == f"pointer to argv[{i}]":
                    pointers[i] = int.from_bytes(value.to_bytes(), "little")

        self.assertEqual(len(strings), len(argv))
        self.assertEqual(len(pointers), len(argv))
        for i in range(len(argv)):
            self.assertEqual(pointers[i], strings[i])
            data = s.to_bytes()
            start = strings[i] - s.address
            self.assertEqual(data[start : start + len(argv[i])], argv[i])

    def test_no_extra_padding_when_already_aligned(self):
        # If argc/argv content is already 16-byte aligned, no padding
        # bytes should be inserted (the old formula inserted 16).
        argv = [b"aaaaaaa\0", b"bbbbbbb\0"]  # 16 string bytes
        s = AMD64Stack.initialize_stack(argv, 0x71000000, 0x1000)
        # strings (16) + padding (0) + NULL (8) + 2 pointers (16) + argc (8)
        self.assertEqual(s.get_pointer(), 0x71000000 + 0x1000 - 48)
        self.assertEqual(s.get_pointer() % 16, 0)

    def test_stack_pointer_is_aligned_with_padding(self):
        argv = [b"foo\0", b"barbaz\0"]  # 11 string bytes
        s = AMD64Stack.initialize_stack(argv, 0x71000000, 0x1000)
        self.assertEqual(s.get_pointer() % 16, 0)


class I386RelocatorTests(unittest.TestCase):
    def test_r_386_32_masks_overflow_to_32_bits(self):
        # A symbol+addend sum that overflows 32 bits must be truncated,
        # not raise OverflowError from int.to_bytes.
        relocator = I386ElfRelocator()
        rela = ElfRela(
            is_rela=True,
            offset=0x1000,
            type=1,  # R_386_32
            symbol=_make_symbol(value=0xFFFFFFFF, baseaddr=0),
            addend=0x10,
        )
        val = relocator._compute_value(rela, None)
        self.assertEqual(val, (0x0000000F).to_bytes(4, "little"))

    def test_r_386_32_masks_negative_value(self):
        relocator = I386ElfRelocator()
        rela = ElfRela(
            is_rela=True,
            offset=0x1000,
            type=1,  # R_386_32
            symbol=_make_symbol(value=0x10, baseaddr=0),
            addend=-0x20,
        )
        val = relocator._compute_value(rela, None)
        self.assertEqual(val, (0xFFFFFFF0).to_bytes(4, "little"))

    def test_r_386_relative_masks_to_32_bits(self):
        relocator = I386ElfRelocator()
        rela = ElfRela(
            is_rela=True,
            offset=0x1000,
            type=8,  # R_386_RELATIVE
            symbol=_make_symbol(value=0, baseaddr=0),
            addend=0x20,
        )
        val = relocator._compute_value(rela, _FakeElf(0xFFFFFFF0))
        self.assertEqual(val, (0x00000010).to_bytes(4, "little"))


class FindSubclassCacheTests(unittest.TestCase):
    """Tests for the find_subclass cache_key memoization."""

    class _Base:
        marker: str = ""

        def __init__(self, tag):
            self.tag = tag

    class _ImplA(_Base):
        marker = "a"

    class _ImplB(_Base):
        marker = "b"

    def test_cached_lookup_returns_fresh_instances(self):
        first = utils.find_subclass(
            self._Base, lambda x: x.marker == "a", 1, cache_key="marker-a"
        )
        second = utils.find_subclass(
            self._Base, lambda x: x.marker == "a", 2, cache_key="marker-a"
        )
        self.assertIsInstance(first, self._ImplA)
        self.assertIsInstance(second, self._ImplA)
        self.assertIsNot(first, second)
        self.assertEqual(first.tag, 1)
        self.assertEqual(second.tag, 2)

    def test_distinct_cache_keys_resolve_independently(self):
        a = utils.find_subclass(
            self._Base, lambda x: x.marker == "a", 0, cache_key="key-a"
        )
        b = utils.find_subclass(
            self._Base, lambda x: x.marker == "b", 0, cache_key="key-b"
        )
        self.assertIsInstance(a, self._ImplA)
        self.assertIsInstance(b, self._ImplB)

    def test_model_lookup_memoized_instances_are_distinct(self):
        platform = platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )
        one = Model.lookup("strlen", platform, platforms.ABI.SYSTEMV, 0x1000)
        two = Model.lookup("strlen", platform, platforms.ABI.SYSTEMV, 0x2000)
        self.assertIsNot(one, two)
        self.assertIs(type(one), type(two))
        self.assertEqual(one.name, "strlen")
        self.assertEqual(one._address, 0x1000)
        self.assertEqual(two._address, 0x2000)


def _amd64_platform():
    return platforms.Platform(platforms.Architecture.X86_64, platforms.Byteorder.LITTLE)


class EmulatorExitPointCopyTests(unittest.TestCase):
    """Emulator.get_exit_points() must return a copy, not the internal set.

    Previously it returned the internal set itself, so callers mutating the
    result silently corrupted the emulator's exit-point bookkeeping.
    """

    def setUp(self):
        self.emu = emulators.UnicornEmulator(_amd64_platform())
        self.emu.add_exit_point(0x1000)

    def test_mutating_returned_set_does_not_add_exit_points(self):
        pts = self.emu.get_exit_points()
        pts.add(0x9999)
        self.assertEqual(self.emu.get_exit_points(), {0x1000})

    def test_clearing_returned_set_does_not_remove_exit_points(self):
        pts = self.emu.get_exit_points()
        pts.clear()
        self.assertEqual(self.emu.get_exit_points(), {0x1000})


class UnicornRegisterLabelReadTests(unittest.TestCase):
    """read_register_label must return None when no labels exist.

    Previously, once any byte of a base register was labeled, reading the
    label of a disjoint sub-register returned "" (a join over an empty set)
    instead of None.
    """

    def setUp(self):
        self.emu = emulators.UnicornEmulator(_amd64_platform())

    def test_fresh_register_label_is_none(self):
        self.assertIsNone(self.emu.read_register_label("rax"))

    def test_labeled_subregister_reads_back(self):
        self.emu.write_register_label("al", "tag")
        self.assertEqual(self.emu.read_register_label("al"), "tag")
        self.assertEqual(self.emu.read_register_label("rax"), "tag")

    def test_unlabeled_bytes_of_labeled_base_register_are_none(self):
        # "al" labels byte 0 of rax; "ah" is byte 1, which stays unlabeled.
        # The base register IS present in the label map, so this exercises
        # the empty-label-set path that used to return "".
        self.emu.write_register_label("al", "tag")
        self.assertIsNone(self.emu.read_register_label("ah"))


class UnicornUnsupportedRegisterTests(unittest.TestCase):
    """Registers whose unicorn id is 0 must raise UnsupportedRegisterError.

    On amd64, "fpr0" (among others) maps to UC_X86_REG_INVALID (0).
    Reads already raised, but with a literal "{name}" placeholder in the
    message; writes did not check at all and fell through to unicorn.
    """

    def setUp(self):
        self.emu = emulators.UnicornEmulator(_amd64_platform())

    def test_write_invalid_register_raises_unsupported(self):
        with self.assertRaises(exceptions.UnsupportedRegisterError) as cm:
            self.emu.write_register_content("fpr0", 1)
        self.assertIn("fpr0", str(cm.exception))
        self.assertNotIn("{name}", str(cm.exception))

    def test_read_invalid_register_message_names_register(self):
        with self.assertRaises(exceptions.UnsupportedRegisterError) as cm:
            self.emu.read_register_content("fpr0")
        self.assertIn("fpr0", str(cm.exception))
        self.assertNotIn("{name}", str(cm.exception))


class AngrPreInitHookBookkeepingTests(unittest.TestCase):
    """Pre-initialization hook bookkeeping in AngrEmulator.

    These exercise the cached hook lists an uninitialized AngrEmulator
    maintains, without ever starting emulation.
    """

    def setUp(self):
        self.emu = emulators.AngrEmulator(_amd64_platform())

    @staticmethod
    def _read_cb(emu, addr, size, value):
        return None

    def test_unhook_memory_read_removes_only_exact_range(self):
        # The old filter used `and`, which also removed any hook sharing
        # either endpoint with the range being unhooked.
        self.emu.hook_memory_read(0x1000, 0x1004, self._read_cb)
        self.emu.hook_memory_read(0x1000, 0x2000, self._read_cb)

        self.emu.unhook_memory_read(0x1000, 0x1004)

        ranges = [(start, end) for start, end, _ in self.emu._read_hooks]
        self.assertNotIn((0x1000, 0x1004), ranges)
        self.assertEqual(ranges, [(0x1000, 0x2000)])

    def test_unhook_instructions_clears_pending_global_hook(self):
        def cb(emu):
            pass

        self.emu.hook_instructions(cb)
        self.assertIs(self.emu._gb_instr_hook, cb)

        self.emu.unhook_instructions()

        # The old code assigned to a nonexistent attribute
        # (_gb_instruction_hook), leaving the real one set.
        self.assertIsNone(self.emu._gb_instr_hook)
        self.assertFalse(hasattr(self.emu, "_gb_instruction_hook"))

    def test_unhook_memory_writes_clears_write_hook_only(self):
        def write_cb(emu, addr, size, value):
            pass

        self.emu.hook_memory_writes(write_cb)
        self.emu.hook_memory_reads(self._read_cb)
        self.assertIsNotNone(self.emu._gb_write_hook)
        self.assertIsNotNone(self.emu._gb_read_hook)

        # The old code had no pre-init path (it touched self.state, which
        # does not exist yet) and removed the READ hook when it did run.
        self.emu.unhook_memory_writes()

        self.assertIsNone(self.emu._gb_write_hook)
        self.assertIsNotNone(self.emu._gb_read_hook)


class AngrGlobalReadUnhookTests(unittest.TestCase):
    """unhook_memory_reads presence check on an initialized AngrEmulator.

    The old code raised ConfigurationError when a global read hook WAS
    present (inverted check) and tried to remove a None breakpoint when
    one was absent.
    """

    def _initialized_emulator(self):
        emu = emulators.AngrEmulator(_amd64_platform())
        emu.write_code(0x1000, b"\x90" * 16)
        emu.initialize()
        return emu

    def test_unhook_removes_installed_global_read_hook(self):
        emu = self._initialized_emulator()

        def cb(e, addr, size, expr):
            return None

        emu.hook_memory_reads_symbolic(cb)
        self.assertIsNotNone(emu.state.scratch.global_read_bp)

        emu.unhook_memory_reads()

        self.assertIsNone(emu.state.scratch.global_read_bp)

    def test_unhook_without_hook_raises_configuration_error(self):
        emu = self._initialized_emulator()
        with self.assertRaises(exceptions.ConfigurationError):
            emu.unhook_memory_reads()


class AngrNWBTAnalysisInitTests(unittest.TestCase):
    """AngrNWBTAnalysis.__init__ must forward to the base Analysis.

    Previously it never called super().__init__, so the hinter was
    silently dropped and the instance had no `hinter` attribute.
    """

    def test_hinter_reaches_base_analysis(self):
        from smallworld.analyses.unstable.angr_nwbt import AngrNWBTAnalysis

        hinter = hinting.Hinter()
        analysis = AngrNWBTAnalysis(hinter, max_steps=10)
        self.assertIs(analysis.hinter, hinter)
        self.assertEqual(analysis.steps_left, 10)


class FieldDetectionFilterTests(unittest.TestCase):
    """FieldDetectionFilter must accept a hinter and register with it.

    Previously __init__ took no hinter (and called super().__init__()
    with no arguments, which the base Analysis rejects), and activate()
    called a nonexistent self.listen().
    """

    def _make_filter(self, hinter):
        from smallworld.analyses.field_detection.field_analysis import (
            FieldDetectionFilter,
        )

        # FieldDetectionFilter inherits the abstract Analysis.run, so give
        # it a trivial implementation to allow instantiation.
        class ConcreteFilter(FieldDetectionFilter):
            def run(self, machine):
                pass

        return ConcreteFilter(hinter)

    def test_init_stores_hinter(self):
        hinter = hinting.Hinter()
        filt = self._make_filter(hinter)
        self.assertIs(filt.hinter, hinter)
        self.assertEqual(filt.partial_ranges, {})

    def test_activate_registers_analyze_with_hinter(self):
        from smallworld.analyses.field_detection.hints import FieldEventHint

        hinter = hinting.Hinter()
        filt = self._make_filter(hinter)
        filt.activate()

        self.assertIn(FieldEventHint, hinter.callbacks)
        self.assertIn(filt.analyze, hinter.callbacks[FieldEventHint])

    def test_sent_field_event_hint_reaches_analyze(self):
        from smallworld.analyses.field_detection.hints import FieldEventHint

        hinter = hinting.Hinter()
        filt = self._make_filter(hinter)
        filt.activate()

        hint = FieldEventHint(
            message="unit-test field event",
            address=0x1000,
            size=4,
            pc=0x400000,
            access="read",
        )
        # analyze() pretty-prints every FieldEventHint via log.error.
        with self.assertLogs(
            "smallworld.analyses.field_detection.field_analysis", level="ERROR"
        ) as captured:
            hinter.send(hint)
        self.assertTrue(
            any("unit-test field event" in line for line in captured.output)
        )


@unittest.skipUnless(_STYX_AVAILABLE, "styx_emulator not installed")
class StyxInterruptDispatcherTests(unittest.TestCase):
    """Exactly one processor-level InterruptHook dispatcher is registered.

    The old code registered a second InterruptHook when hook_interrupt()
    was followed by hook_interrupts(), double-firing handlers.
    """

    def setUp(self):
        self.platform = platforms.Platform(
            platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
        )
        self.emu = emulators.StyxEmulator(self.platform)
        self.per_calls = []
        self.glob_calls = []

    def _per_handler(self, emu):
        self.per_calls.append(emu)
        return True

    def _glob_handler(self, emu, intno):
        self.glob_calls.append(intno)
        return True

    def _capture_dispatchers(self, *hook_calls):
        """Run the given hook registrations, capturing InterruptHook uses.

        Returns the list of dispatcher callbacks wrapped in InterruptHook
        objects (one entry per processor-level registration).
        """
        import smallworld.emulators.styx.styx as styx_module

        captured = []
        registered = []

        def fake_interrupt_hook(cb):
            captured.append(cb)
            return ("interrupt-hook", cb)

        with mock.patch.object(
            styx_module, "InterruptHook", side_effect=fake_interrupt_hook
        ):
            with mock.patch.object(
                self.emu, "_register_styx_hook", side_effect=registered.append
            ):
                for call in hook_calls:
                    call()

        interrupt_registrations = [
            item
            for item in registered
            if isinstance(item, tuple) and item[0] == "interrupt-hook"
        ]
        self.assertEqual(len(captured), len(interrupt_registrations))
        return captured

    def test_per_number_then_global_registers_single_dispatcher(self):
        dispatchers = self._capture_dispatchers(
            lambda: self.emu.hook_interrupt(3, self._per_handler),
            lambda: self.emu.hook_interrupts(self._glob_handler),
        )
        self.assertEqual(len(dispatchers), 1)

        dispatcher = dispatchers[0]

        # A hooked interrupt number fires ONLY the per-number handler, once.
        dispatcher(object(), 3)
        self.assertEqual(self.per_calls, [self.emu])
        self.assertEqual(self.glob_calls, [])

        # An unhooked number falls through to the global handler, once.
        dispatcher(object(), 5)
        self.assertEqual(self.per_calls, [self.emu])
        self.assertEqual(self.glob_calls, [5])

    def test_global_then_per_number_registers_single_dispatcher(self):
        dispatchers = self._capture_dispatchers(
            lambda: self.emu.hook_interrupts(self._glob_handler),
            lambda: self.emu.hook_interrupt(3, self._per_handler),
        )
        self.assertEqual(len(dispatchers), 1)

        dispatcher = dispatchers[0]
        dispatcher(object(), 3)
        self.assertEqual(self.per_calls, [self.emu])
        self.assertEqual(self.glob_calls, [])
        dispatcher(object(), 5)
        self.assertEqual(self.glob_calls, [5])


class RangeCollectionMissingRangesSignatureTests(unittest.TestCase):
    """get_missing_ranges takes a single (start, end) tuple.

    Documents the signature relied on by the fixed angr.py callbacks:
    the old call sites passed two separate ints, which TypeErrors.
    """

    def test_takes_single_range_tuple(self):
        rc = utils.RangeCollection()
        rc.add_range((0x1000, 0x2000))
        self.assertEqual(
            rc.get_missing_ranges((0x0, 0x3000)),
            [(0x0, 0x1000), (0x2000, 0x3000)],
        )

    def test_two_positional_ints_rejected(self):
        rc = utils.RangeCollection()
        rc.add_range((0x1000, 0x2000))
        with self.assertRaises(TypeError):
            rc.get_missing_ranges(0x0, 0x3000)


_GHIDRA_EMU_CACHE: typing.Dict[typing.Any, typing.Any] = {}


def _ensure_pyghidra_started() -> None:
    """Boot the pyghidra JVM, preloading the SymZ3 extension if possible.

    The SymbolicSummaryZ3 native libraries can only be registered before
    the JVM starts, and unittest may run a concrete-emulator test first,
    so every ghidra test boots the JVM through this helper.
    """
    import pyghidra

    if pyghidra.started():
        return
    try:
        from smallworld.emulators.ghidra import symz3_loader

        symz3_loader.ensure_loaded()
    except Exception:
        # SymZ3 extension unavailable; symbolic tests will error, but the
        # concrete-emulator tests can still run.
        pass
    if not pyghidra.started():
        pyghidra.start()


def _ghidra_concrete_emulator(arch: platforms.Architecture):
    """Return a cached concrete GhidraEmulator for a little-endian platform."""
    key = ("concrete", arch)
    if key not in _GHIDRA_EMU_CACHE:
        _ensure_pyghidra_started()
        platform = platforms.Platform(arch, platforms.Byteorder.LITTLE)
        _GHIDRA_EMU_CACHE[key] = emulators.ghidra.GhidraEmulator(platform)
    return _GHIDRA_EMU_CACHE[key]


def _ghidra_symbolic_amd64_emulator():
    """Construct a fresh amd64 GhidraSymbolicEmulator (never cached)."""
    _ensure_pyghidra_started()
    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )
    return emulators.ghidra.GhidraSymbolicEmulator(platform)


class GhidraArmFramePointerAliasTests(unittest.TestCase):
    """The ghidra ARM machdef bound "fp" to r10; ARM's frame pointer is r11."""

    @classmethod
    def setUpClass(cls):
        cls.emu = _ghidra_concrete_emulator(platforms.Architecture.ARM_V7A)

    def test_fp_maps_to_r11_in_register_map(self):
        regs = self.emu.machdef._registers
        self.assertEqual(regs["fp"], "r11")
        self.assertEqual(regs["r11"], "r11")
        # The stack-limit alias must still resolve to r10.
        self.assertEqual(regs["sl"], "r10")
        self.assertEqual(regs["r10"], "r10")

    def test_fp_write_aliases_r11_not_r10(self):
        emu = self.emu
        emu.write_register("r10", 0xAAAA5555)
        emu.write_register("r11", 0)
        emu.write_register("fp", 0xDEADBEEF)
        self.assertEqual(emu.read_register("r11"), 0xDEADBEEF)
        self.assertEqual(emu.read_register("fp"), 0xDEADBEEF)
        self.assertEqual(emu.read_register("r10"), 0xAAAA5555)


class GhidraDefaultSpaceCacheTests(unittest.TestCase):
    """GhidraEmulator must cache the default address space at construction."""

    def test_default_space_cached_at_construction(self):
        emu = _ghidra_concrete_emulator(platforms.Architecture.X86_64)
        self.assertTrue(
            hasattr(emu, "_default_space"),
            "GhidraEmulator has no _default_space attribute",
        )
        expected = emu.machdef.language.getDefaultSpace()
        self.assertEqual(
            int(emu._default_space.getSpaceID()), int(expected.getSpaceID())
        )
        self.assertTrue(emu._default_space.equals(expected))


class GhidraMips64DelaySlotMnemonicTests(unittest.TestCase):
    """A missing comma fused "bne", "bnez" into one "bnebnez" entry."""

    def test_bne_and_bnez_are_separate_entries(self):
        # Importing the machdef package requires a running JVM.
        _ensure_pyghidra_started()
        from smallworld.emulators.ghidra.machdefs.mips64 import MIPS64MachineDef

        opcodes = MIPS64MachineDef._delay_slot_opcodes
        self.assertIn("bne", opcodes)
        self.assertIn("bnez", opcodes)
        self.assertNotIn("bnebnez", opcodes)


class GhidraNegativeRegisterWriteTests(unittest.TestCase):
    """Negative register writes must wrap via two's complement.

    The old write path passed the raw int to int.to_bytes, which raises
    OverflowError for any negative value.
    """

    @classmethod
    def setUpClass(cls):
        cls.emu = _ghidra_concrete_emulator(platforms.Architecture.X86_64)

    def test_write_negative_one_to_rax(self):
        self.emu.write_register("rax", -1)
        self.assertEqual(self.emu.read_register("rax"), 0xFFFFFFFFFFFFFFFF)

    def test_write_negative_two_to_rax(self):
        self.emu.write_register("rax", -2)
        self.assertEqual(self.emu.read_register("rax"), 0xFFFFFFFFFFFFFFFE)

    def test_write_negative_one_to_eax(self):
        self.emu.write_register("eax", -1)
        self.assertEqual(self.emu.read_register("eax"), 0xFFFFFFFF)


class _GhidraFakeConcretePair:
    """Stand-in for a Java Pair<byte[], SymValueZ3> with no symbolic side.

    GhidraSymbolicEmulator.read_memory_symbolic's concrete fallback only
    runs when SymZ3 returns a null symbolic side, which the public write
    paths never produce; this fake drives that branch deterministically.
    """

    def __init__(self, raw: bytes):
        self._raw = raw

    def getLeft(self):
        return self._raw

    def getRight(self):
        return None


class GhidraSymbolicMemoryBVWidthTests(unittest.TestCase):
    """read_memory_symbolic must build concrete BVs in platform byte order.

    The old fallback used claripy.BVV(bytes), which always interprets the
    buffer big-endian, disagreeing with the little-endian interpretation
    used everywhere else in the ghidra symbolic emulator.
    """

    @classmethod
    def setUpClass(cls):
        cls.emu = _ghidra_symbolic_amd64_emulator()

    def test_concrete_fallback_uses_platform_byte_order(self):
        emu = self.emu
        data = bytes(range(0x11, 0x19))
        emu.map_memory(0x4000, 0x1000)
        original = emu._read_memory_pair
        emu._read_memory_pair = lambda address, size: _GhidraFakeConcretePair(data)
        try:
            bv = emu.read_memory_symbolic(0x4000, len(data))
        finally:
            emu._read_memory_pair = original
        self.assertFalse(bv.symbolic)
        self.assertEqual(bv.size(), len(data) * 8)
        self.assertEqual(bv.concrete_value, int.from_bytes(data, "little"))

    def test_written_memory_reads_back_in_platform_byte_order(self):
        emu = self.emu
        data = b"\x99\x88\x77\x66\x55\x44\x33\x22"
        emu.map_memory(0x5000, 0x1000)
        emu.write_memory_content(0x5000, data)
        bv = emu.read_memory_symbolic(0x5000, len(data))
        self.assertFalse(bv.symbolic)
        self.assertEqual(bv.size(), len(data) * 8)
        self.assertEqual(bv.concrete_value, int.from_bytes(data, "little"))
        self.assertEqual(
            bv.concrete_value,
            int.from_bytes(emu.read_memory_content(0x5000, len(data)), "little"),
        )


class GhidraSymbolicStoreTrackingTests(unittest.TestCase):
    """STOREs of user-symbolic values must be tracked for later reads.

    Executes ``mov qword ptr [0x2000], rax`` with rax labeled symbolic.
    The store's destination range must be recorded so read_memory_content
    runs the precise symbolic check (and raises) instead of silently
    returning stale concrete bytes.
    """

    CODE = 0x1000
    DATA = 0x2000
    LABEL = "stored_rax"

    @classmethod
    def setUpClass(cls):
        cls.emu = _ghidra_symbolic_amd64_emulator()
        # mov qword ptr [0x2000], rax
        insn = bytes.fromhex("48890425" + "00200000")
        cls.emu.map_memory(cls.CODE, 0x1000)
        cls.emu.map_memory(cls.DATA, 0x1000)
        cls.emu.write_memory_content(cls.CODE, insn)
        cls.emu.write_register("pc", cls.CODE)
        cls.emu.write_register_label("rax", cls.LABEL)
        cls.emu.step_instruction()

    def test_symbolic_store_range_is_recorded(self):
        self.assertIn((self.DATA, self.DATA + 8), self.emu._symbolic_store_ranges)

    def test_read_memory_content_after_symbolic_store_raises(self):
        # Ghidra's native STORE writes the symbolic side in a form the
        # state accessor does not reproduce on read-back, so overlay the
        # value the store semantically wrote (public API); the range
        # tracked during the step must then force the precise symbolic
        # check, which raises.
        self.emu.write_memory_content(
            self.DATA, claripy.BVS(self.LABEL, 64, explicit_name=True)
        )
        with self.assertRaises(exceptions.SymbolicValueError):
            self.emu.read_memory_content(self.DATA, 8)


class GhidraSymbolicWriteHookByteOrderTests(unittest.TestCase):
    """Symbolic write hooks must observe values in platform byte order.

    Executes ``mov qword ptr [0x2000], 0x11223344`` (fully concrete data)
    with a global symbolic write hook installed; the hook must see the
    little-endian 0x11223344. Guards the write-breakpoint hook path whose
    concrete fallback was rebuilt in platform byte order; SymZ3 currently
    populates the symbolic side for immediate stores, so this exercises
    the hook plumbing rather than the (unreachable) null-side fallback.
    """

    def test_concrete_store_hook_sees_platform_order_value(self):
        emu = _ghidra_symbolic_amd64_emulator()
        # mov qword ptr [0x2000], 0x11223344
        insn = bytes.fromhex("48C70425" + "00200000" + "44332211")
        emu.map_memory(0x1000, 0x1000)
        emu.map_memory(0x2000, 0x1000)
        emu.write_memory_content(0x1000, insn)
        emu.write_register("pc", 0x1000)
        seen = []
        emu.hook_memory_writes_symbolic(
            lambda e, addr, size, value: seen.append((addr, size, value))
        )
        emu.step_instruction()
        self.assertEqual(len(seen), 1)
        addr, size, value = seen[0]
        self.assertEqual(addr, 0x2000)
        self.assertEqual(size, 8)
        self.assertFalse(value.symbolic)
        self.assertEqual(value.size(), 64)
        self.assertEqual(value.concrete_value, 0x11223344)


try:
    from smallworld.emulators.panda.panda import PandaEmulator as _PandaEmulator

    _PANDA_AVAILABLE = True
except Exception:
    _PandaEmulator = None  # type: ignore[assignment,misc]
    _PANDA_AVAILABLE = False

_PANDA_PAGE = 0x1000


def _make_bare_panda_emulator():
    """Build a PandaEmulator without running __init__.

    A real PandaEmulator spawns a QEMU thread in __init__ and only one
    instance is safe per process, so tests construct the object via
    __new__ and populate only the attributes the methods under test use.
    """
    emu = _PandaEmulator.__new__(_PandaEmulator)
    emu.PAGE_SIZE = _PANDA_PAGE
    emu.platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )
    emu.mapped_pages = utils.RangeCollection()
    emu.panda_thread = mock.Mock()
    return emu


def _panda_write_chunks(emu):
    """Return recorded (address, data) pairs from physical_memory_write."""
    calls = emu.panda_thread.panda.physical_memory_write.call_args_list
    return [(call.args[0], bytes(call.args[1])) for call in calls]


@unittest.skipUnless(_PANDA_AVAILABLE, "pandare2 not installed")
class PandaPageRangeForMemoryTests(unittest.TestCase):
    """_page_range_for_memory is the canonical address+size -> page range map."""

    def setUp(self):
        self.emu = _make_bare_panda_emulator()

    def test_sub_page_allocation_is_one_page(self):
        # 0x1100..0x1110 sits entirely inside page 1
        self.assertEqual(self.emu._page_range_for_memory(0x1100, 0x10), (1, 2))

    def test_allocation_spanning_boundary_is_two_pages(self):
        # 0x1F00..0x2100 straddles the page 1 / page 2 boundary
        self.assertEqual(self.emu._page_range_for_memory(0x1F00, 0x200), (1, 3))

    def test_page_aligned_address_and_size(self):
        self.assertEqual(self.emu._page_range_for_memory(0x4000, 0x2000), (4, 6))

    def test_aligned_single_byte_is_one_page(self):
        self.assertEqual(self.emu._page_range_for_memory(0x3000, 1), (3, 4))

    def test_allocation_ending_on_boundary_excludes_next_page(self):
        # 0x1800..0x2000 ends exactly at the page 2 boundary
        self.assertEqual(self.emu._page_range_for_memory(0x1800, 0x800), (1, 2))

    def test_non_positive_size_rejected(self):
        with self.assertRaises(ValueError):
            self.emu._page_range_for_memory(0x1000, 0)


@unittest.skipUnless(_PANDA_AVAILABLE, "pandare2 not installed")
class PandaMapMemoryTests(unittest.TestCase):
    """map_memory had a special case that mapped an extra page for
    allocations contained within a single page; it must now agree with
    _page_range_for_memory."""

    def setUp(self):
        self.emu = _make_bare_panda_emulator()
        self.panda_map = self.emu.panda_thread.panda.map_memory

    def test_sub_page_allocation_maps_single_page(self):
        # Old code produced a two-page region (1, 3) for this request
        self.emu.map_memory(0x1100, 0x10)
        self.assertEqual(self.emu.mapped_pages.ranges, [(1, 2)])
        self.panda_map.assert_called_once_with(f"{0x1000}", 0x1000, 0x1000)

    def test_page_aligned_small_allocation_maps_single_page(self):
        # Old code produced a two-page region (3, 5) for this request
        self.emu.map_memory(0x3000, 0x10)
        self.assertEqual(self.emu.mapped_pages.ranges, [(3, 4)])
        self.panda_map.assert_called_once_with(f"{0x3000}", 0x1000, 0x3000)

    def test_allocation_spanning_page_boundary(self):
        self.emu.map_memory(0x1F00, 0x200)
        self.assertEqual(self.emu.mapped_pages.ranges, [(1, 3)])
        self.panda_map.assert_called_once_with(f"{0x1000}", 0x2000, 0x1000)

    def test_page_aligned_address_and_size(self):
        self.emu.map_memory(0x4000, 0x2000)
        self.assertEqual(self.emu.mapped_pages.ranges, [(4, 6)])
        self.panda_map.assert_called_once_with(f"{0x4000}", 0x2000, 0x4000)

    def test_remap_within_mapped_page_maps_nothing_new(self):
        # Once page 1 is mapped, a sub-page request inside it must not
        # touch panda again (old code asked for page 2 as well).
        self.emu.map_memory(0x1000, 0x1000)
        self.panda_map.reset_mock()
        self.emu.map_memory(0x1100, 0x10)
        self.panda_map.assert_not_called()
        self.assertEqual(self.emu.mapped_pages.ranges, [(1, 2)])

    def test_map_memory_bookkeeping_matches_page_range_helper(self):
        for address, size in [
            (0x1100, 0x10),
            (0x1F00, 0x200),
            (0x4000, 0x2000),
            (0x7FFF, 1),
            (0x8000, 0x1001),
        ]:
            with self.subTest(address=hex(address), size=hex(size)):
                emu = _make_bare_panda_emulator()
                emu.map_memory(address, size)
                expected = emu._page_range_for_memory(address, size)
                self.assertEqual(emu.mapped_pages.ranges, [expected])


@unittest.skipUnless(_PANDA_AVAILABLE, "pandare2 not installed")
class PandaWriteMemoryContentTests(unittest.TestCase):
    """write_memory_content must split unaligned writes so the first chunk
    ends exactly at the next page boundary; the old code used
    ``address % PAGE_SIZE`` as the first chunk size instead of the number
    of bytes remaining in the page."""

    def setUp(self):
        self.emu = _make_bare_panda_emulator()

    def test_unaligned_first_chunk_ends_at_page_boundary(self):
        # Regression: address = page_base + 0x100, len(content) = PAGE_SIZE.
        # Old code's first chunk was 0x100 bytes; it must be 0xF00 bytes.
        address = 0x2100
        content = bytes(x & 0xFF for x in range(_PANDA_PAGE))
        self.emu.write_memory_content(address, content)

        chunks = _panda_write_chunks(self.emu)
        first_address, first_data = chunks[0]
        self.assertEqual(first_address, address)
        self.assertEqual(len(first_data), _PANDA_PAGE - 0x100)
        self.assertEqual(
            (first_address + len(first_data)) % _PANDA_PAGE,
            0,
            "first chunk of an unaligned write must end at a page boundary",
        )
        self.assertEqual(
            chunks, [(0x2100, content[0:0xF00]), (0x3000, content[0xF00:])]
        )

    def test_unaligned_multi_page_chunks_contiguous_and_page_bounded(self):
        address = 0x5234
        content = bytes((7 * x + 3) & 0xFF for x in range(0x2500))
        self.emu.write_memory_content(address, content)

        chunks = _panda_write_chunks(self.emu)
        self.assertGreater(len(chunks), 1)

        # First chunk starts at the requested address and ends on a boundary
        self.assertEqual(chunks[0][0], address)
        self.assertEqual((chunks[0][0] + len(chunks[0][1])) % _PANDA_PAGE, 0)

        expected_address = address
        for chunk_address, chunk_data in chunks:
            self.assertEqual(
                chunk_address,
                expected_address,
                "each chunk must start where the previous chunk ended",
            )
            # No chunk may cross a page boundary (QEMU may segfault if it does)
            first_page = chunk_address // _PANDA_PAGE
            last_page = (chunk_address + len(chunk_data) - 1) // _PANDA_PAGE
            self.assertEqual(
                first_page,
                last_page,
                f"chunk at {hex(chunk_address)} of size {hex(len(chunk_data))} "
                "crosses a page boundary",
            )
            expected_address += len(chunk_data)

        self.assertEqual(b"".join(data for _, data in chunks), content)

    def test_aligned_write_uses_page_sized_chunks(self):
        address = 0x4000
        content = bytes((3 * x + 1) & 0xFF for x in range(0x1800))
        self.emu.write_memory_content(address, content)

        chunks = _panda_write_chunks(self.emu)
        self.assertEqual(
            chunks,
            [(0x4000, content[0:0x1000]), (0x5000, content[0x1000:])],
        )

    def test_small_unaligned_write_is_single_chunk(self):
        address = 0x2100
        content = b"\xaa" * 0x20
        self.emu.write_memory_content(address, content)

        chunks = _panda_write_chunks(self.emu)
        self.assertEqual(chunks, [(address, content)])


_FUZZFIX_UNICORNAFL_AVAILABLE = importlib.util.find_spec("unicornafl") is not None


def _fuzzfix_amd64_platform():
    return platforms.Platform(platforms.Architecture.X86_64, platforms.Byteorder.LITTLE)


class HelpersFuzzMemberIterationTests(unittest.TestCase):
    """``smallworld.helpers.fuzz`` iterates ``machine.members()`` directly.

    ``StatefulSet.members()`` returns a plain set. The pre-fix code called
    ``.items()`` on that set, raising ``AttributeError`` during member
    discovery -- before the fuzzer backend was ever reached. These tests
    drive ``helpers.fuzz`` end-to-end (with the downstream
    ``Machine.fuzz_with_file`` mocked out) and assert it gets all the way
    through CPU/code discovery and forwards the right exit points.
    """

    def _machine_with_bounds(self, bounds):
        machine = state.Machine()
        cpu = state.cpus.CPU.for_platform(_fuzzfix_amd64_platform())
        cpu.rip.set_content(0x1000)
        machine.add(cpu)
        code = state.memory.code.Executable.from_bytes(b"\x90" * 16, address=0x1000)
        # helpers.fuzz derives fuzzer exit points from the ends of the
        # Executable's bounds (an iterable of ranges, as loader-backed
        # Executables provide).
        code.bounds = list(bounds)
        machine.add(code)
        return machine

    def test_fuzz_reaches_downstream_with_exit_points_from_bounds(self):
        machine = self._machine_with_bounds([range(0x1000, 0x1010)])

        def callback(emulator, input_bytes, persistent_round, data):
            return None

        with mock.patch.object(
            state.Machine, "fuzz_with_file", autospec=True
        ) as fuzz_with_file:
            with mock.patch.object(sys, "argv", ["harness.py", "/nonexistent/afl-in"]):
                helpers.fuzz(machine, callback, iterations=3)

        fuzz_with_file.assert_called_once()
        args = fuzz_with_file.call_args.args
        self.assertIs(args[0], machine)
        emulator = args[1]
        self.assertIsInstance(emulator, emulators.UnicornEmulator)
        self.assertEqual(emulator.get_exit_points(), {0x1010})
        self.assertIs(args[2], callback)
        self.assertEqual(args[3], "/nonexistent/afl-in")
        self.assertIsNone(args[4])  # crash_callback
        self.assertFalse(args[5])  # always_validate
        self.assertEqual(args[6], 3)  # iterations

    def test_fuzz_collects_exit_points_from_every_bound(self):
        machine = self._machine_with_bounds(
            [range(0x1000, 0x1008), range(0x1008, 0x1010)]
        )

        with mock.patch.object(
            state.Machine, "fuzz_with_file", autospec=True
        ) as fuzz_with_file:
            with mock.patch.object(sys, "argv", ["harness.py", "/nonexistent/afl-in"]):
                helpers.fuzz(machine, lambda *_args: None)

        fuzz_with_file.assert_called_once()
        emulator = fuzz_with_file.call_args.args[1]
        self.assertEqual(emulator.get_exit_points(), {0x1008, 0x1010})


@unittest.skipUnless(_FUZZFIX_UNICORNAFL_AVAILABLE, "unicornafl not installed")
class UnicornFuzzPersistentSnapshotTests(unittest.TestCase):
    """Persistent-mode state restoration in ``Machine._fuzz_with_unicorn``.

    With ``iterations > 1`` a single forked child runs many inputs
    back-to-back, so ``Machine.fuzz`` snapshots the post-``apply()`` state
    (unicorn register context, writable memory, and the Python ``__dict__``
    of Heap members) and the ``place_input_callback`` adapter restores it
    for every persistent round after the first. ``uc_afl_fuzz`` is mocked
    out; the adapter it would have been given is captured and driven
    directly, which is valid because the snapshot/restore logic runs
    entirely before/inside the adapter and never needs AFL or emulation.
    """

    CODE_ADDR = 0x1000
    DATA_ADDR = 0x4000
    HEAP_ADDR = 0x6000
    RAX_INITIAL = 0x11112222
    DATA_INITIAL = b"A" * 16

    def _build_machine(self, heap):
        platform = _fuzzfix_amd64_platform()
        machine = state.Machine()
        cpu = state.cpus.CPU.for_platform(platform)
        cpu.rip.set_content(self.CODE_ADDR)
        cpu.rax.set_content(self.RAX_INITIAL)
        machine.add(cpu)
        machine.add(
            state.memory.code.Executable.from_bytes(
                b"\x90" * 16, address=self.CODE_ADDR
            )
        )
        machine.add(
            state.memory.RawMemory.from_bytes(self.DATA_INITIAL, address=self.DATA_ADDR)
        )
        machine.add(heap)
        emulator = emulators.UnicornEmulator(platform)
        emulator.add_exit_point(self.CODE_ADDR + 16)
        return machine, emulator

    def _fuzz_with_mocked_afl(self, machine, emulator, callback, iterations):
        """Run Machine.fuzz with uc_afl_fuzz mocked; return its call kwargs."""
        with mock.patch("unicornafl.uc_afl_fuzz") as uc_afl_fuzz:
            with mock.patch.object(sys, "argv", ["harness.py", "/nonexistent/afl-in"]):
                machine.fuzz(emulator, callback, iterations=iterations)
        uc_afl_fuzz.assert_called_once()
        return uc_afl_fuzz.call_args.kwargs

    def test_iterations_and_input_file_reach_uc_afl_fuzz(self):
        heap = state.memory.heap.CheckedBumpAllocator(self.HEAP_ADDR, 0x1000, 0)
        machine, emulator = self._build_machine(heap)

        kwargs = self._fuzz_with_mocked_afl(machine, emulator, lambda *_a: None, 2)

        self.assertIs(kwargs["uc"], emulator.engine)
        self.assertEqual(kwargs["input_file"], "/nonexistent/afl-in")
        self.assertEqual(kwargs["persistent_iters"], 2)
        self.assertEqual(kwargs["exits"], {self.CODE_ADDR + 16})
        self.assertIsNone(kwargs["validate_crash_callback"])
        self.assertFalse(kwargs["always_validate"])

    def test_persistent_round_restores_register_memory_and_heap_state(self):
        heap = state.memory.heap.CheckedBumpAllocator(self.HEAP_ADDR, 0x1000, 0)
        machine, emulator = self._build_machine(heap)

        observations = {}

        def callback(emu, input_bytes, persistent_round, data):
            # The adapter must hand the user callback the SmallWorld
            # emulator, not the raw unicorn engine.
            self.assertIs(emu, emulator)
            if persistent_round == 0:
                # Round 0 runs on the freshly forked child; nothing may be
                # restored, so the mutation made after the snapshot (below)
                # must still be visible here.
                observations["round0_rax_before"] = emu.read_register_content("rax")
                emu.write_register_content("rax", 0xDEAD)
                emu.write_memory_content(self.DATA_ADDR, b"ZZZZ")
                observations["round0_alloc"] = heap.allocate_bytes(b"round0", "r0")
                return "round-0-token"
            observations["round1_rax"] = emu.read_register_content("rax")
            observations["round1_data"] = emu.read_memory(
                self.DATA_ADDR, len(self.DATA_INITIAL)
            )
            observations["round1_alloc"] = heap.allocate_bytes(b"round1", "r1")
            return "round-1-token"

        kwargs = self._fuzz_with_mocked_afl(machine, emulator, callback, 2)
        adapter = kwargs["place_input_callback"]

        # Mutate a register after the snapshot was taken. Round 0 must not
        # restore, so the callback has to observe this value.
        emulator.write_register_content("rax", 0x99999999)

        # Round 0: no restore, and the callback's return value is forwarded.
        self.assertEqual(adapter(emulator.engine, b"AAAA", 0, None), "round-0-token")
        self.assertEqual(observations["round0_rax_before"], 0x99999999)
        # The round-0 mutations really are in place before round 1 begins.
        self.assertEqual(emulator.read_register_content("rax"), 0xDEAD)
        self.assertEqual(emulator.read_memory(self.DATA_ADDR, 4), b"ZZZZ")

        # Round 1: everything a fuzz run mutated must be rolled back to the
        # post-apply snapshot before the input callback runs.
        self.assertEqual(adapter(emulator.engine, b"BBBB", 1, None), "round-1-token")
        self.assertEqual(observations["round1_rax"], self.RAX_INITIAL)
        self.assertEqual(observations["round1_data"], self.DATA_INITIAL)
        # The heap's Python-side bump offset was restored: re-allocating
        # yields the same address round 0 got on the fresh child.
        self.assertEqual(observations["round1_alloc"], observations["round0_alloc"])

    def test_single_iteration_does_not_snapshot_or_restore(self):
        heap = state.memory.heap.CheckedBumpAllocator(self.HEAP_ADDR, 0x1000, 0)
        machine, emulator = self._build_machine(heap)

        kwargs = self._fuzz_with_mocked_afl(machine, emulator, lambda *_a: None, 1)
        adapter = kwargs["place_input_callback"]

        self.assertEqual(kwargs["persistent_iters"], 1)
        # With no snapshot taken, a round > 0 must not attempt (or perform)
        # any restoration: state mutated earlier stays put.
        emulator.write_register_content("rax", 0xBEEF)
        adapter(emulator.engine, b"AAAA", 1, None)
        self.assertEqual(emulator.read_register_content("rax"), 0xBEEF)

    @unittest.expectedFailure
    def test_plain_bump_allocator_offset_restored_between_rounds(self):
        # KNOWN GAP: BumpAllocator derives its bump offset from the values
        # stored in its dict-part (Memory subclasses dict), but the snapshot
        # only saves/restores instance __dict__ attributes. A plain
        # BumpAllocator's round-0 allocations therefore still count toward
        # get_used() in round 1 and the re-allocation address drifts.
        # CheckedBumpAllocator keeps its offset in an instance attribute
        # (_current_free_offset) and is restored correctly (tested above).
        # If this test starts passing, the gap was fixed: promote it to a
        # regular test by removing the expectedFailure decorator.
        heap = state.memory.heap.BumpAllocator(self.HEAP_ADDR, 0x1000)
        machine, emulator = self._build_machine(heap)

        allocations = []

        def callback(emu, input_bytes, persistent_round, data):
            allocations.append(heap.allocate_bytes(b"chunk", None))
            return None

        kwargs = self._fuzz_with_mocked_afl(machine, emulator, callback, 2)
        adapter = kwargs["place_input_callback"]

        adapter(emulator.engine, b"AAAA", 0, None)
        adapter(emulator.engine, b"BBBB", 1, None)
        self.assertEqual(allocations[1], allocations[0])


def _analyses_amd64_platform():
    return platforms.Platform(platforms.Architecture.X86_64, platforms.Byteorder.LITTLE)


class _RecordingHinter(hinting.Hinter):
    """Hinter that records sent hints verbatim (no deepcopy, no logging).

    Overriding send() sidesteps Hinter.send's json/deepcopy of hint
    payloads (some carry capstone/ctypes objects that cannot be copied)
    while still exercising the analyses' ``self.hinter.send(...)`` calls.
    """

    def __init__(self):
        super().__init__()
        self.sent = []

    def send(self, hint):
        self.sent.append(hint)


def _disasm_one(code, address, cs_arch, cs_mode):
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    insns = list(md.disasm(code, address))
    assert len(insns) == 1, f"expected 1 instruction, got {len(insns)}"
    return insns[0]


class CrashTriagePrinterUnsatOperandTests(unittest.TestCase):
    """print_diag_memory must print each unsat operand's OWN expression.

    The unsat loop bound its expression to a typo'd name (``epxr``), so
    print_expression received the leftover ``expr`` from the preceding
    unconstrained loop (or hit a NameError if that loop never ran).
    """

    def _make_printer(self):
        printer = CrashTriagePrinter(hinting.Hinter())
        recorder = mock.MagicMock()
        printer.print_expression = recorder
        return printer, recorder

    def test_unsat_operands_print_their_own_expressions(self):
        printer, recorder = self._make_printer()
        expr_unconstrained = object()
        expr_unsat_1 = object()
        expr_unsat_2 = object()
        diagnosis = SimpleNamespace(
            is_hook=False,
            unmapped_operands={},
            unconstrained_operands={"opA": expr_unconstrained},
            unsat_operands={"opB": expr_unsat_1, "opC": expr_unsat_2},
        )
        printer.print_diag_memory(0x1000, diagnosis)
        printed = [c.args[0] for c in recorder.call_args_list]
        self.assertEqual(len(printed), 3)
        self.assertIs(printed[0], expr_unconstrained)
        # The buggy version printed expr_unconstrained for both of these.
        self.assertIs(printed[1], expr_unsat_1)
        self.assertIs(printed[2], expr_unsat_2)

    def test_unsat_operands_with_no_unconstrained_operands(self):
        # With an empty unconstrained dict the buggy loop referenced a
        # never-bound name and raised NameError.
        printer, recorder = self._make_printer()
        expr_unsat = object()
        diagnosis = SimpleNamespace(
            is_hook=False,
            unmapped_operands={},
            unconstrained_operands={},
            unsat_operands={"opB": expr_unsat},
        )
        printer.print_diag_memory(0x1000, diagnosis)
        printed = [c.args[0] for c in recorder.call_args_list]
        self.assertEqual(len(printed), 1)
        self.assertIs(printed[0], expr_unsat)


class PointerFinderPointerHintTests(unittest.TestCase):
    """find_the_pointer must put the found operand in PointerHint.pointer.

    The hint was built with ``pointer=r``: ``r`` is only bound by the
    *read* loop, so on the write path it was an unbound name (NameError).
    """

    def test_write_pointer_hint_carries_found_memory_operand(self):
        # aarch64 `str x1, [x0]`: a memory *write* whose write-set contains
        # a plain BSIDMemoryReferenceOperand (x86 uses a subclass, which
        # find_the_pointer's exact type check rejects).
        cs_insn = _disasm_one(
            b"\x01\x00\x00\xf9", 0x1000, capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
        )
        self.assertEqual(cs_insn.mnemonic, "str")

        hinter = _RecordingHinter()
        finder = PointerFinder(hinter)
        # find_the_pointer builds the hint as hinting.PointerHint(...), but
        # PointerHint is missing from smallworld.hinting's __all__ (a
        # separate latent export bug), so inject it for the duration.  This
        # test pins the fixed behavior: pointer=<found operand p>, not the
        # unbound loop variable r.
        with mock.patch.object(hinting, "PointerHint", PointerHint, create=True):
            finder.find_the_pointer(cs_insn, True)

        hints = [h for h in hinter.sent if isinstance(h, PointerHint)]
        self.assertEqual(len(hints), 1)
        hint = hints[0]
        self.assertEqual(hint.message, "Pointer Found")
        self.assertIsInstance(hint.pointer, BSIDMemoryReferenceOperand)
        self.assertEqual(hint.pointer.base, "x0")
        # The pointer must be the operand identified from the instruction's
        # write set, not some other leftover value.
        expected = [
            w for w in hint.instruction.writes if type(w) is BSIDMemoryReferenceOperand
        ]
        self.assertEqual(len(expected), 1)
        self.assertEqual(hint.pointer, expected[0])


class ColorizerSummaryMemoryUnavailableTests(unittest.TestCase):
    """The MemoryUnavailable summary hint must be built from hint.scale.

    The old code read ``hint.bscale`` (a field that does not exist ->
    AttributeError) and passed a ``num_micro_executions`` kwarg that
    MemoryUnavailableSummaryHint's dataclass does not accept (TypeError).
    """

    def _make_hint(self, scale=4, exec_id=7):
        h = MemoryUnavailableHint(
            message="mem-unavail",
            is_read=True,
            size=8,
            base_reg_name="rax",
            base_reg_val=0x1000,
            index_reg_name="rbx",
            index_reg_val=2,
            offset=0x10,
            scale=scale,
            address=0xDEAD0,
            pc=0x401000,
            instruction_num=3,
        )
        # ColorizerSummary.run() consumes colorizer-produced hints, which
        # carry exec_id and dynamic_value at runtime; the frozen dataclass
        # does not declare them, so emulate the colorizer by injecting.
        object.__setattr__(h, "exec_id", exec_id)
        object.__setattr__(h, "dynamic_value", 0)
        return h

    def test_summary_hint_uses_scale_field(self):
        hinter = _RecordingHinter()
        summary = ColorizerSummary(hinter)
        summary.collect_hints(self._make_hint(scale=4))
        summary.run(None)

        sent = [h for h in hinter.sent if isinstance(h, MemoryUnavailableSummaryHint)]
        self.assertEqual(len(sent), 1)
        out = sent[0]
        self.assertEqual(out.scale, 4)
        self.assertEqual(out.size, 8)
        self.assertEqual(out.base_reg_name, "rax")
        self.assertEqual(out.index_reg_name, "rbx")
        self.assertEqual(out.offset, 0x10)
        self.assertEqual(out.pc, 0x401000)
        self.assertEqual(out.count, 1)
        self.assertEqual(out.message, "mem-unavail-summary")


class WRGraphRecordAddressTests(unittest.TestCase):
    """WRGraph.record_address accumulates (ic, address) pairs on memory lvals."""

    def _mem_dvk(self, pc=0x1000, color=0):
        return MemLvalDvKey(
            pc=pc,
            size=8,
            read=True,
            new=True,
            color=color,
            bsid=BSIDMemoryReferenceOperand(
                segment=None, base="rax", index="rcx", scale=4, offset=8
            ),
        )

    def test_memory_dvk_accumulates_addresses(self):
        graph = WRGraph()
        dvk = self._mem_dvk()
        graph.record_address(dvk, 5, 0xDEAD0)
        graph.record_address(dvk, 6, 0xDEAD4)
        rwi = graph.get_or_add_rw_from_dvk(dvk)
        self.assertIsInstance(rwi.info, MemoryLvalInfo)
        self.assertEqual(rwi.info.addresses, [(5, 0xDEAD0), (6, 0xDEAD4)])

    def test_register_dvk_record_address_is_noop(self):
        graph = WRGraph()
        dvk = RegDvKey(pc=0x1000, size=8, read=True, new=True, color=0, name="rax")
        graph.record_address(dvk, 1, 0x1234)
        rwi = graph.get_or_add_rw_from_dvk(dvk)
        self.assertIsInstance(rwi.info, RegisterInfo)
        self.assertFalse(hasattr(rwi.info, "addresses"))

    def test_memory_lval_info_equality_and_hash_ignore_addresses(self):
        bsid = BSIDMemoryReferenceOperand(
            segment=None, base="rax", index=None, scale=1, offset=0
        )
        info_a = MemoryLvalInfo(
            color=1, is_new=True, bsid=bsid, size=8, addresses=[(0, 0x1000)]
        )
        info_b = MemoryLvalInfo(
            color=1, is_new=True, bsid=bsid, size=8, addresses=[(9, 0x9999)]
        )
        self.assertEqual(info_a, info_b)
        self.assertEqual(hash(info_a), hash(info_b))


class ColorizerReadWriteFirstObsGuardTests(unittest.TestCase):
    """run() must check colors against rawcolor2dvkey[exec_id], not the outer dict.

    The outer dict is keyed by exec_id, so any color whose value collided
    with an existing exec_id key was never registered as a first
    observation, and a later use of that color raised KeyError.
    """

    @staticmethod
    def _reg_hint(pc, reg, color, use, new, exec_id, instruction_num=0):
        return DynamicRegisterValueHint(
            message="drv",
            pc=pc,
            time=0,
            instruction_num=instruction_num,
            exec_id=exec_id,
            dynamic_value=0xAB,
            color=color,
            size=8,
            use=use,
            new=new,
            reg_name=reg,
        )

    def test_color_equal_to_exec_id_still_registered(self):
        colorizer = ColorizerReadWrite(hinting.Hinter())
        # exec_id 1 with color 1: on the buggy guard, color 1 hits the
        # outer dict's exec_id key and the first observation is skipped,
        # so the later use raises KeyError.
        colorizer.collect_hints(
            self._reg_hint(0x1000, "rax", color=1, use=True, new=True, exec_id=1)
        )
        colorizer.collect_hints(
            self._reg_hint(0x1004, "rbx", color=1, use=True, new=False, exec_id=1)
        )
        with mock.patch("builtins.open", mock.mock_open()):
            colorizer.run(None)

        self.assertIn(0x1000, colorizer.graph.wr_nodes)
        self.assertIn(0x1004, colorizer.graph.wr_nodes)
        edges = {
            (src.pc, dst.pc)
            for src, dsts in colorizer.graph.out_edges.items()
            for dst in dsts
        }
        self.assertEqual(edges, {(0x1000, 0x1004)})

    def test_new_memory_hint_records_concrete_address(self):
        colorizer = ColorizerReadWrite(hinting.Hinter())
        colorizer.collect_hints(
            DynamicMemoryValueHint(
                message="dmv",
                pc=0x2000,
                time=0,
                instruction_num=3,
                exec_id=0,
                dynamic_value=0xAA,
                color=9,
                size=8,
                use=True,
                new=True,
                address=0xBEEF0,
                segment="None",
                base="rbp",
                index="None",
                scale=1,
                offset=-8,
            )
        )
        with mock.patch("builtins.open", mock.mock_open()):
            colorizer.run(None)

        node = colorizer.graph.wr_nodes[0x2000]
        self.assertEqual(len(node.reads), 1)
        info = node.reads[0].info
        self.assertIsInstance(info, MemoryLvalInfo)
        self.assertEqual(info.addresses, [(3, 0xBEEF0)])


class _FakeAngrMallocEmulator(emulators.AngrEmulator):
    """Just enough AngrEmulator surface for MallocModel.model().

    Subclasses the real AngrEmulator (model() type-checks with isinstance)
    but never initializes angr; every method model() touches is overridden.
    The capacity register holds a symbolic size that concretizes to 0.
    """

    def __init__(self, heap_addr):
        self._heap_addr = heap_addr
        self._capacity = claripy.BVS("len", 64, explicit_name=True)
        self.mem_writes = []
        self.reg_writes = []

    def get_extension(self, name):
        return None

    def read_register_symbolic(self, name):
        return self._capacity

    def eval_atmost(self, expr, most):
        return [0]

    def read_memory_content(self, address, size):
        if address == self._heap_addr:
            # heap end pointer
            return (self._heap_addr + 0x1000).to_bytes(8, "little")
        if address == self._heap_addr + 8:
            # heap next-alloc pointer
            return (self._heap_addr + 16).to_bytes(8, "little")
        raise AssertionError(f"unexpected read at {hex(address)}")

    def write_memory_content(self, address, content):
        self.mem_writes.append((address, content))

    def write_register_content(self, name, content):
        self.reg_writes.append((name, content))


class MallocModelZeroCountTests(unittest.TestCase):
    """A symbolic size that concretizes to 0 must not divide by zero.

    MallocModel.model computes ``length // n``; with n == 0 the old code
    raised ZeroDivisionError instead of taking the "don't track" path.
    """

    def test_zero_count_takes_dont_track_path(self):
        heap = _AnalysesBumpAllocator(0x10000, 0x1000)
        model = MallocModel(0x400000, heap, _analyses_amd64_platform(), None, None)
        # Bind the "len" length field to an 8-byte struct so the tracking
        # logic (and the n == 0 guard) is actually reached.
        model.bind_length_to_struct("len", "foo", [(4, "a"), (4, "b")])

        emu = _FakeAngrMallocEmulator(0x10000)
        model.model(emu)  # must not raise ZeroDivisionError

        # Allocation of 0 bytes still succeeds and returns the heap pointer.
        self.assertEqual(emu.reg_writes, [("rax", 0x10010)])


class _FieldDetectionProbe(field_analysis.FieldDetectionMixin):
    """Concrete FieldDetectionMixin: satisfies the abstract execute()."""

    def execute(self):
        pass


class FieldDetectionMemReadHintTests(unittest.TestCase):
    """mem_read_hook must emit the unknown-field hint via Hinter.send.

    The old code called ``self.hinter.self(hint)``; Hinter has no ``self``
    attribute, so every unknown-field read raised AttributeError.
    """

    def test_unknown_symbol_read_sends_hint_and_halts(self):
        hinter = _RecordingHinter()
        probe = _FieldDetectionProbe(hinter)
        self.assertTrue(probe.halt_on_hint)

        fda = field_analysis.FDAState()
        emu = SimpleNamespace(
            get_extension=lambda name: fda,
            read_register=lambda name: 0x401000,
            state=SimpleNamespace(
                _ip=SimpleNamespace(concrete_value=0x401000),
                scratch=SimpleNamespace(guards=[]),
            ),
        )
        expr = claripy.BVS("mystery", 64)

        with self.assertRaises(PathTerminationSignal):
            probe.mem_read_hook(emu, 0x2000, 8, expr)

        hints = [h for h in hinter.sent if isinstance(h, UnknownFieldHint)]
        self.assertEqual(len(hints), 1)
        hint = hints[0]
        self.assertEqual(hint.pc, 0x401000)
        self.assertEqual(hint.address, 0x2000)
        self.assertEqual(hint.size, 8)
        self.assertIn("mystery", hint.expr)


class GetCmpInfoTests(unittest.TestCase):
    """get_cmp_info returns (cmp_info, cmp_values, immediates) with concrete
    operand values read from the live emulator, index-aligned with cmp_info."""

    def setUp(self):
        self.platform = _analyses_amd64_platform()
        self.emu = emulators.UnicornEmulator(self.platform)

    def _decode(self, code):
        return _disasm_one(code, 0x1000, capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def test_register_immediate_compare(self):
        # cmp rax, 5
        cs_insn = self._decode(b"\x48\x83\xf8\x05")
        self.assertEqual(cs_insn.mnemonic, "cmp")
        self.emu.write_register("rax", 0x1234)

        cmp_info, cmp_values, immediates = trace_execution.get_cmp_info(
            self.platform, self.emu, cs_insn
        )
        self.assertEqual(len(cmp_info), 2)
        self.assertIsInstance(cmp_info[0], RegisterOperand)
        self.assertEqual(cmp_info[0].name, "rax")
        self.assertEqual(cmp_info[1], 5)
        self.assertEqual(cmp_values, [0x1234, 5])
        self.assertEqual(immediates, [5])

    def test_memory_operand_compare_reads_mapped_value(self):
        # cmp qword ptr [0x2000], rax
        cs_insn = self._decode(b"\x48\x39\x04\x25\x00\x20\x00\x00")
        self.assertEqual(cs_insn.mnemonic, "cmp")
        self.emu.map_memory(0x2000, 0x1000)
        self.emu.write_memory_content(
            0x2000, (0x1122334455667788).to_bytes(8, "little")
        )
        self.emu.write_register("rax", 99)

        cmp_info, cmp_values, immediates = trace_execution.get_cmp_info(
            self.platform, self.emu, cs_insn
        )
        self.assertEqual(len(cmp_info), 2)
        self.assertIsInstance(cmp_info[0], BSIDMemoryReferenceOperand)
        self.assertIsInstance(cmp_info[1], RegisterOperand)
        self.assertEqual(cmp_values, [0x1122334455667788, 99])
        self.assertEqual(immediates, [])

    def test_memory_operand_compare_unmapped_yields_none(self):
        # cmp qword ptr [0x6000], rax -- 0x6000 is not mapped
        cs_insn = self._decode(b"\x48\x39\x04\x25\x00\x60\x00\x00")
        self.assertEqual(cs_insn.mnemonic, "cmp")
        self.emu.write_register("rax", 7)

        cmp_info, cmp_values, immediates = trace_execution.get_cmp_info(
            self.platform, self.emu, cs_insn
        )
        self.assertEqual(len(cmp_info), 2)
        self.assertIsNone(cmp_values[0])
        self.assertEqual(cmp_values[1], 7)

    def test_non_compare_returns_three_empty_lists(self):
        # mov rax, 5
        cs_insn = self._decode(b"\x48\xc7\xc0\x05\x00\x00\x00")
        self.assertEqual(cs_insn.mnemonic, "mov")
        result = trace_execution.get_cmp_info(self.platform, self.emu, cs_insn)
        self.assertEqual(result, ([], [], []))


class TraceElementCmpValuesTests(unittest.TestCase):
    """TraceElement.cmp_values: optional, excluded from __eq__ and repr."""

    @staticmethod
    def _element(**kwargs):
        return TraceElement(0x1000, 0, "cmp", "rax, 5", [], False, [5], **kwargs)

    def test_construct_without_cmp_values_defaults_empty(self):
        te = self._element()
        self.assertEqual(te.cmp_values, [])

    def test_equality_ignores_cmp_values(self):
        te_a = self._element(cmp_values=[0x1234, 5])
        te_b = self._element(cmp_values=[0x9999, None])
        self.assertEqual(te_a, te_b)

    def test_repr_excludes_cmp_values(self):
        te = self._element(cmp_values=[0x1234, 5])
        self.assertNotIn("cmp_values", repr(te))


class TraceExecutionUndecodableInsnTests(unittest.TestCase):
    """run() must stop with ER_FAIL when pc points at undecodable bytes.

    Previously get_insn indexed capstone's empty result (cs_insns[0]) and
    the IndexError escaped run(), aborting the whole analysis.
    """

    def test_undecodable_pc_yields_er_fail_hint(self):
        platform = _analyses_amd64_platform()
        machine = state.Machine()
        cpu = state.cpus.CPU.for_platform(platform)
        # 0x06 is not a valid opcode in 64-bit mode; capstone decodes
        # nothing, though the memory itself is mapped and readable.
        code = state.memory.RawMemory.from_bytes(b"\x06" * 16, 0x1000)
        machine.add(code)
        cpu.rip.set(0x1000)
        machine.add(cpu)
        machine.add_exit_point(0x1000 + 16)

        hinter = _RecordingHinter()
        analysis = trace_execution.TraceExecution(hinter, num_insns=4)
        analysis.run(machine)

        hints = [h for h in hinter.sent if isinstance(h, TraceExecutionHint)]
        self.assertEqual(len(hints), 1)
        hint = hints[0]
        self.assertEqual(hint.emu_result, TraceRes.ER_FAIL)
        self.assertEqual(hint.trace, [])
        self.assertIn("no decodable instruction", str(hint.exception))
        self.assertIn("0x1000", str(hint.exception))


BINARIES_TESTS_DIR = pathlib.Path(__file__).resolve().parent
if not (BINARIES_TESTS_DIR / "pe").is_dir():
    # Running standalone next to a checkout; fall back to the repo layout.
    BINARIES_TESTS_DIR = BINARIES_TESTS_DIR.parent / "tests"

_TEST_BINARIES_BUILT = (BINARIES_TESTS_DIR / "pe" / "pe.amd64.pe").exists()
_BINARIES_SKIP_REASON = "compiled test binaries not present (nix build ./ci#tests)"

AMD64_PLATFORM = platforms.Platform(
    platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
)
I386_PLATFORM = platforms.Platform(
    platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
)


def _build_two_text_relocatable() -> bytes:
    """Build a minimal ELF64 relocatable with two executable sections.

    Layout (section indices):
      0 NULL, 1 .text (16 bytes), 2 .text2 (16 bytes),
      3 .symtab (func1 -> .text+0, func2 -> .text2+0),
      4 .strtab, 5 .shstrtab

    Symbols in the second executable section only resolve correctly if
    the loader records each executable section's offset within the
    accumulated text buffer.
    """
    text1 = bytes(range(0xA0, 0xB0))  # 16 distinctive bytes
    text2 = bytes(range(0xC0, 0xD0))  # 16 different bytes

    strtab = b"\0func1\0func2\0"
    shstrtab = b"\0.text\0.text2\0.symtab\0.strtab\0.shstrtab\0"

    def sym(name_off, info, shndx, value, size):
        return struct.pack("<IBBHQQ", name_off, info, 0, shndx, value, size)

    STT_FUNC = 2
    STB_GLOBAL = 1
    symtab = b"".join(
        [
            sym(0, 0, 0, 0, 0),  # null symbol
            sym(1, (STB_GLOBAL << 4) | STT_FUNC, 1, 0, 16),  # func1
            sym(7, (STB_GLOBAL << 4) | STT_FUNC, 2, 0, 16),  # func2
        ]
    )

    ehsize = 64
    contents = [text1, text2, symtab, strtab, shstrtab]
    offsets = []
    pos = ehsize
    for content in contents:
        pos = (pos + 15) & ~15
        offsets.append(pos)
        pos += len(content)
    shoff = (pos + 15) & ~15

    SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 1, 2, 3
    SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4

    def shdr(name_off, typ, flags, offset, size, link, info, align, entsize):
        return struct.pack(
            "<IIQQQQIIQQ",
            name_off,
            typ,
            flags,
            0,
            offset,
            size,
            link,
            info,
            align,
            entsize,
        )

    shdrs = b"".join(
        [
            shdr(0, 0, 0, 0, 0, 0, 0, 0, 0),
            shdr(
                1, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, offsets[0], 16, 0, 0, 16, 0
            ),
            shdr(
                7, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, offsets[1], 16, 0, 0, 16, 0
            ),
            shdr(14, SHT_SYMTAB, 0, offsets[2], len(symtab), 4, 1, 8, 24),
            shdr(22, SHT_STRTAB, 0, offsets[3], len(strtab), 0, 0, 1, 0),
            shdr(30, SHT_STRTAB, 0, offsets[4], len(shstrtab), 0, 0, 1, 0),
        ]
    )

    ET_REL, EM_X86_64 = 1, 62
    ehdr = struct.pack(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        b"\x7fELF",
        2,  # ELFCLASS64
        1,  # ELFDATA2LSB
        1,  # EV_CURRENT
        0,  # ELFOSABI_NONE
        0,  # ABI version
        ET_REL,
        EM_X86_64,
        1,  # e_version
        0,  # e_entry
        0,  # e_phoff
        shoff,
        0,  # e_flags
        ehsize,
        0,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        6,  # e_shnum
        5,  # e_shstrndx
    )

    image = bytearray(ehdr)
    for content, offset in zip(contents, offsets):
        image.extend(b"\0" * (offset - len(image)))
        image.extend(content)
    image.extend(b"\0" * (shoff - len(image)))
    image.extend(shdrs)
    return bytes(image)


class ElfShdrsTextOffsetTests(unittest.TestCase):
    """Section-header loading must record executable section offsets
    within the text buffer (not the data buffer's length at the time)."""

    BASE = 0x400000

    def _load(self):
        image = _build_two_text_relocatable()
        return Executable.from_elf(
            io.BytesIO(image), platform=AMD64_PLATFORM, address=self.BASE
        )

    def test_symbol_in_first_text_section(self):
        code = self._load()
        addr = code.get_symbol_value("func1")
        self.assertEqual(addr, self.BASE)
        data = code.to_bytes()
        self.assertEqual(
            data[addr - self.BASE : addr - self.BASE + 16], bytes(range(0xA0, 0xB0))
        )

    def test_symbol_in_second_text_section(self):
        code = self._load()
        addr = code.get_symbol_value("func2")
        self.assertEqual(addr, self.BASE + 16)
        data = code.to_bytes()
        self.assertEqual(
            data[addr - self.BASE : addr - self.BASE + 16], bytes(range(0xC0, 0xD0))
        )

    @unittest.skipUnless(_TEST_BINARIES_BUILT, _BINARIES_SKIP_REASON)
    def test_real_relocatable_object_main_symbol(self):
        path = BINARIES_TESTS_DIR / "static_rela" / "static_rela.amd64.o"
        elf = lief.ELF.parse(str(path))
        text = bytes(elf.get_section(".text").content)
        with path.open("rb") as f:
            code = Executable.from_elf(f, platform=AMD64_PLATFORM, address=self.BASE)
        addr = code.get_symbol_value("main")
        data = code.to_bytes()
        self.assertEqual(data[addr - self.BASE : addr - self.BASE + 16], text[:16])


@unittest.skipUnless(_TEST_BINARIES_BUILT, _BINARIES_SKIP_REASON)
class PEBaseRelocationTests(unittest.TestCase):
    """Base relocations must be applied to the section containing each
    relocation entry when a PE is loaded away from its preferred base."""

    def _relocated_value(self, path, platform, load_base, size):
        pe = lief.PE.parse(str(path))
        file_base = pe.optional_header.imagebase
        self.assertNotEqual(load_base, file_base)

        wanted = 10 if size == 8 else 3  # IMAGE_REL_BASED_DIR64 / HIGHLOW
        entry_rva = None
        for base_reloc in pe.relocations:
            for entry in base_reloc.entries:
                if entry.type.value == wanted:
                    entry_rva = entry.address
                    break
            if entry_rva is not None:
                break
        self.assertIsNotNone(entry_rva, "test PE has no matching relocation")

        original = None
        for section in pe.sections:
            start = section.virtual_address
            if start <= entry_rva < start + section.virtual_size:
                content = bytes(section.content)
                off = entry_rva - start
                original = int.from_bytes(content[off : off + size], "little")
                break
        self.assertIsNotNone(original, "relocation target not inside a section")

        with path.open("rb") as f:
            code = Executable.from_pe(f, platform=platform, address=load_base)
        data = code.to_bytes()
        loaded = int.from_bytes(data[entry_rva : entry_rva + size], "little")
        return original, loaded, load_base - file_base

    def test_amd64_dir64_relocation_applied(self):
        original, loaded, delta = self._relocated_value(
            BINARIES_TESTS_DIR / "pe" / "pe.amd64.pe", AMD64_PLATFORM, 0x10000, 8
        )
        self.assertEqual(loaded, original + delta)

    def test_i386_highlow_relocation_applied(self):
        original, loaded, delta = self._relocated_value(
            BINARIES_TESTS_DIR / "pe" / "pe.i386.pe", I386_PLATFORM, 0x10000000, 4
        )
        self.assertEqual(loaded, (original + delta) & 0xFFFFFFFF)


if __name__ == "__main__":
    unittest.main()
