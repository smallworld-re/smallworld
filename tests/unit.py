import logging
import os
import signal
import subprocess
import typing
import unittest

import claripy

from smallworld import emulators, exceptions, platforms, state, utils

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)


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

        # test memory discontinuous
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[5] = state.BytesValue(b"fgh", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"ABCDEFGH")

        # test memory discontinuous on end
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abcde", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"ABCDEFGH")

        # test write out of bounds
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abcdefgh")
        self.assertRaises(
            exceptions.ConfigurationError,
            lambda: memory.write_bytes(0x1000, b"abcdefghijklmnop"),
        )

        # test memory contains symbolic
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[3] = state.SymbolicValue(2, None, None, None)
        memory[5] = state.BytesValue(b"fgh", None)
        self.assertRaises(
            exceptions.SymbolicValueError, lambda: memory.read_bytes(0x1000, 0x8)
        )

        # test to_bytes method
        memory = state.memory.Memory(0x1000, 0x8)
        memory[0] = state.BytesValue(b"abc", None)
        memory[5] = state.BytesValue(b"fgh", None)
        memory.write_bytes(0x1000, b"ABCDEFGH")
        self.assertEqual(
            memory.to_bytes(byteorder=platforms.Byteorder.LITTLE), b"ABCDEFGH"
        )

    def test_memory_read_bytes(self):
        # test read memory all in one segment
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abcdefgh")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"abcdefgh")

        # test read memory in sub-segment
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abcdefgh")
        self.assertEqual(memory.read_bytes(0x1001, 0x4), b"bcde")

        # test read memory split over 2 segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abcd")
        memory.write_bytes(0x1004, b"efgh")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"abcdefgh")

        # test read memory split over 3 segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abc")
        memory.write_bytes(0x1003, b"de")
        memory.write_bytes(0x1005, b"fgh")
        self.assertEqual(memory.read_bytes(0x1000, 0x8), b"abcdefgh")

        # test read memory with unused segments and sub-segments
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"a")
        memory.write_bytes(0x1001, b"bcd")
        memory.write_bytes(0x1004, b"efg")
        memory.write_bytes(0x1007, b"h")
        self.assertEqual(memory.read_bytes(0x1002, 0x4), b"cdef")

        # test read out of bounds
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abcdefgh")
        self.assertRaises(
            exceptions.ConfigurationError, lambda: memory.read_bytes(0x1000, 0x10)
        )

        # test read memory discontinuous
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abc")
        memory.write_bytes(0x1005, b"fgh")
        self.assertRaises(
            exceptions.ConfigurationError, lambda: memory.read_bytes(0x1000, 0x8)
        )

        # test read memory containing symbolic values
        memory = state.memory.Memory(0x1000, 0x8)
        memory.write_bytes(0x1000, b"abc")
        memory[3] = state.SymbolicValue(2, None, None, None)
        memory.write_bytes(0x1005, b"fgh")
        self.assertRaises(
            exceptions.SymbolicValueError, lambda: memory.read_bytes(0x1000, 0x8)
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
        memory.write_bytes(memory.address + 1, b"\xFF\xFF")
        self.assertEqual(
            memory.get_ranges_initialized(),
            [range(memory.address + 1, memory.address + 2)],
        )

        # non-contiguous initialized regions
        memory.write_bytes(memory.address + 6, b"\xFF\xFF")
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
        memory.write_bytes(memory.address, b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
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
        memory.write_bytes(memory.address + 1, b"\xFF\xFF")
        self.assertEqual(
            memory.get_ranges_uninitialized(),
            [
                range(memory.address, memory.address),
                range(memory.address + 3, memory.address + 7),
            ],
        )

        # non-contiguous initialized regions
        memory.write_bytes(memory.address + 6, b"\xFF\xFF")
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
        memory.write_bytes(memory.address, b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
        self.assertEqual(
            memory.get_ranges_uninitialized(),
            [],
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

        for reg in cpu:
            # Check that the register is supposed to exist
            self.assertTrue(
                reg.name in pdef.registers,
                msg=f"CPU for {platform} has unknown register {reg.name}",
            )

            # Track that we've seen this register
            all_regs.remove(reg.name)

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
            except:
                bad_regs.add(reg)
        self.assertEqual(
            len(bad_regs),
            0,
            msg=f"Ghidra did not handle the following registers for {platform}: {bad_regs}",
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
        # Not supported by unicorn
        self.assertRaises(ValueError, self.run_test, platform)

    def test_unicorn_mips64el(self):
        platform = platforms.Platform(
            platforms.Architecture.MIPS64, platforms.Byteorder.LITTLE
        )
        # Not supported by unicorn
        self.assertRaises(ValueError, self.run_test, platform)

    def test_unicorn_ppc(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
        )
        # Not supported by unicorn
        self.assertRaises(ValueError, self.run_test, platform)

    def test_unicorn_ppc64(self):
        platform = platforms.Platform(
            platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
        )
        # Not supported by unicorn
        self.assertRaises(ValueError, self.run_test, platform)

    def test_unicorn_riscv64(self):
        platform = platforms.Platform(
            platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
        )
        # Not supported by unicorn
        self.assertRaises(ValueError, self.run_test, platform)

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
                cmd,
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
        # Not supported by Panda
        self.assertRaises(ValueError, self.run_test, platform)

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

    def test_ghidra_xtensa(self):
        platform = platforms.Platform(
            platforms.Architecture.XTENSA, platforms.Byteorder.LITTLE
        )
        self.run_test(platform)


if __name__ == "__main__":
    unittest.main()
