import os
import sys

from smallworld import emulators, exceptions, platforms

# Test script for ensuring Panda can read its registers.
#
# This is an extension of PandaMachineDefTests in unit.py;
# all the other emulators do this computation in that script,
# but instantiating multiple PandaEmulators in one script
# leads to errors.

architecture = None
for arch in platforms.Architecture:
    if arch.name == sys.argv[1]:
        architecture = arch
        break

if architecture is None:
    print(f"Unknown architecture {sys.argv[1]}", file=sys.stderr)
    os._exit(1)

byteorder = None
for bo in platforms.Byteorder:
    if bo.name == sys.argv[2]:
        byteorder = bo
        break
if byteorder is None:
    print(f"Unknown byteorder {sys.argv[2]}", file=sys.stderr)
    os._exit(1)

platform = platforms.Platform(architecture, byteorder)
platdef = platforms.PlatformDef.for_platform(platform)
machdef = emulators.panda.machdefs.PandaMachineDef.for_platform(platform)

emu = emulators.PandaEmulator(platform)
bad = False

for reg in platdef.registers.keys():
    try:
        emu.read_register(reg)
    except exceptions.UnsupportedRegisterError:
        continue
    except Exception as e:
        print(
            f"Register {reg} of {platform} not handled correctly by Panda: {e}",
            file=sys.stderr,
        )
        bad = True

writeback_registers = ()
if architecture == platforms.Architecture.TRICORE:
    writeback_registers = ("d2", "d4", "a4", "sp", "ra")
elif architecture in (
    platforms.Architecture.SUPERH_SH4,
    platforms.Architecture.SUPERH_SH2A_FPU,
):
    # r0 is the return value, r4 the first argument, pr the return address, and
    # sp/ra are aliases of r15/pr - so this also checks that writes through an
    # alias reach the parent.  fr0 covers the floating-point path, which QEMU
    # keeps in a separate array from the GPRs.
    writeback_registers = ("r0", "r4", "pr", "sp", "ra", "fr0")

_ARM_FP = {
    platforms.Architecture.ARM_V6K,
    platforms.Architecture.ARM_V7R,
    platforms.Architecture.ARM_V7A,
    platforms.Architecture.ARM_V8A,
    platforms.Architecture.ARM_V8R,
}
_ARM_NEON = {
    platforms.Architecture.ARM_V7A,
    platforms.Architecture.ARM_V8A,
    platforms.Architecture.ARM_V8R,
}
if architecture in _ARM_FP:
    # cpacr and the FP registers live in the CPU state rather than behind
    # PANDA's register accessors.
    writeback_registers = ("r0", "cpacr", "fpexc", "s3", "d5")
    if architecture in _ARM_NEON:
        writeback_registers += ("d17", "q9")
_AARCH64 = {
    platforms.Architecture.AARCH64,
    platforms.Architecture.AARCH64_V8_5A,
}
if architecture in _AARCH64:
    # cpacr_el1 and the SIMD and FP registers live in the CPU state rather
    # than behind PANDA's register accessors.
    writeback_registers = ("x0", "cpacr_el1", "q9", "d17", "s3")

if writeback_registers:
    for reg in writeback_registers:
        try:
            original = emu.read_register(reg)
            emu.write_register(reg, original ^ 0x11111111)
            updated = emu.read_register(reg)
            if updated != (original ^ 0x11111111):
                print(
                    f"Register {reg} of {platform} did not round-trip through Panda writes",
                    file=sys.stderr,
                )
                bad = True
            emu.write_register(reg, original)
        except Exception as e:
            print(
                f"Register {reg} of {platform} not writable through Panda: {e}",
                file=sys.stderr,
            )
            bad = True

if architecture in _ARM_FP:
    # The FP registers overlap: s2 and s3 are the halves of d1, and q0 is d0
    # and d1. QEMU masks FPSCR's reserved bits, so it gets a value it keeps.
    try:
        emu.write_register("d1", 0x1122334455667788)
        if (emu.read_register("s2"), emu.read_register("s3")) != (
            0x55667788,
            0x11223344,
        ):
            print(f"s2/s3 of {platform} are not the halves of d1", file=sys.stderr)
            bad = True
        emu.write_register("s2", 0x99AABBCC)
        if emu.read_register("d1") != 0x1122334499AABBCC:
            print(f"Writing s2 of {platform} didn't update d1", file=sys.stderr)
            bad = True
        if architecture in _ARM_NEON:
            emu.write_register("d0", 0x0102030405060708)
            if emu.read_register("q0") != (
                0x1122334499AABBCC << 64 | 0x0102030405060708
            ):
                print(f"q0 of {platform} is not d0 and d1", file=sys.stderr)
                bad = True
        emu.write_register("fpscr", 0x03C00000)
        if emu.read_register("fpscr") != 0x03C00000:
            print(f"fpscr of {platform} did not round-trip", file=sys.stderr)
            bad = True
    except Exception as e:
        print(f"FP registers of {platform} not handled by Panda: {e}", file=sys.stderr)
        bad = True

if architecture in _AARCH64:
    # d1, s1, h1 and b1 are the low bits of q1, and writing one leaves the
    # rest of q1 alone. QEMU masks fpcr's and fpsr's reserved bits, so they get
    # values it keeps.
    try:
        q1 = 0x00112233445566778899AABBCCDDEEFF
        emu.write_register("q1", q1)
        views = {name: emu.read_register(name) for name in ("d1", "s1", "h1", "b1")}
        if views != {
            "d1": q1 & (1 << 64) - 1,
            "s1": q1 & (1 << 32) - 1,
            "h1": q1 & (1 << 16) - 1,
            "b1": q1 & (1 << 8) - 1,
        }:
            print(
                f"d1/s1/h1/b1 of {platform} are not the low bits of q1", file=sys.stderr
            )
            bad = True
        emu.write_register("s1", 0x01020304)
        if emu.read_register("q1") != (q1 & ~0xFFFFFFFF) | 0x01020304:
            print(
                f"Writing s1 of {platform} changed more than q1's low bits",
                file=sys.stderr,
            )
            bad = True
        emu.write_register("b1", 0xA5)
        if emu.read_register("q1") != (q1 & ~0xFFFFFFFF) | 0x010203A5:
            print(
                f"Writing b1 of {platform} changed more than q1's low byte",
                file=sys.stderr,
            )
            bad = True
        for reg, value in (("fpcr", 0x03C00000), ("fpsr", 0x08000000)):
            emu.write_register(reg, value)
            if emu.read_register(reg) != value:
                print(f"{reg} of {platform} did not round-trip", file=sys.stderr)
                bad = True
    except Exception as e:
        print(f"FP registers of {platform} not handled by Panda: {e}", file=sys.stderr)
        bad = True

if bad:
    os._exit(1)
os._exit(0)
