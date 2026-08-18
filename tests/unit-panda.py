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

if bad:
    os._exit(1)
os._exit(0)
