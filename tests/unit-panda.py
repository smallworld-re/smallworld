import sys

from smallworld import emulators, exceptions, platforms

architecture = None
for arch in platforms.Architecture:
    if arch.name == sys.argv[1]:
        architecture = arch
        break

if architecture is None:
    print(f"Unknown architecture {sys.argv[1]}", file=sys.stderr)
    quit(1)

byteorder = None
for bo in platforms.Byteorder:
    if bo.name == sys.argv[2]:
        byteorder = bo
        break
if byteorder is None:
    print(f"Unknown byteorder {sys.argv[2]}", file=sys.stderr)
    quit(1)

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
    except:
        print(
            f"Register {reg} of {platform} not handled correctly by Panda",
            file=sys.stderr,
        )
        bad = True

if bad:
    quit(1)
