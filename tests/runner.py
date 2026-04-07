import argparse
import logging
import pathlib

import smallworld

# Universal harness for the C99 and POSIX tests.

# Load arguments
parser = argparse.ArgumentParser()
parser.add_argument("--quiet-exit", "-q", action="store_true")
parser.add_argument("path")
parser.add_argument("arch")
parser.add_argument("byteorder")
args = parser.parse_args()

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.DEBUG)

# Define the platform
arch = smallworld.platforms.Architecture[args.arch]
byteorder = smallworld.platforms.Byteorder[args.byteorder]
platform = smallworld.platforms.Platform(arch, byteorder)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filepath = pathlib.Path(__file__).parent / args.path

if arch in (
    smallworld.platforms.Architecture.ARM_V6M,
    smallworld.platforms.Architecture.LOONGARCH64,
    smallworld.platforms.Architecture.MIPS32,
    smallworld.platforms.Architecture.MIPS64,
    smallworld.platforms.Architecture.POWERPC32,
):
    address = None
else:
    address = 0x400000

with open(filepath, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(
        f, platform=platform, address=address
    )
    machine.add(code)

# Set the entrypoint to the address of "main"
entrypoint = code.get_symbol_value("main")
cpu.pc.set(entrypoint)
if hasattr(cpu, "t9"):
    # This is a MIPS variant
    # Their calling convention uses t9 to compute a global pointer
    cpu.t9.set(entrypoint)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0xC000000, 0x4000)
machine.add(stack)

# Push a return address onto the stack
stack.push_integer(0x7FFFFFF0, 8, "fake return address")
machine.add_exit_point(0x7FFFFFF0)

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

# Configure the heap
heap = smallworld.state.memory.heap.BumpAllocator(0x4000000, 0x1000)
machine.add(heap)

# Configure libc
libc = smallworld.state.models.posix.libc.POSIXLibc(
    0x8000000,
    platform,
    smallworld.platforms.ABI.SYSTEMV,
    allow_imprecise={
        "atexit",
        "bsd_signal",
        "atoll",
        "exit",
        "getenv",
        "pthread_sigmask",
        "remove",
        "rename",
        "sigaction",
        "signal",
        "sigpending",
        "sigprocmask",
        "system",
    },
    heap=heap,
)
libc.link(code)
machine.add(libc)

# Configure fake filesystem
fdmgr = smallworld.state.models.filedesc.FileDescriptorManager.for_platform(
    platform, smallworld.platforms.ABI.SYSTEMV
)
fdmgr.add_file("/tmp/foobar")

# Configure an inbound connection for socket server tests
sockname = smallworld.state.models.posix.filedesc.sockaddr.SockaddrIn()
sockname.addr = 0x0  # 0.0.0.0
sockname.port = 8080

peername = smallworld.state.models.posix.filedesc.sockaddr.SockaddrIn()
peername.addr = 0x7F000001  # 127.0.0.1
peername.port = 33333

assert isinstance(
    fdmgr, smallworld.state.models.posix.filedesc.fdmgr.POSIXFileDescriptorManager
)
fdmgr.add_connection(
    fdmgr.AF_INET,
    fdmgr.SOCK_STREAM,
    fdmgr.PROTO_DEFAULT,
    sockname,
    peername,
    b"Hello, world!",
)


# Create a type of exception only I will generate
class SuccessExitException(Exception):
    pass


# We signal failure atolls by dereferencing 0xdead.
# Catch the dereference
class DeadModel(smallworld.state.models.mmio.MemoryMappedModel):
    def __init__(self):
        super().__init__(0xDEAD0, 1)

    def on_read(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, content: bytes
    ) -> bytes:
        raise SuccessExitException()

    def on_write(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        pass


dead = DeadModel()
machine.add(dead)

# Emulate
emulator: smallworld.emulators.Emulator
if arch in (
    smallworld.platforms.Architecture.ARM_V7A,
    smallworld.platforms.Architecture.LOONGARCH64,
    smallworld.platforms.Architecture.MIPS64,
    smallworld.platforms.Architecture.POWERPC32,
    smallworld.platforms.Architecture.RISCV64,
):
    emulator = smallworld.emulators.GhidraEmulator(platform)
else:
    emulator = smallworld.emulators.UnicornEmulator(platform)


try:
    machine.emulate(emulator)
    if not args.quiet_exit:
        raise Exception("Did not exit as expected")
except SuccessExitException:
    if args.quiet_exit:
        raise Exception("Did not exit as expected")
