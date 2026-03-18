import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.DEBUG)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.POWERPC32, smallworld.platforms.Byteorder.BIG
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filename = (
    __file__.replace(".py", ".elf")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)

# Set the entrypoint to the address of "main"
entrypoint = code.get_symbol_value("main")
cpu.pc.set(entrypoint)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
machine.add(stack)

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 8, "fake return address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

# Configure libc
libc = smallworld.state.models.posix.POSIXLibc(
    0x10000,
    platform,
    smallworld.platforms.ABI.SYSTEMV,
)
libc.link(code)
machine.add(libc)

# Configure an inbound connection for our socket
sockname = smallworld.state.models.posix.filedesc.sockaddr.SockaddrIn()
sockname.addr = 0x0  # 0.0.0.0
sockname.port = 8080

peername = smallworld.state.models.posix.filedesc.sockaddr.SockaddrIn()
peername.addr = 0x7F000001  # 127.0.0.1
peername.port = 33333

fdmgr = smallworld.state.models.filedesc.fdmgr.FileDescriptorManager.for_platform(
    platform, smallworld.platforms.ABI.SYSTEMV
)
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
class FailExitException(Exception):
    pass


# We signal failure abss by dereferencing 0xdead.
# Catch the dereference
class DeadModel(smallworld.state.models.mmio.MemoryMappedModel):
    def __init__(self):
        super().__init__(0xDEAD0, 1)

    def on_read(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, content: bytes
    ) -> bytes:
        raise FailExitException()

    def on_write(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        pass


dead = DeadModel()
machine.add(dead)

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(0)
try:
    machine.emulate(emulator)
    raise Exception("Did not exit as expected")
except FailExitException:
    pass
