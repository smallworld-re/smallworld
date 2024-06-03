from __future__ import annotations

import logging
import os
import queue
import stat
import subprocess
import tempfile
import threading
import time
import typing

from ... import state
from .. import emulator
from . import elf

logger = logging.getLogger(__name__)


class GDBEmulator(emulator.Emulator):
    """An emulator that just runs GDB.

    Arguments:
        entry: The entrypoint for execution - required for GDB startup.
        timeout: Maximum command execution time before raising an exception.
    """

    def __init__(self, entry: int, timeout=5):
        super().__init__()

        self.entry = entry
        self.timeout = timeout

        self.process = None

        self.stdout = queue.Queue()
        self.stderr = queue.Queue()

    @staticmethod
    def flush(q: queue.Queue) -> bytes:
        """Flush the given queue and return everything read from it.

        Arguments:
            q: Queue object to read (stdout or stderr).

        Returns:
            All bytes currently available without blocking.
        """

        result = b""

        while True:
            try:
                result = result + q.get(timeout=0.1)
            except queue.Empty:
                break

        return result

    def expect(self, q: queue.Queue, expected: bytes) -> bytes:
        """Read until the given string is in the output.

        Arguments:
            q: Queue object to read (stdout or stderr).
            expected: The expected string.

        Returns:
            All bytes read until `expected` was found.

        Raises:
            An exception if the timeout duration is reached.
        """

        output = b""
        elapsed = 0

        while True:
            output += self.flush(q)

            if expected in output:
                break

            time.sleep(1)
            elapsed += 1

            if elapsed > self.timeout:
                # TODO make this a real exception
                raise Exception(
                    f"timeout exceeded ({self.timeout}), expected value not found {expected!r}"
                )

        return output

    def command(self, command: str, error=False) -> str:
        """Run the given GDB command and return the result.

        Arguments:
            command: The command to run.
            error: If `True` raise an exception if the given command prints to
                `stderr`.

        Returns:
            `stdout`, `stderr` from running the given command.

        Raises:
            ValueError if GDB is not currently running.
            RuntimeError if the command fails and `error` is `True`.
        """

        if not self.process:
            raise ValueError("GDB process is not currently running")

        self.process.stdin.write(f"{command}\n".encode())
        self.process.stdin.flush()

        stdout = self.expect(self.stdout, b"(gdb) ").decode()
        stdout = stdout[: stdout.rfind("(gdb)")].strip()

        stderr = self.flush(self.stderr).decode().strip()

        if error and stderr:
            raise RuntimeError(f"command failed: {stderr}")

        return stdout, stderr

    def interact(self) -> None:
        """Start an interactive session with GDB process."""

        if not self.process:
            raise ValueError("GDB process is not currently running")

        while True:
            try:
                command = input("(gdb) ")
            except EOFError:
                print()
                break

            stdout, stderr = self.command(command)

            if stdout:
                print(stdout)
            if stderr:
                print(stderr)

    def start(self) -> None:
        """Start the GDB process."""

        if self.process:
            raise ValueError("GDB process already running")

        self.process = subprocess.Popen(
            ["gdb"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def enqueue(f, queue):
            for line in iter(lambda: f.read(1), b""):
                queue.put(line)
            f.close()

        self.stdout = queue.Queue()
        self.stderr = queue.Queue()

        threading.Thread(
            target=enqueue, args=(self.process.stdout, self.stdout), daemon=True
        ).start()
        threading.Thread(
            target=enqueue, args=(self.process.stderr, self.stderr), daemon=True
        ).start()

        self.expect(self.stdout, b"(gdb) ")

        self.working = tempfile.TemporaryDirectory()

        image = os.path.join(self.working.name, "image")

        with open(image, "wb") as f:
            f.write(
                elf.build(
                    elf.Bits.B64,
                    elf.Byteorder.LITTLE,
                    elf.ABI.SYSTEM_V,
                    elf.ISA.X86_64,
                    self.entry,
                )
            )

        # chmod +x
        status = os.stat(image)
        os.chmod(image, status.st_mode | stat.S_IEXEC)

        self.command(f"file {image}", error=True)
        self.command("starti", error=True)

    def stop(self) -> None:
        """Stop the GDB process."""

        if self.process:
            self.process.terminate()
            self.process.wait()

        self.process = None

    def read_register(self, name: str) -> int:
        output, _ = self.command(f"info registers {name}", error=True)
        return int(output.split()[1], 16)

    def write_register(self, name: str, value: typing.Optional[int]) -> None:
        value = value or 0
        output, _ = self.command(f"set ${name}={value}", error=True)

    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        count = (size // 4) + 1
        output, _ = self.command(f"x/{count}x {address}", error=True)

        data = b""
        for line in output.split("\n"):
            for value in line.split()[1:]:
                data += bytearray.fromhex(value[2:])

        return data[:size]

    def write_memory(self, address: int, value: typing.Optional[bytes]) -> None:
        value = value or b""

        # import pwn
        # pwn.context.update(arch='x86_64', os='linux')
        # mmap = pwn.asm(pwn.shellcraft.common.linux.mmap(address, len(value), 7, 49, -1, 0))
        # shellcode = mmap + pwn.asm(f"jmp $-{len(mmap)-1}")
        shellcode = b"j1AZj\xffAXE1\xc9\xbf\x01\x01\x02\x01\x81\xf7\x01\x01\x03\x01j\x07Zj ^j\tX\x0f\x05\xeb\xde"

        # TODO keep track of memory maps and only map as necessary.
        scratch = self.entry
        self.command(f"set $pc={hex(scratch)}", error=True)
        self.command(f"break", error=True)
        self.command(
            f'set {{char[{len(shellcode)}]}}({hex(scratch)}) = "{repr(shellcode)[2:-1]}"',
            error=True,
        )
        self.command("continue", error=True)
        self.command(f'set {{char[{len(shellcode)}]}}({hex(scratch)}) = ""', error=True)
        self.command(f"delete", error=True)

        self.command(
            f'set {{char[{len(value)}]}}({hex(address)}) = "{repr(value)[2:-1]}"',
            error=True,
        )

    def load(self, code: state.Code) -> None:
        raise NotImplementedError()

    def hook(
        self,
        address: int,
        function: typing.Callable[[emulator.Emulator], None],
        finish: bool = False,
    ) -> None:
        raise NotImplementedError()

    def run(self) -> None:
        raise NotImplementedError()

    def step(self) -> bool:
        raise NotImplementedError()

        return False

    def __del__(self):
        if self.process:
            self.stop()

    def __repr__(self) -> str:
        arguments = "stopped"

        if self.process:
            arguments = f"running, pid={self.process.pid}"

        return f"GDB({arguments})"
