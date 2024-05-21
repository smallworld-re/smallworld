from __future__ import annotations

import logging
import queue
import subprocess
import threading
import time
import typing

from .. import state
from . import emulator

logger = logging.getLogger(__name__)


class GDBEmulator(emulator.Emulator):
    """An emulator that just runs GDB."""

    def __init__(self, timeout=5):
        super().__init__()

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
                raise Exception(
                    f"timeout exceeded ({self.timeout}), expected value not found {expected!r}"
                )

        return output

    def command(self, command: str) -> str:
        """Run the given GDB command and return the result.

        Arguments:
            command: The command to run.

        Returns:
            Output from running the given command.

        Raises:
            ValueError if GDB is not currently running.
        """

        if not self.process:
            raise ValueError("GDB process is not currently running")

        self.process.stdin.write(f"{command}\n".encode())
        self.process.stdin.flush()

        result = self.expect(self.stdout, b"(gdb) ").decode()
        result = result[: result.rfind("\n")]

        return result

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

            print("oof")
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

    def stop(self) -> None:
        """Stop the GDB process."""

        if self.process:
            self.process.terminate()
            self.process.wait()

        self.process = None

    def read_register(self, name: str) -> int:
        raise NotImplementedError()

        return 0

    def write_register(self, name: str, value: typing.Optional[int]) -> None:
        raise NotImplementedError()

    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        raise NotImplementedError()

        return b""

    def write_memory(self, address: int, value: typing.Optional[bytes]) -> None:
        raise NotImplementedError()

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
