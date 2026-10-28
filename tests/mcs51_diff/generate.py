"""Generate the expected results for the mcs51_diff scenario with ucsim_51.

For each ``<name>.mcs51.s`` here, build a random starting state, run the
program on ucsim_51 (SDCC's 8051 simulator) as an 8052, and write the starting
and final state to ``<name>.json``.  The scenario
(``tests/harness/scenarios/mcs51_diff.py``) loads the same starting state into
SmallWorld and compares where it ends against the final state recorded here.

Rerun this after changing a program, and review the diff of the .json files:

    cd tests/mcs51_diff && python3 generate.py

It needs SDCC's sdas8051, sdld and sdobjcopy, and ucsim_51, on PATH, as in
the test binaries' Nix build.

The starting state is random but seeded by the program's name, so a rerun
reproduces it.  Internal RAM, R0-R7, A, B, DPTR, the PSW flags and XDATA
0x0000-0x00FF are random; register bank 0 is selected, and SP starts at 0xB0
so pushes land in the upper internal RAM only an 8052 has.

ucsim is driven through its TCP console, one command at a time.  Piped to its
standard input instead, it echoes each command into its output on a separate
path, interleaved with the results, sometimes mid-line.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import socket
import subprocess
import tempfile
import time
import zlib

HERE = pathlib.Path(__file__).resolve().parent

CODE_BASE = 0x1000
SP_START = 0xB0
XDATA_WINDOW = 0x100

SFR_SP = 0x81
SFR_DPL = 0x82
SFR_DPH = 0x83
SFR_PSW = 0xD0
SFR_ACC = 0xE0
SFR_B = 0xF0

# PSW bits the random state leaves clear: the register bank select (RS1, RS0),
# since the programs run in bank 0, and parity, which the hardware computes
# from the accumulator rather than taking.
PSW_FIXED_BITS = 0x18 | 0x01


class Ucsim:
    """A ucsim_51 session, driven through its TCP console.

    ``-P`` makes the prompt a NUL byte, so each command's response is
    everything up to the next NUL, starting with the console's echo of the
    command itself.
    """

    def __init__(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.process = subprocess.Popen(
            ["ucsim_51", "-q", "-P", "-t", "8052", "-Z", str(port)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10
        while True:
            try:
                self.socket = socket.create_connection(("127.0.0.1", port), timeout=10)
                break
            except OSError:
                if time.monotonic() > deadline:
                    self.process.kill()
                    raise
                time.sleep(0.1)
        # Skip the telnet negotiation and banner: sync on a known reply.
        self.socket.sendall(b"echo @@ready\n")
        while "@@ready" not in self._read_prompt():
            pass

    def _read_prompt(self) -> str:
        data = bytearray()
        while True:
            byte = self.socket.recv(1)
            if not byte:
                raise RuntimeError("ucsim closed its console")
            if byte == b"\0":
                return data.decode("latin-1").replace("\r", "")
            data += byte

    def command(self, command: str) -> str:
        self.socket.sendall(command.encode() + b"\n")
        lines = self._read_prompt().split("\n")
        if lines and lines[0].strip() == command:
            lines = lines[1:]
        return "\n".join(lines)

    def run_to_stop(self) -> str:
        """Run until the simulation stops, which may outlast `run`'s prompt."""
        output = self.command("run")
        while "Stop at" not in output:
            output += self._read_prompt()
        return output

    def dump(self, memory: str, start: int, end: int) -> bytes:
        """Read memory[start:end] with `dump /h`, 16 bytes to a line."""
        text = self.command(f"dump /h {memory} {start:#x} {end - 1:#x} 16")
        data = {}
        for line in text.split("\n"):
            fields = line.split()
            if not fields or not fields[0].startswith("0x"):
                continue
            address = int(fields[0], 16)
            # Take only as many bytes as the line holds: the ASCII column
            # after them can look like hex.
            count = min(16, end - address)
            for i, field in enumerate(fields[1 : 1 + count]):
                data[address + i] = int(field, 16)
        missing = [hex(a) for a in range(start, end) if a not in data]
        if missing:
            raise RuntimeError(f"ucsim's {memory} dump is missing {missing[:4]}")
        return bytes(data[a] for a in range(start, end))

    def set_memory(self, memory: str, start: int, data: bytes) -> None:
        for i in range(0, len(data), 16):
            values = " ".join(f"{b:#04x}" for b in data[i : i + 16])
            self.command(f"set memory {memory} {start + i:#x} {values}")

    def close(self) -> None:
        try:
            self.socket.sendall(b"kill\n")
            self.process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()
        finally:
            self.socket.close()


def _assemble(source: pathlib.Path, work: pathlib.Path) -> tuple[pathlib.Path, int]:
    """Assemble and link at CODE_BASE as mcs51_asm.sh does; return the .ihx
    and the code size."""
    prog = work / "prog.s"
    prog.write_text(source.read_text())
    subprocess.run(["sdas8051", "-plosgff", str(prog)], check=True)
    ihx = work / "prog.ihx"
    subprocess.run(
        ["sdld", "-i", "-b", f"CSEG={CODE_BASE:#x}", str(ihx), str(work / "prog.rel")],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    binary = work / "prog.bin"
    subprocess.run(
        ["sdobjcopy", "-I", "ihex", "-O", "binary", str(ihx), str(binary)], check=True
    )
    return ihx, binary.stat().st_size


def generate(source: pathlib.Path) -> dict:
    name = source.name.split(".")[0]
    rng = random.Random(zlib.crc32(name.encode()))
    iram = rng.randbytes(0x100)
    xdata = rng.randbytes(XDATA_WINDOW)
    registers = {
        SFR_ACC: rng.randrange(0x100),
        SFR_B: rng.randrange(0x100),
        SFR_DPL: rng.randrange(0x100),
        SFR_DPH: rng.randrange(0x100),
        SFR_PSW: rng.randrange(0x100) & ~PSW_FIXED_BITS,
        SFR_SP: SP_START,
    }

    with tempfile.TemporaryDirectory() as tmp:
        ihx, size = _assemble(source, pathlib.Path(tmp))
        last = CODE_BASE + size - 1
        ucsim = Ucsim()
        try:
            ucsim.command(f'file "{ihx}"')
            ucsim.set_memory("iram", 0x00, iram)
            ucsim.set_memory("xram", 0x0000, xdata)
            for sfr, value in registers.items():
                ucsim.command(f"set memory sfr {sfr:#x} {value:#04x}")
            initial = {
                "iram": ucsim.dump("iram", 0x00, 0x100),
                "sfr": ucsim.dump("sfr", 0x80, 0x100),
                "xdata": ucsim.dump("xram", 0x0000, XDATA_WINDOW),
            }
            ucsim.command(f"pc {CODE_BASE:#x}")
            ucsim.command(f"break {last:#x}")
            stop = ucsim.run_to_stop()
            if f"Stop at {last:#08x}" not in stop:
                raise RuntimeError(f"{name}: ucsim did not stop at {last:#x}: {stop}")
            final = {
                "iram": ucsim.dump("iram", 0x00, 0x100),
                "sfr": ucsim.dump("sfr", 0x80, 0x100),
                "xdata": ucsim.dump("xram", 0x0000, XDATA_WINDOW),
            }
        finally:
            ucsim.close()

    return {
        "program": source.name,
        "simulator": "ucsim_51 -t 8052",
        "code_base": CODE_BASE,
        "initial": {key: value.hex() for key, value in initial.items()},
        "final": {key: value.hex() for key, value in final.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("programs", nargs="*", help="programs to regenerate")
    args = parser.parse_args()
    sources = (
        [pathlib.Path(p).resolve() for p in args.programs]
        if args.programs
        else sorted(HERE.glob("*.mcs51.s"))
    )
    for source in sources:
        expected = generate(source)
        out = source.with_name(source.name.split(".")[0] + ".json")
        out.write_text(json.dumps(expected, indent=2) + "\n")
        print(f"wrote {out.relative_to(HERE)}")


if __name__ == "__main__":
    main()
