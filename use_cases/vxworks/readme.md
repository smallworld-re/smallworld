# Harnessing a VxWorks Binary for Field Detection

In this demonstration, SmallWorld is used to harness a function in a PowerPC VxWorks firmware image and run a simple function contained inside

## Setup and Motivation

The example firmware is a big-endian PowerPC VxWorks 5 image sourced from the
[vxhunter](https://github.com/PAGalaxyLab/vxhunter/tree/master/example_firmware)
project. This provides a useful example as a VxWorks binary, because it includes a symbol table, which is necessary for Binary Ninja to automatically parse it.
Path to the binary can passed as a command line argument.

The target function is `show_cpm`, a routine that prints data values from memory.

## How the Script Works

### Boilerplate

```python
import logging
import pathlib
import smallworld
from smallworld.analyses.field_detection import FieldDetectionAnalysis

smallworld.logging.setup_logging(level=logging.INFO)
log = logging.getLogger("smallworld")
```

Standard logging setup. The `warnings` filter suppresses a noisy protobuf version
warning that does not affect execution.

### Loading the Firmware

```python
filepath = pathlib.Path(__file__).parent / "bin" / "image_vx5_ppc_big_endian.bin"
with open(filepath, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_vxworks(f)
    machine.add(code)
```

`from_vxworks` loads the firmware image using Binary Ninja under the hood, which
auto-detects the platform (PowerPC32 big-endian in this case), maps sections, and
extracts the symbol table. The platform and executable bounds are all derived from
the image — no manual configuration required.

### Execution Bounds

```python
for bound in code.bounds:
    machine.add_bound(bound[0], bound[1])
```

The bounds detected from the firmware's executable segments are added to the machine
so the emulator knows which memory regions contain valid code.

### CPU and Entry Point

```python
cpu = smallworld.state.cpus.CPU.for_platform(platform)
cpu.pc.set(code.get_symbol_value('show_cpm'))
machine.add(cpu)
```

The CPU is created for the detected platform and the program counter is set to the
address of `show_cpm`, resolved by name from the symbol table.

### Stack

```python
stack = smallworld.state.memory.stack.Stack.for_platform(
    platform, 0x7FFFC000, 0x4000
)
machine.add(stack)
stack.push_integer(0x01010101, 8, None)
cpu.r1.set(stack.get_pointer())
```

A stack is allocated and the stack pointer register `r1` is set to point to it.
A dummy value is pushed onto the stack to serve as a return address, giving the
emulator a concrete value to branch to when `show_cpm` returns.

### Modeling `printf`

```python
printf_model = smallworld.state.models.Model.lookup(
    "printf", platform, smallworld.platforms.ABI.SYSTEMV, code.get_symbol_value('printf')
)
machine.add(printf_model)
printf_model.allow_imprecise = True
```

`show_cpm` calls `printf` internally. Rather than emulating the full libc
implementation, SmallWorld substitutes a model that handles the calling convention
and arguments without requiring the real function to be present or executable.
`allow_imprecise` relaxes argument parsing so the model tolerates partially-initialized inputs.

### Auxiliary Memory

```python
gdata = smallworld.state.memory.Memory(0x4800000, 0x1000)
machine.add(gdata)
gdata[0x99e] = smallworld.state.IntegerValue(1, 2, "reg count", code.platform.byteorder, False)
```

`show_cpm` reads from a global data region at `0x4800000`. This block allocates
that region so the emulator does not fault on the access. The value at offset
`0x99e` is one of the registers referenced. It's value is set to highlight how you might control memory references, where desired.

### Emulation and Exit Point

```python
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(code.get_function_end('show_cpm'))
machine.apply(emulator)
try:
    emulator.run()
except smallworld.exceptions.EmulationStop:
    pass
```

Unicorn is used for concrete emulation. The exit point is set to the first address
past the last instruction of `show_cpm`, resolved automatically from the symbol
table via `get_function_end`. Emulation runs until that point is reached.

Other smallworld emulators may be used simply by commenting the line selecting unicorn, and uncommenting lines for Angr or Ghidra.