.. _emulators:

Emulators
---------

Emulators play a big role in SmallWorld. On the one hand, they represent a
possible consumer of the harness we'd build for code.  That is, once harnessed,
a reasonable thing to do with that harness is use an emulator to execute its
instructions.  This could mean executing with breakpoints or single stepping
and examining intermediate register values or memory contents in a dynamic
reverse engineering situation. Or the harness might be used to run code many
times with random draws from an initialization environment, possibly as part of
a fuzzing campaign.

Emulation is also employed by various analyzers to improve a harness. This
means we emulate with our current best harness in order to get hints to improve
our harness for emulation.  In other words, we emulate in order to emulate
better.

SmallWorld abstracts away emulator details with an interface.  That interface
provides methods for reading and writing registers and memory, for loading code
into memory, for executing one instruction or a large number.

Here's some example code using the ``Emulator`` interface::

   import smallworld
   state = smallworld.cpus.AMD64CPUState()
   zero = smallworld.initializers.ZeroInitializer()
   state.initialize(zero)
   emu = smallworld.emulators.UnicornEmulator(state.arch, state.mode)
   code = smallworld.state.Code.from_filepath("../tests/square.amd64.bin", base=0x1000, entry=0x1000)
   state.map(code)
   state.apply(emu)
   emu.write_register('edi', 8)
   emu.run()
   print(emu.read_register('eax'))

In this example, we create an emulator that, under the hood, uses Unicorn. We
map code into our state object which is then applied to (mapped into) the
emulator's memory at the expected base address. Finaly, we write a register and
then emulate and read an output register.

The point here is that this script would have one line different if a different
emulator were used.  And if a different cpu like ARM or MIPS were used, only
the names of the registers would change.
