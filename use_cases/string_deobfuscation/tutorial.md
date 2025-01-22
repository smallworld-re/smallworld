# Harnessing Malware to Deobfuscate its Strings

Malicious software will often encrypt or otherwise obfuscate its
strings. This makes manual reverse engineering in something like
Ghidra or IDA Pro annoying, as strings are not available for viewing
in the disassembly. Logging messages, window titles, and other info
all appear as jibberish. If possible, it is worthwhile, as a precursor
to reverse engineering, to decrypt the strings offline and patch them
back into the binary. However, if the decryption routines are
hand-rolled this can be difficult without running the routines in the
malware themselves.

In this tutorial, we will work with a binary that deobfuscates its
strings as it runs, and see how to use Smallworld to harness a subset
of the program's functions in order to output a file containing the
decrypted data, which can then be injected back into the binary for
manual reversing.

## Setup and Motivation

The example program to harness is `./strdeobfus` and it should be in
this directory waiting for your perusal. It contains obfuscated
strings that the program deobfuscates whilst running.  Let's verify
that in two ways.  First, with the `strings` command.

```
(smallworld) tleek@leet:~/git/smallworld/use_cases/string_deobfuscation$ strings ./strdeobfus
/lib64/ld-linux-x86-64.so.2
GLIBC_2.2.5
GLIBC_2.3
GLIBC_2.34
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
__ctype_b_loc
__cxa_finalize
__gmon_start__
__libc_start_main
libc.so.6
printf
putchar
puts
PTE1
u+UH
%s: [
thing1
thing2
:*3$"
$wTEGA
NQWP
FAHMARA
REWPH]
LQCAH]
IMJ@
FKCCHMJCH]
IAEJ
PLMJO
HKJC
@KSJ
VKE@
GLAIMWP
PLEP
NQWP
TAEJQPW
WTEGA
PKSAH
lMPGLLMOAV
cQM@A
cEHE\]y
WE]W
EFKQP
IKWP
IEWWMRAH]
QWABQH
PLMJC
MJPAVWPAHHEV
LMPGLLMOAV
LERA
tEVPH]
CVAEP
TVEGPMGEH
REHQA
SVET
EVKQJ@
SEVIPL
FKQJ@
EGVKWW
GKH@
IKKJW
nECHEJ
fAPE
FVMHHMEJP
IEVFHA
WEJ@A@
FAEGLAW
wEJPVECMJQW
...
```

The last few dozen lines in this output (and many more which are
elided away here) are the encrypted strings. Take my word for it. We
can verify that a second way, by just running the program, which will
give you some readable and even comical strings, none of which were
output by the `strings` command above. More evidence that this is a
program that decrypts strings before displaying them.

```
(smallworld) tleek@leet:~/git/smallworld/use_cases/string_deobfuscation$ ./strdeobfus 
thing1: [Space is big. You just won't believe how vastly, hugely, mind-bogglingly big it is. I mean, you may think it's a long way down the road to the chemist's, but that's just peanuts to space.$]
thing2: [A towel, [The Hitchhiker's Guide to the Galaxy] says, is about the most massively useful thing an interstellar hitchhiker can have. Partly it has great practical value. You can wrap it around you for warmth as you bound across the cold moons of Jaglan Beta; you can lie on it on the brilliant marble-sanded beaches of Santraginus V, inhaling the heady sea vapors; you can sleep under it beneath the stars which shine so redly on the desert world of Kakrafoon; use it to sail a miniraft down the slow heavy River Moth; wet it for use in hand-to-hand-combat; wrap it round your head to ward off noxious fumes or avoid the gaze of the Ravenous Bugblatter Beast of Traal (such a mind-boggingly stupid animal, it assumes that if you can't see it, it can't see you); you can wave your towel in emergencies as a distress signal, and of course dry yourself off with it if it still seems to be clean enough.$]
```

Where do those strings come from? If we open the binary `strdeobfus`
in our favorite disassembler [^1] we see that this program is fairly
simple. There is a `main` function, which calls `kringle_things`,
which, in turn, calls `kringle_thing` twice. Further, with a little
study, it would appear that `kringle_thing` is a string decryption
function. The key is the first byte in the string and that value is
xored with every byte in the string which is terminated by another
occurence of the key. The function `kringle_things` calls
`kringle_thing` twice, decrypting two different strings. The strings
live in the data section and `kringle_thing` overwrites a single
string with a decrypted version. So, in this case, decrypting of
strings transforms the data section. These strings are later printed
out as `thing1` and `thing2` by the function `prs`. Here's what the
disassembly for `kringle_things` looks like if we peer at it using
[radare2](https://book.rada.re).

```
[0x000010c0]> pdf @ sym.kringle_things
            ; CALL XREF from main @ 0x12d5(x)
┌ 41: sym.kringle_things ();
│           0x000011fe      f30f1efa       endbr64
│           0x00001202      55             push rbp
│           0x00001203      4889e5         mov rbp, rsp
│           0x00001206      488d05132e..   lea rax, obj.thing1         ; 0x4020 ; "$wTEGA\x04MW\x04FMC...$"
│           0x0000120d      4889c7         mov rdi, rax                ; int64_t arg1
│           0x00001210      e894ffffff     call sym.kringle_thing
│           0x00001215      488d05c42e..   lea rax, obj.thing2         ; 0x40e0 ; "$e\x04PKSAH\b\x04\x...$"
│           0x0000121c      4889c7         mov rdi, rax                ; int64_t arg1
│           0x0000121f      e885ffffff     call sym.kringle_thing
│           0x00001224      90             nop
│           0x00001225      5d             pop rbp
└           0x00001226      c3             ret
[0x000010c0]> 
```

Notice the two calls to `kringle_thing` and that the arg to each is a
string of presumably encrypted data. Seems like if we harness
`kringle_things` we should be able to decrypt the data section of this
program.

Note: this is a VERY simple program. There's not much need to reverse
engineer or harness. It is intended as an example, and was patterned
after real malware that works this way. Imagine that you had an
enormous piece of malware with tens of thousands of functions, two of
which are these `kringle_things` and `kringle_thing` functions, which
you have identified as almost certainly how the malware decrypts its
strings for later use. Harnessing those two functions can let you test
that theory, but it can also provide you with a way of quickly
creating a version of the binary in which the strings are dencrypted
and, thus, the code is much easier to understand in something like
Ghidra.

## Harnessing a function

The program `harness.py` in this directory harnesses `kringle_things`
and `kringle_thing`, and then runs them in order to extract the data
section after it has been decrypted, after which, it injects decrypted
data section into a new version of the binary that would be nicer to
open in ghidra. Here's how that script works from top to bottom.

We start with a little boilerplate code.

```
import logging
import os
import sys
import lief
import smallworld
smallworld.logging.setup_logging(level=logging.INFO)
```

Next we define the platform, i.e. the CPU and endianness 

```
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)
```

And then we load the code (an elf file), which we put at offset 0x1000,
as well as set some execution bounds and an exit point at which to
halt emulation. Note that the execution bounds correspond to
start/ends of the two functions `kringle_things` and `kringle_thing`
which might have come from looking at the code in a disassembler.

```
binfile = "strdeobfus"
code = smallworld.state.memory.code.Executable.from_elf(
    open(binfile, "rb"), address=0
)
fns = [
    range(0x11fe, 0x1226),  # kringle_things
    range(0x11a9, 0x11fd)   # kringle_thing
]
code.bounds = []
for b in fns:
    code.bounds.append(b)
exit_point = 0x1226
```

We need a cpu.  Also a stack (since `kringle_things` calls the
function `kringle_thing`).  We also must set `rip` to the first
instruction in `kringle_things`.

```
cpu = smallworld.state.cpus.CPU.for_platform(platform)
stack = smallworld.state.memory.stack.Stack.for_platform(platform, code.address + code.size + 0x1000, 0x5000)
cpu.rsp.set(stack.get_pointer() - 128)
cpu.rip.set(0x11fe)
```

SmallWorld packages all this up into a `machine` which can be cloned easily, which turns out to be useful.

```
machine = smallworld.state.Machine()
machine.add(cpu)
machine.add(code)
machine.add(stack)
machine.add_exit_point(exit_point)
```

With this setup complete, we can use the Unicorn emulator to run the code.

```
emu = smallworld.emulators.UnicornEmulator(platform)
new_machine = machine.emulate(emu)
```

This `new_machine` is the result of running `kringle_things` to
completion given all that initialization of the environment. A that
point, it will have the decrypted data section in memory. We can use
`lief` to tell us where the data section is in memory, then read that
data out of `new_machine`, and finally, again use `lief` to patch that
decrypted data section into the binary and write it out to disk as the
binary `strdeobfus2`.

```
elf = lief.ELF.parse(binfile)
ds = elf.get_section(".data")
decrypted_data = new_machine.read_memory(ds.virtual_address, ds.size)
ds.content = list(decrypted_data)
elf.write("strdeobfus2")
os.chmod("strdeobfus2", 0o744)
```

After all that, if we run strings on `strdeobfus2` we will see
the decrypted strings. And if we look at the function `main`, in a disassembler, we
see that the strings it references are decrypted.  Note that, of
course, this code no longer makes sense from an execution standpoint,
as the strings are decrypted before even calling the decryption
function, but reverse engineering will be easier for later code which
refers to those strings. Here is `main` as rendered by radare2.

```
[0x000010c0]> pdf @ sym.main
            ; ICOD XREF from entry0 @ 0x10d8(r)
┌ 86: int main (int argc, char **argv);
│ `- args(rdi, rsi) vars(2:sp[0xc..0x18])
│           0x000012bd      f30f1efa       endbr64
│           0x000012c1      55             push rbp
│           0x000012c2      4889e5         mov rbp, rsp
│           0x000012c5      4883ec10       sub rsp, 0x10
│           0x000012c9      897dfc         mov dword [var_4h], edi     ; argc
│           0x000012cc      488975f0       mov qword [var_10h], rsi    ; argv
│           0x000012d0      b800000000     mov eax, 0
│           0x000012d5      e824ffffff     call sym.kringle_things
│           0x000012da      488d05402d..   lea rax, [0x00004021]       ; "Space is big. You just won't believe how vastly, hugely, mind-bogglingly big it is. I mean, you may think it's a long way down "
│           0x000012e1      4889c6         mov rsi, rax                ; int64_t arg2
│           0x000012e4      488d05210d..   lea rax, str.thing1         ; 0x200c ; "thing1"
│           0x000012eb      4889c7         mov rdi, rax                ; int64_t arg1
│           0x000012ee      e834ffffff     call sym.prs
│           0x000012f3      488d05e72d..   lea rax, [0x000040e1]       ; "A towel, [The Hitchhiker's Guide to the Galaxy] says, is about the most massively useful thing an interstellar hitchhiker can h"
│           0x000012fa      4889c6         mov rsi, rax                ; int64_t arg2
│           0x000012fd      488d050f0d..   lea rax, str.thing2         ; 0x2013 ; "thing2"
│           0x00001304      4889c7         mov rdi, rax                ; int64_t arg1
│           0x00001307      e81bffffff     call sym.prs
│           0x0000130c      b800000000     mov eax, 0
│           0x00001311      c9             leave
└           0x00001312      c3             ret
```

Ta da!



[^1]: like Ghidra or objdump or radare2 or Ida Pro or Binary Ninja or ...

