
Currently all panda tests should pass with the following exceptions:

- DMATests.test_dma_armel_panda
	- Qemu thrashes with many prefetch exception errors. This is likely an issue with panda-ng but the exact cause has not been determined to fix.
	- ```
IN:
0x0000100c:  e8a20001  stm      r2!, {r0}

R00=0000000a R01=00000002 R02=50004000 R03=00005000
R04=00000000 R05=00000000 R06=00000000 R07=00000000
R08=00000000 R09=00000000 R10=00000000 R11=00000000
R12=00000000 R13=00000000 R14=00000000 R15=0000100c
PSR=400001d3 -Z-- A svc32
Taking exception 4 [Data Abort] on CPU 0
...from EL1 to EL1
...with ESR 0x25/0x9600007f
...with DFSR 0x8 DFAR 0x50004000
Taking exception 3 [Prefetch Abort] on CPU 0
...from EL1 to EL1
...with ESR 0x21/0x8600003f
...with IFSR 0x8 IFAR 0x10
Taking exception 3 [Prefetch Abort] on CPU 0
...from EL1 to EL1
...with ESR 0x21/0x8600003f
...with IFSR 0x8 IFAR 0xc
Taking exception 3 [Prefetch Abort] on CPU 0
...from EL1 to EL1
...with ESR 0x21/0x8600003f
...with IFSR 0x8 IFAR 0xc
<...snip...>
```

- MemhookTests.test_aarch64_panda
	- Qemu thrashes with many prefetch exception errors. This is likely an issue with panda-ng but the exact cause has not been determined to fix.
	- ```
IN:
0x004008e4:  a9bb7bfd  stp      x29, x30, [sp, #-0x50]!
0x004008e8:  910003fd  mov      x29, sp
0x004008ec:  d2820080  movz     x0, #0x1004
0x004008f0:  f90027e0  str      x0, [sp, #0x48]
0x004008f4:  d2820180  movz     x0, #0x100c
0x004008f8:  f90023e0  str      x0, [sp, #0x40]
0x004008fc:  d2820480  movz     x0, #0x1024
0x00400900:  f9001fe0  str      x0, [sp, #0x38]
0x00400904:  d2820600  movz     x0, #0x1030
0x00400908:  f9001be0  str      x0, [sp, #0x30]
0x0040090c:  f94027e0  ldr      x0, [sp, #0x48]
0x00400910:  39400000  ldrb     w0, [x0]
0x00400914:  3900bfe0  strb     w0, [sp, #0x2f]
0x00400918:  f94023e0  ldr      x0, [sp, #0x40]
0x0040091c:  f9400000  ldr      x0, [x0]
0x00400920:  f90013e0  str      x0, [sp, #0x20]
0x00400924:  f9401fe0  ldr      x0, [sp, #0x38]
0x00400928:  f9400000  ldr      x0, [x0]
0x0040092c:  f9000fe0  str      x0, [sp, #0x18]
0x00400930:  f9401be0  ldr      x0, [sp, #0x30]
0x00400934:  f9400000  ldr      x0, [x0]
0x00400938:  f9000be0  str      x0, [sp, #0x10]
0x0040093c:  f94027e0  ldr      x0, [sp, #0x48]
0x00400940:  52800541  movz     w1, #0x2a
0x00400944:  39000001  strb     w1, [x0] 
0x00400948:  f94023e0  ldr      x0, [sp, #0x40]
0x0040094c:  d2800541  movz     x1, #0x2a
0x00400950:  f9000001  str      x1, [x0] 
0x00400954:  f9401fe0  ldr      x0, [sp, #0x38]
0x00400958:  d2800541  movz     x1, #0x2a
0x0040095c:  f9000001  str      x1, [x0] 
0x00400960:  f9401be0  ldr      x0, [sp, #0x30]
0x00400964:  d2800541  movz     x1, #0x2a
0x00400968:  f9000001  str      x1, [x0]
0x0040096c:  52800000  movz     w0, #0
0x00400970:  97ffff74  bl       #0x400740

 PC=00000000004008e4 X00=0000000000000000 X01=0000000000000000
X02=0000000000000000 X03=0000000000000000 X04=0000000000000000
X05=0000000000000000 X06=0000000000000000 X07=0000000000000000
X08=0000000000000000 X09=0000000000000000 X10=0000000000000000
X11=0000000000000000 X12=0000000000000000 X13=0000000000000000
X14=0000000000000000 X15=0000000000000000 X16=0000000000000000
X17=0000000000000000 X18=0000000000000000 X19=0000000000000000
X20=0000000000000000 X21=0000000000000000 X22=0000000000000000
X23=0000000000000000 X24=0000000000000000 X25=0000000000000000
X26=0000000000000000 X27=0000000000000000 X28=0000000000000000
X29=0000000000000000 X30=0000000000000000  SP=000000000000bff8
PSTATE=400003cd -Z-- EL3h
Taking exception 4 [Data Abort] on CPU 0
...from EL3 to EL3
...with ESR 0x25/0x96000021
...with FAR 0x100c
...with SPSR 0x400003cd
...with ELR 0x40091c
...to EL3 PC 0x200 PSTATE 0x3cd
Taking exception 3 [Prefetch Abort] on CPU 0
...from EL3 to EL3
...with ESR 0x21/0x86000010
...with FAR 0x200
...with SPSR 0x3cd
...with ELR 0x200
...to EL3 PC 0x200 PSTATE 0x3cd
Taking exception 3 [Prefetch Abort] on CPU 0
...from EL3 to EL3
...with ESR 0x21/0x86000010
...with FAR 0x200
...with SPSR 0x3cd
...with ELR 0x200
...to EL3 PC 0x200 PSTATE 0x3cd
<...snip...>
```

- LinkElfTests.test_link_elf_mips64_panda
	- Smallworld complains: `Base address defined for fixed-position ELF`
	- This is an issue with the smallworld test binary

- LinkElfTests.test_link_elf_mips64el_panda
	- Smallworld complains: `Base address defined for fixed-position ELF`
	- This is an issue with the smallworld test binary

- MemhookTests.test_armhf_panda
	- This test issues an 8 byte read for an address that is only 4 byte aligned.
	- The processor manuals state that the may not be atomic as though two 4 byte reads were issued for the two 4-byte aligned halves
	- Older version of qemu happened to actually issue two 4 byte reads, and the test assumes this is a requirement
	- We now report the 8 byte read as qemu is now actually atomic for the full 8 bytes whether 4 or 8-byte aligned address
	- This test should be changed to not depend on emulator internals, there's no reasonable way to preserve this level of architecture detail
