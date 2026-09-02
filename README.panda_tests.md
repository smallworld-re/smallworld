# Known-failing PANDA tests

The integration suite is manifest-driven: each case has an id of the form
`scenario:variant` (for example `dma:armel.panda`), and the test runner selects
cases with `--filter`, not by `unittest` class/method names. To run a single
case from the project dev shell:

```
nix develop . -c python3 tests/integration.py --filter 'dma:armel.panda'
```

Use `python3 tests/integration.py --list` to see every case and its current
skip status.

All PANDA cases are expected to pass except for the ones below, which are
recorded as skips in the corresponding manifest
(`tests/harness/scenarios/<scenario>.py`). The skip reason shown by `--list`
is quoted for each.

## `dma:armel.panda` — "Waiting for panda-ng fix"

Qemu thrashes with many prefetch exception errors. This is likely an issue with
panda-ng but the exact cause has not been determined to fix.

```
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
<...snip...>
```

## `memhook:i386.panda` — "Waiting for panda-ng"

Blocked on the same outstanding panda-ng fix as `dma:armel.panda`.

## `memhook:mips64.panda` / `memhook:mips64el.panda` — "Panda failure"

The memhook scenario currently fails under panda on the 64-bit MIPS variants.

## `link_elf:mips64.panda` / `link_elf:mips64el.panda` — "Unexpected failure"

SmallWorld complains: `Base address defined for fixed-position ELF`. This is an
issue with the SmallWorld test binary for these variants. The cases are pure
skips: the mips64/mips64el link_elf variants have no spec and are
short-circuited before any emulation runs.

## Resolved / historical notes

These variants used to fail and are now expected to pass (their manifest skip
reason is `None`), but the underlying notes are kept here for context.

- `memhook:aarch64.panda`: previously thrashed with prefetch exception errors,
  similar to `dma:armel.panda`.
- `memhook:armhf.panda`: this test issues an 8-byte read for an address that is
  only 4-byte aligned. The processor manuals state that this may not be atomic,
  as though two 4-byte reads were issued for the two 4-byte-aligned halves.
  Older versions of qemu happened to actually issue two 4-byte reads, and the
  test assumed this was a requirement. panda-ng now reports the 8-byte read as a
  single atomic access whether the address is 4- or 8-byte aligned. The test was
  changed to no longer depend on this emulator internal, since there is no
  reasonable way to preserve that level of architecture detail.
