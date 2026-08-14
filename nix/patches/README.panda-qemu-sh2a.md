# `panda-qemu-sh2a.patch` — SH-2A / SH2A-FPU instruction set for QEMU's sh4 target

Companion note for `nix/patches/panda-qemu-sh2a.patch`, which backs SmallWorld's
`Architecture.SUPERH_SH2A_FPU` on the PANDA backend.

**Applies on top of `panda-qemu-superh.patch`.** The patch order in
`nix/panda-packages.nix` is `panda-qemu-tricore.patch`,
`panda-qemu-remove-debug-printf.patch`, `panda-qemu-superh.patch`,
`panda-qemu-sh2a.patch`; this patch is generated against the tree with the first
three applied and needs that ordering to apply at zero offset. The SH-4 patch
owns the exported `sh_sr_read()` / `sh_sr_write()` SR accessors that PANDA's cffi
bindings use — they are *not* duplicated here.

## Why it exists

QEMU's `target/sh4` models **SH-4 only** — the CPU models are `sh7750r`,
`sh7751r` and `sh7785`, and `enum sh_features` knew only about SH-4A. SH-2A is a
different branch of the SuperH family: it shares the SH-2 base ISA with SH-4, but

* adds ~40 instructions of its own, including **SuperH's only 32-bit encodings**,
* drops SH-4's MMU, cache-control and vector-FPU instructions,
* has no user mode and no banked `R0`–`R7`,
* replaces the SH-4 reset vector with a vector table at address 0.

So SH-2A code does not merely run "a bit differently" on an SH-4 core — the
instructions a real SH-2A toolchain emits most are precisely the ones SH-4 lacks.
`gcc -m2a` uses `MOVML.L`/`MOVMU.L` in essentially every function prologue and
epilogue, and `MOVI20`/`MOVI20S` for large constants.

## Where the encodings came from

Not from memory. This same QEMU tree already vendors the binutils SH opcode table
at `disas/sh4.c`. Every row tagged `arch_sh2a_up` or `arch_sh2a_nofpu_up` and not
shared with SH-3/SH-4 was extracted mechanically — 56 rows, of which 24 carry
`arch_op32` (the 32-bit forms) — and each `case` label in the patch was then
re-derived from that table a second time and diffed against the implementation.
To re-extract the table:

```sh
Q=$(nix eval --raw '.#...panda-qemu-src')   # or read it out of flake.lock
grep -nE 'arch_sh2a(_nofpu)?_up' "$Q/disas/sh4.c" | grep -vE 'arch_sh3|arch_sh4|arch_sh2_up'
```

The operand-descriptor semantics (`IMM0_20`, `IMM0_20BY8`, `IMM0_3c`/`IMM0_3s`,
`IMM0_3Uc`, `DISP0_12*`/`DISP1_12*`) are defined in the same file and were used
verbatim for the immediate and displacement maths.

## What is implemented

| Area | Detail |
|---|---|
| `target/sh4/cpu.h` | `SH_FEATURE_SH2A`, `env->tbr`, `SR_CS` (bit 13), `SH_CPU_SH7264`/`SH_CPU_SH7269` |
| `target/sh4/cpu-qom.h` | `TYPE_SH7264_CPU`, `TYPE_SH7269_CPU` |
| `target/sh4/cpu.c` | `sh7264`/`sh7269` CPU classes; SH-2A reset (PC = 0, `SR.MD` set but `RB`/`BL` clear); `info->mach = bfd_mach_sh2a` so the disassembler decodes SH-2A |
| `target/sh4/translate.c` | `CHECK_SH2A`/`CHECK_NOT_SH2A`, 32-bit second-word fetch, all 56 encodings, conservative TB instruction bound |
| `target/sh4/{helper.h,op_helper.c}` | `helper_divs`/`helper_divu` |
| `disas/sh4.c` | `bfd_mach_sh2a` / `bfd_mach_sh2a_nofpu` → `arch_sh2a` / `arch_sh2a_nofpu` |

All 42 SH-2A-only mnemonics are covered:

`ldc Rm,TBR` · `stc TBR,Rn` · `mov.{b,w,l} R0,@Rn+` · `mov.{b,w,l} @-Rm,R0` ·
`mov.{b,w,l}` to/from `@(disp12,Rn)` · `movu.{b,w} @(disp12,Rm),Rn` ·
`fmov.{s,d}` to/from `@(disp12,Rn)` · `movi20` · `movi20s` ·
`bclr`/`bset`/`bst`/`bld` `#imm3,Rn` ·
`bclr.b`/`bset.b`/`bst.b`/`bld.b`/`bldnot.b`/`band.b`/`bandnot.b`/`bor.b`/`bornot.b`/`bxor.b`
`#imm3,@(disp12,Rn)` · `clips.{b,w}` · `clipu.{b,w}` · `divs` · `divu` · `mulr` ·
`movrt` · `nott` · `movml.l` · `movmu.l` · `jsr/n @Rm` ·
`jsr/n @@(disp8,TBR)` · `rts/n` · `rtv/n` · (`ldbank`/`stbank`/`resbank`: see below)

### Delay slots

`RTS/N`, `RTV/N` and `JSR/N` are the SuperH family's only delay-slot-*free*
control transfers. They deliberately do **not** go through `ctx->delayed_pc` /
`TB_FLAG_DELAY_SLOT`; `gen_sh2a_jump_now()` writes `cpu_pc` and ends the block
within the same instruction. Because there is no delay slot, `JSR/N` sets
`PR = pc + 2` rather than the `pc + 4` that `JSR` uses.

32-bit instructions are rejected inside a delay slot (`CHECK_NOT_DELAY_SLOT`),
matching the architecture.

### SH-4 instructions that now fault on SH-2A

`ldtlb`, `movca.l`, `ocbi`, `ocbp`, `ocbwb`, `frchg`, `fsrra`, `fipr`, `ftrv`.
`fschg` is *kept* — the opcode table lists it as `arch_sh4_up | arch_sh2a_up`.
`prefi`, `icbi` and `movua.l` were already `CHECK_SH4A`, which excludes SH-2A
automatically.

## What is NOT implemented

### Register bank (`LDBANK` / `STBANK` / `RESBANK`)

These are decoded and then raise an illegal-instruction exception.

The SH-2A register bank is 512 entries × 20 longwords, and it is filled and
drained by the **automatic save/restore the SH-2A interrupt controller performs
on exception entry** — machinery QEMU's SH-4 model does not have in any form.
Without that automatic side, `RESBANK` would never have anything meaningful to
restore, and `LDBANK`/`STBANK` would be addressing storage nothing else touches.
Faulting is honest; inventing a bank-address layout and silently returning zeroes
would be worse than a clean fault, because it would fail silently.

This only matters for interrupt-handler firmware. Ordinary compiled code, and
everything SmallWorld's test suite exercises, never uses these.

### Automatic bank switch on interrupt

Not implemented, as above.

## Cross-checked against Ghidra's SH-2A sleigh

Ghidra 12.1.2's `Ghidra/Processors/SuperH/data/languages/superh.sinc` is an
independent implementation of the same manual, and was used to settle the two
points I originally could not:

1. **`SR.CS` is set-only / software-cleared.** `:clips.b` does
   `if (!(uppercheck || lowercheck)) goto inst_next;` before ever touching the
   flag, and the saturating path only assigns `$(CS_FLAG)=1` — so CS is never
   cleared by a non-saturating clip. `CS_FLAG` is `sr[13,1]`, matching `SR_CS`.
   `gen_sh2a_clip()` therefore or-s into `cpu_sr` rather than depositing, which
   is what it already did. (Ghidra's authors also left a comment there noting
   "The pseudo code for clips in the super-h manual looks incorrect" — worth
   knowing if this is ever revisited from the manual alone.)

2. **Transfer slot 15 is PR, not R15 — in both instructions and both
   directions.** Every slot-15 rule in the sleigh reads `storeRegister(pr, r15)`
   or `loadRegister(pr, r15)`:

   ```
   MovMLReg1_15: ... & rm_08_11=15 { storeRegister(pr,r15); build MovMLReg1_14store; }
   MovMLReg2_15: ... & rm_08_11=15 { build MovMLReg2_14load; loadRegister(pr,r15); }
   MovMUReg1_15: ... & rm_08_11=15 { storeRegister(pr,r15); }
   MovMUReg2_15: ... & rm_08_11=15 { loadRegister(pr,r15); }
   ```

   **This found a real bug.** My first version substituted PR only in MOVMU's
   last slot and used `REG(15)` for MOVML with `Rm == R15`, i.e. it pushed the
   stack pointer where PR belonged, and then skipped the R15 adjustment on the
   matching pop. `gen_sh2a_movml()` now applies one uniform rule — *transfer
   index 15 is PR* — which collapses both cases, makes R15 never a transfer
   operand, and lets the R15 adjustment be unconditional. Re-verified against a
   model of the sleigh macros (`storeRegister` pre-decrements, `loadRegister`
   post-increments) for all `m` = 0..15 × {MOVML, MOVMU} × {store, load}: full
   agreement, plus push/pop round-trip.

   So `MOVML.L R15,@-R15` transfers R0..R14 **and PR**, and
   `MOVMU.L R15,@-R15` transfers PR alone.

3. **The `/N` forms' return address and delay-slot-freedom** were confirmed the
   same way. `:jsr @rm` uses `_pr = inst_start + 4`, which calibrates the
   convention against QEMU's existing `ctx->base.pc_next + 4`; `:jsr"/n"` uses
   `pr = inst_next`, i.e. `inst_start + 2`, matching this patch's
   `ctx->base.pc_next + 2`. None of `jsr/n`, `jsr/n @@(disp,TBR)`, `rts/n` or
   `rtv/n` contains a `delayslot(1)` call, unlike `jsr`/`jmp`/`rts`/`bsr`/`bsrf`
   — which is the independent confirmation that they are delay-slot-free.
   `:rtv"/n"` assigns `r0 = rm` and *then* `return [pr]`, the order used here.

### Still unverified

* **`LDC Rm,TBR` privilege.** Not gated on `CHECK_PRIVILEGED`, on the grounds
  that SH-2A has no user mode. Harmless in practice because the SH-2A reset sets
  `SR.MD`.
* **`DIVS`/`DIVU` corner cases.** Zero divisor returns 0 and `INT_MIN / -1`
  returns `INT_MIN`, to avoid a host trap where the architecture says
  "undefined". Any defined value is conformant; these are just the choices made.

### A caution on using sleigh as an oracle

These specs are not uniformly trustworthy. In the *SH-4* spec (`SuperH4.sinc`),
`:bsr` never assigns `PR` at all, and `:bsrf`/`:jsr` assign `inst_next` rather
than the architectural `inst_start + 4`. The SH-2A spec gets all three right.
Where the SH-2A sleigh and the manual agree, trust them; where they disagree,
the manual wins.

## Things a reviewer should know about the fetch path

`sh4_tr_translate_insn()` now conditionally reads a second word. The three 32-bit
first-word families (`0011nnnnmmmm0001`, `0011nnnn0iii1001`,
`0000nnnniiii000x`) are unused on SH-1..SH-4, so SH-4 decoding is bit-for-bit
unchanged; the fetch is additionally gated on `SH_FEATURE_SH2A` so a non-SH-2A
CPU still consumes exactly two bytes per instruction.

`sh4_tr_init_disas_context()` used to bound a TB by
`page_bytes_remaining / 2`, justified by the ISA being fixed-width. That
justification no longer holds on SH-2A, so the divisor becomes 4 there — a
conservative bound (we may end a TB early, never late) that keeps a run of 32-bit
instructions from walking off the end of the page. SH-4 keeps the exact `/ 2`.

## Verification actually performed

* All 56 SH-2A rows in `disas/sh4.c` mechanically re-derived and matched against
  the implemented `case` labels and inner word-2 selectors.
* The whole of `_decode_opc` (with all new cases) plus the new helper functions
  compiled with `gcc -fsyntax-only -Wall -Wextra` against a stub harness: **0
  errors**. This also proves there are **no duplicate `case` values**, i.e. none
  of the new labels collide with an existing SH-4 label in the same switch — the
  check was confirmed live by injecting a deliberate duplicate and watching GCC
  reject it.
* `movi20` / `movi20s` immediate maths checked exhaustively over the 4-bit high
  nibble × sampled 16-bit low words against the disassembler's own reference
  expression.
* `MOVML`/`MOVMU` register order, addresses and SP updates checked against a
  model of Ghidra's SH-2A sleigh macros for every `m` = 0..15 × {MOVML, MOVMU} ×
  {store, load}, including push/pop round-trip, and asserting R15 is never a
  transfer operand.
* `helper_divs`/`helper_divu` behaviourally unit-tested.
* Applied after `panda-qemu-superh.patch` with both `patch -p1` and
  `git apply`, at **zero fuzz and zero offset**, and the applied result is
  byte-identical to the tree the patch was generated from. `sh_sr_read` appears
  exactly once in `target/sh4/cpu.c` and once in `target/sh4/cpu.h` (both from
  the SH-4 patch).

**Not** verified: anything requiring a built QEMU. No instruction has been
executed. The first real test is
`nix develop . -c python3 tests/run_case.py square sh2a.panda 42`, and the
four-way `pcode`/`angr`/`styx`/`panda` register-dump comparison described in the
plan's verification section is the strongest available check on this patch.

## Regenerating

The baseline is the pinned tree **plus `panda-qemu-superh.patch`** — regenerate
against anything else and the `target/sh4/cpu.c` hunks pick up a +15-line offset.

```sh
Q=/nix/store/<hash>-panda-qemu-src   # from flake.lock, panda-qemu-src node.
                                     # NB: this store path is already the output
                                     # of applyPatches, i.e. tricore and
                                     # remove-debug-printf are baked in.
P=$(git rev-parse --show-toplevel)/nix/patches

# base/ = pinned tree + the SH-4 patch
mkdir -p /tmp/sh2a/{base,mine}
for d in base mine; do
  mkdir -p /tmp/sh2a/$d/target/sh4 /tmp/sh2a/$d/disas \
           /tmp/sh2a/$d/panda/src /tmp/sh2a/$d/hw/avatar
  cp --no-preserve=mode $Q/target/sh4/*.{c,h}      /tmp/sh2a/$d/target/sh4/
  cp --no-preserve=mode $Q/disas/sh4.c             /tmp/sh2a/$d/disas/
  cp --no-preserve=mode $Q/panda/src/{common.c,panda_arch.c} /tmp/sh2a/$d/panda/src/
  cp --no-preserve=mode $Q/hw/avatar/{configurable_machine.c,meson.build} \
                                                   /tmp/sh2a/$d/hw/avatar/
done

# mine/ = base/ + this patch, then edit under mine/
(cd /tmp/sh2a/base && patch -p1 < $P/panda-qemu-superh.patch)
(cd /tmp/sh2a/mine && patch -p1 < $P/panda-qemu-superh.patch \
                   && patch -p1 < $P/panda-qemu-sh2a.patch)

# ... edit /tmp/sh2a/mine/ ... then:
cd /tmp/sh2a
for f in target/sh4/cpu.h target/sh4/cpu-qom.h target/sh4/cpu.c \
         target/sh4/helper.h target/sh4/op_helper.c target/sh4/translate.c \
         disas/sh4.c; do
  git diff --no-index --no-prefix -- "base/$f" "mine/$f" \
    | sed -e '/^index /d' \
          -e "1s|.*|diff --git a/$f b/$f|" \
          -e "s|^--- base/$f|--- a/$f|" -e "s|^+++ mine/$f|+++ b/$f|"
done
```

Prepend the `#`-prefixed header comment: `pkgs.applyPatches` tolerates it, and it
is the first thing the next person will read.

Then re-verify the whole chain applies at zero fuzz *and* zero offset:

```sh
mkdir -p /tmp/seq && cd /tmp/seq
cp -r --no-preserve=mode $Q/target $Q/disas $Q/panda . && mkdir -p hw
cp -r --no-preserve=mode $Q/hw/avatar hw/
patch -p1 < $P/panda-qemu-superh.patch
patch -p1 < $P/panda-qemu-sh2a.patch      # must print no "offset"/"fuzz"
test "$(grep -c sh_sr_read target/sh4/cpu.c)" = 1 && echo "SR accessors OK"
```
