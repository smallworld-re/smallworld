# Instruction use/def validation corpus

This directory holds a validation corpus for SmallWorld's pcode-based
instruction use/def analysis (`smallworld/instructions/instr_use_def.py`,
`analyze_bytes()`), plus a harness (`harness.py`) that runs every corpus entry
through the analysis and compares the result against hand-written ground
truth.

## Files

- `corpus_<isa>.json` — one corpus per ISA: `x86_64`, `i386`, `ppc32`,
  `aarch64`, `mips32`.
- `harness.py` — runs the corpora through `analyze_bytes` and reports
  agreement with ground truth. Run as
  `python tests/use_def/harness.py [--isa x86_64] [--json report.json]`.

## Corpus file schema

```json
{
  "isa": "x86_64",
  "ghidra_lang": "x86:LE:64:default",
  "llvm_triple": "x86_64-unknown-linux-gnu",
  "base_address": 4096,
  "entries": [
    {
      "asm": "mov rax, qword ptr [rdx + 8]",
      "bytes": "488b4208",
      "categories": ["load", "base+disp"],
      "uses": [
        {"reg": "rdx"},
        {"mem": {"base": "rdx", "index": null, "scale": 1, "offset": 8, "size": 8}}
      ],
      "defs": [{"reg": "rax"}],
      "uses_optional": [],
      "defs_optional": [],
      "notes": ""
    }
  ]
}
```

Every entry is a single machine instruction, assembled at `base_address`
(each entry is analyzed independently — entries are NOT concatenated).
`bytes` is the hex encoding as produced by `llvm-mc --show-encoding` for
`llvm_triple` and verified by round-tripping through Capstone.

## Ground-truth conventions

An operand item is either `{"reg": "<name>"}` or
`{"mem": {"base": <reg-or-null>, "index": <reg-or-null>, "scale": <int>,
"offset": <signed int>, "size": <bytes>}}`.

1. **Register names** are lowercase, using the architecture's standard
   names (also what Capstone/Ghidra call them): `rax`/`eax`/`al`, `x0`/`w0`/
   `sp`, `r0`–`r31`/`lr`/`ctr`/`cr0`, `t0`/`a0`/`sp`/`ra`, etc. MIPS names
   drop the `$`.
2. **Ground truth is architectural**, not Ghidra-flavored: for
   `mov eax, ebx` the def is `eax` (the harness has a normalization mode
   that canonicalizes sub-registers to their full-width parent when
   comparing, so Ghidra's zero-extension modeling — a def of `rax` — still
   matches in normalized mode).
3. **The program counter is excluded** from use/def sets everywhere: no
   `rip`/`eip`/`pc` uses or defs, even for branches/calls. For PC-relative
   *data* addressing (x86-64 rip-relative, AArch64 `adr`/`ldr literal`),
   express the memory operand as an absolute address: `base: null`,
   `offset` = the fully resolved address (`base_address` + instruction
   length + displacement for x86; `base_address` + imm for AArch64), since
   the disassembler resolves it at decode time.
4. **Memory operands** are expressed in terms of register values *before*
   the instruction executes:
   - x86 `push rax` → uses `rax`, `rsp`; defs `rsp`,
     `mem{base: rsp, offset: -8, size: 8}`.
   - x86 `pop rax` → uses `rsp`, `mem{base: rsp, offset: 0, size: 8}`;
     defs `rax`, `rsp`.
   - PPC `stwu r1, -0x30(r1)` → uses `r1`; defs `r1`,
     `mem{base: r1, offset: -48, size: 4}`.
   - AArch64 pre-index `str x0, [sp, #-16]!` → uses `x0`, `sp`; defs `sp`,
     `mem{base: sp, offset: -16, size: 8}`.
   - AArch64 post-index `ldr x0, [x1], #8` → uses `x1`,
     `mem{base: x1, offset: 0, size: 8}`; defs `x0`, `x1`.
   Registers used to compute an address (base/index) are ALSO listed as
   plain register uses. `size` is the number of bytes accessed.
5. **`lea` and other pure address computations** have NO memory operand —
   only the base/index register uses and the destination def.
6. **A read-modify-write location** (`add [rax], rbx`) appears in both
   `uses` and `defs`.
7. **Flags** are individual registers, lowercase, named as Ghidra names
   them:
   - x86: `cf pf af zf sf of df`
   - AArch64: `ng zr cy ov`
   - PPC: `cr0`..`cr7` (one item per 4-bit field), `xer_so xer_ov xer_ca`
   - MIPS: none
   A flag genuinely read (e.g. `adc`, `jne`, conditional select) or written
   goes in `uses`/`defs`. Flags whose result is *architecturally undefined*
   for that instruction (e.g. `af` after `and`) go in `defs_optional`.
8. **`uses_optional`/`defs_optional`** list operands that are acceptable
   but not required — the analysis is not penalized for reporting or
   omitting them. Use for: architecturally-undefined flag effects, reads
   of hardwired-zero registers (MIPS `zero`, AArch64 `xzr`/`wzr` — reads
   go in `uses_optional`; writes to them in `defs_optional`), and modeling
   choices known to legitimately differ between tools. Use sparingly —
   every optional item weakens the test.
9. **Calls and returns**: only their data effects.
   - x86 `call` → uses `rsp`; defs `rsp`, `mem{base: rsp, offset: -8, size: 8}`.
   - x86 `ret` → uses `rsp`, `mem{base: rsp, offset: 0, size: 8}`; defs `rsp`.
   - AArch64 `bl` → defs `x30`; `ret` → uses `x30`.
   - PPC `bl` → defs `lr`; `blr` → uses `lr`; `bctr` → uses `ctr`.
   - MIPS `jal` → defs `ra`; `jr ra` → uses `ra`.
10. **Conditional branches** use the flags/registers they test and define
    nothing.

## Coverage checklist (per ISA, ≥50 entries)

- reg↔reg moves, immediate loads
- loads and stores in every common addressing mode the ISA has:
  base, base+disp, base+index, scaled index, absolute, PC-relative,
  pre/post-increment (AArch64), update forms (PPC `stwu`/`lwzu`)
- sub-word accesses (byte/halfword loads and stores, sign/zero extension)
- arithmetic (add/sub, with-carry variants), logical ops, shifts/rotates
  (immediate and register-counted), multiply/divide (incl. MIPS hi/lo)
- compares and tests
- conditional and unconditional branches, indirect jumps
- calls and returns
- stack operations (push/pop, ldp/stp, lmw/stmw)
- a few "weird but load-bearing" instructions per ISA: x86 `xchg`,
  `movs`/`stos` (no rep), `cdq`, `setcc`, `cmov`; PPC record forms
  (`add.`), `mfspr`/`mtspr`; AArch64 `csel`, `cbz`, `adrp`; MIPS
  branch-likely or `lui`/`ori` pairs, `mfhi`/`mflo`
