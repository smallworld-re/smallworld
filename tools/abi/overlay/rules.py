"""Named Rules: every non-identity transform the generator applies to a
dependency value, other than a pure rename.

Stage 2 records, per generated field, which of these it applied (provenance),
and refuses to apply a transform that has no Rule here.
"""

import typing

from .documents import amd64_psabi
from .schema import Cite, Rule

RULES: typing.Tuple[Rule, ...] = (
    Rule(
        id="R-CANONICALIZE",
        summary=(
            "Ghidra register names become PlatformDef names through "
            "smallworld.platforms.naming.canonicalize_register, which folds "
            "lane pseudo-registers onto the register view that holds them "
            "(x86 XMMn_Qa, the low 8 bytes of xmmN, becomes xmmN)"
        ),
        cite=(Cite.ghidra("12.1", "x86/data/languages/x86-64-gcc.cspec:38-61"),),
    ),
    Rule(
        id="R-SRET-FIRST-INT",
        summary=(
            "a prototype whose output list ends in <hidden_return/> and has no "
            "hiddenret pentry passes the struct-return pointer in the first "
            "integer input register (Ghidra's default hidden-return placement)"
        ),
        cite=(Cite.ghidra("12.1", "x86/data/languages/x86-64-gcc.cspec:92-113"),),
    ),
    Rule(
        id="R-STACK-SLOT",
        summary=(
            "the first stack argument offset is the offset of the input list's "
            "stack pentry, and the slot size is that pentry's align attribute"
        ),
        cite=(Cite.ghidra("12.1", "x86/data/languages/x86-64-gcc.cspec:80-82"),),
    ),
    Rule(
        id="R-ROLE-FILTER",
        summary=(
            "partition roles: the stack pointer, frame pointer and thread pointer "
            "entries carry their roles; a thread-pointer register is neither "
            "callee- nor caller-saved; every other callee-saved integer entry "
            "holds a value (role value), and a callee-saved FP or vector entry "
            "an FP value (role fp-value)"
        ),
        cite=(amd64_psabi("§3.2.1 (Registers), Figure 3.4 (Register Usage)"),),
    ),
    Rule(
        id="R-COMPLEMENT",
        summary=(
            "caller-saved is every byte (for a bit-split register, every "
            "defined bit) of the register universe that is neither callee-saved "
            "nor in the neither class, and a bit-split register's undefined "
            "(reserved) bits are neither; Ghidra's <killedbycall> is incomplete "
            "and is only an oracle"
        ),
        cite=(amd64_psabi("§3.2.1 (Registers), Figure 3.4 (Register Usage)"),),
    ),
    Rule(
        id="R-CONFIDENCE-MIN",
        summary=(
            "a record's confidence is the minimum of its curated confidence and "
            "the confidence of every one of its entries; an entry that rests only "
            "on a master-seed marker is at most medium"
        ),
        cite=(),
    ),
    Rule(
        id="R-ANGR-SYSCALL-NUMBER",
        summary=(
            "the syscall number register is the register angr's syscall "
            "calling convention reads in syscall_num(state)"
        ),
        cite=(
            Cite.angr("10.0.0", "calling_conventions.py:2110-2112"),
            Cite.angr("9.2.194", "calling_conventions.py:1784-1786"),
        ),
    ),
)

BY_ID: typing.Dict[str, Rule] = {rule.id: rule for rule in RULES}
