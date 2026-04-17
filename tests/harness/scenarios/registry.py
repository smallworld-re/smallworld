from __future__ import annotations

from . import (
    branch,
    call,
    checked_heap,
    dma,
    elf,
    exitpoint,
    fuzz,
    hooking,
    link_elf,
    link_pe,
    pe,
    recursion,
    rela,
    square,
    stack,
    static_buf,
    strlen,
    unmapped,
)

REGISTERED_SCENARIOS = (
    ("square", "square", square),
    ("branch", "branch", branch),
    ("call", "call", call),
    ("dma", "dma", dma),
    ("recursion", "recursion", recursion),
    ("stack", "stack", stack),
    ("strlen", "strlen", strlen),
    ("static_buf", "static_buf", static_buf),
    ("exitpoint", "exitpoint", exitpoint),
    ("unmapped", "unmapped", unmapped),
    ("checked_heap.double_free", "checked_heap.double_free", checked_heap),
    ("checked_heap.read", "checked_heap.read", checked_heap),
    ("checked_heap.uaf", "checked_heap.uaf", checked_heap),
    ("checked_heap.write", "checked_heap.write", checked_heap),
    ("fuzz", "fuzz", fuzz),
    ("elf", "elf", elf),
    ("hooking", "hooking", hooking),
    ("rela", "rela", rela),
    ("link_elf", "link_elf", link_elf),
    ("pe", "pe", pe),
    ("link_pe", "link_pe", link_pe),
)

_handlers: list[object] = []
for _, _, handler in REGISTERED_SCENARIOS:
    if handler not in _handlers:
        _handlers.append(handler)

HANDLERS = tuple(_handlers)
