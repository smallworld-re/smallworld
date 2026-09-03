/* Uninitialized thread-locals: the .tbss half of a TLS block.
 *
 * Every other fixture here initializes all of its thread-locals, so the whole
 * TLS block is .tdata and PT_TLS has filesz == memsz. That leaves the block's
 * uninitialized half untested: the initialization image has to be zero-
 * EXTENDED to memsz, or the bytes behind an uninitialized thread-local are
 * not part of the block at all.
 *
 * `lead` is a single initialized byte and `wide` is 8-byte aligned, so the
 * linker leaves 7 bytes of padding between them: lead=0, wide=8, tail=0x10.
 * bump(5) is 8, and only if `lead` kept its initializer -- zeroed storage
 * returns 5.
 */

__thread char lead = 3;
__thread long long wide;
__thread int tail;

int bump(int n) {
    wide += n;
    tail = (int)wide + lead;
    return tail;
}
