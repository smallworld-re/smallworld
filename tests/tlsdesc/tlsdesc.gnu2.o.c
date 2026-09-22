/* TLS-descriptor fixture as an UNLINKED object.
 *
 * The .so fixtures carry R_X86_64_TLSDESC: the linker has already placed the
 * two-word descriptor in the GOT, and the relocation just fills it in. A .o
 * has not been through a linker, so it carries the earlier form instead:
 *
 *     lea  x@tlsdesc(%rip), %rax     # R_X86_64_GOTPC32_TLSDESC
 *     call *x@tlscall(%rax)          # R_X86_64_TLSDESC_CALL
 *
 * where the relocation names a GOT slot that does not exist yet. Loading this
 * therefore requires synthesizing the descriptor the linker would have made.
 *
 * Deliberately the same shape as tlsdesc.gnu2.so.c -- two thread-locals with
 * different block offsets, and bump(5) == 23 -- so the object and the shared
 * object can be held to the same answer.
 */

__thread int first = 7;
__thread long second = 11;

int bump(int n) {
    first += n;
    return first + (int)second;
}
