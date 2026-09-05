/* TLS-descriptor (gnu2 dialect) fixture.
 *
 * Built with -mtls-dialect=gnu2, which makes the compiler reach a thread-local
 * through a two-word descriptor in the GOT and an indirect call, rather than
 * the older __tls_get_addr call:
 *
 *     lea  x@TLSDESC(%rip), %rax
 *     call *x@TLSCALL(%rax)
 *     mov  %fs:(%rax), ...
 *
 * Two thread-locals, so the R_X86_64_TLSDESC relocations carry DIFFERENT
 * block offsets and a test can tell them apart -- collapsing them is exactly
 * what rebasing the symbol value by the load address used to do.
 */

__thread int first = 7;
__thread long second = 11;

int bump(int n) {
    first += n;
    return first + (int)second;
}
