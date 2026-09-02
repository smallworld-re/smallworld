/* General-dynamic (classic gnu dialect) TLS fixture.
 *
 * Built with -mtls-dialect=gnu, the older ABI in which the compiler reaches a
 * thread-local by calling __tls_get_addr with a {module, offset} pair:
 *
 *     lea  x@TLSGD(%rip), %rdi
 *     call __tls_get_addr        # returns the ADDRESS, no thread pointer needed
 *
 * Two thread-locals, so the R_X86_64_DTPOFF64 relocations carry DIFFERENT
 * block offsets and a test can tell them apart -- collapsing them is exactly
 * what rebasing the symbol value by the load address used to do.
 */

__thread int first = 7;
__thread long second = 11;

int bump(int n) {
    first += n;
    return first + (int)second;
}
