/* The same uninitialized thread-locals, as an UNLINKED object.
 *
 * No linker has laid this TLS block out, so the loader has to: .tdata first,
 * then .tbss padded to its 8-byte alignment, landing on the same offsets
 * tlsbss.gnu2.so.c carries. Dropping the padding puts `wide` at offset 1,
 * and .tbss occupies no file space at all, so its bytes exist only if
 * something synthesizes them.
 *
 * Deliberately identical to tlsbss.gnu2.so.c so the two can be held to the
 * same offsets and the same bump(5) == 8.
 */

__thread char lead = 3;
__thread long long wide;
__thread int tail;

int bump(int n) {
    wide += n;
    tail = (int)wide + lead;
    return tail;
}
