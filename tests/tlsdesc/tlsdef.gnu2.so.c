/* Defines a thread-local for tlsref.gnu2.so.c to import.
 *
 * `pad` comes first so `shared` sits at a non-zero block offset (4): an
 * offset of 0 would survive being wrongly rebased in one of the two load
 * orders, and the test could not tell the difference.
 */

__thread int pad = 1;
__thread int shared = 42;
