/* Imports a thread-local defined in another module.
 *
 * Cross-module is the case link_elf gets wrong: a TLS symbol's value is an
 * offset within its DEFINER's block, so resolving it must carry the offset
 * across unchanged. Rebasing leaves the delta between the two load
 * addresses, which is an offset into nothing.
 */

extern __thread int shared;

int readshared(void) { return shared; }
