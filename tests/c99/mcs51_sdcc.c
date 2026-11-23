/* Linked into each C99 test built for the 8051; see mcs51_cc.sh --c99.
 *
 * Stubs for what SDCC's library lacks; see mcs51_sdcc.h.  They let the
 * tests link; the runner replaces each with its model, and stops at exit as
 * a failure.  None should ever run.
 *
 * They are compiled on their own, not included in the test: SDCC would see
 * that each never returns and drop the test's calls to them.
 */

#include "mcs51_sdcc.h"

void exit(int status) {
    (void)status;
    for (;;) {
    }
}

double fabs(double x) {
    (void)x;
    exit(2);
    return 0;
}

char *strerror(int errnum) {
    (void)errnum;
    exit(2);
    return 0;
}

int strcoll(const char *s1, const char *s2) {
    (void)s1;
    (void)s2;
    exit(2);
    return 0;
}

int getchar(void) {
    exit(2);
    return 0;
}

int putchar(int c) {
    (void)c;
    exit(2);
    return 0;
}
