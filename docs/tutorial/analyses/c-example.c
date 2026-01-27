#include <stdio.h>
#include <inttypes.h> 
#include <stdint.h>
#include <stdlib.h>

int mints[] = {61, 74, 96, 92, 87, 57, 74, 26, 11};

int call_sys(char *cmd) {

    uint64_t a = (uint64_t) cmd;
    int n = a >> 24;
    int m = sizeof(mints) / sizeof(mints[0]);

    printf("n=%d\n",n);
    printf("a=%"PRIX64"\n", a);

    a ^= 0xdeadbeef;
    for (int i=0; i<m; i++) {
        a += mints[i];
        /* printf("+ %d a=%"PRIX64"\n", i, a); */
    }
    printf("a=%"PRIX64"\n", a);

    for (int i=m-1; i>=0; i--) {
        a -= mints[i];
        /* printf("- %d a=%"PRIX64"\n", i, a); */
    }

    a ^= 0xdeadbeef;
    system((char *) a);


}


int main (int argc, char **argv) {

    call_sys(argv[1]);
}

