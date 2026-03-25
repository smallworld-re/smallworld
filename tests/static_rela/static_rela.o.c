#include <stdio.h>
#include <string.h>

char buf[64];

int main(int argc, char *argv[]) {
    if(argc < 2) {
        return 1;
    }
    strncpy(buf, argv[1], 63);
    buf[63] = '\0';

    printf("%s\n", buf);
    return 0;
}
