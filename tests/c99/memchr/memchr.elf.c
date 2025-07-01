#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    
    char *data = NULL;
    data = memchr(argv[1], 'o', 4);

    if (data == NULL) {
        return *bad;
    }
    exit(0);
}
