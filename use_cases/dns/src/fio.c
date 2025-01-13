#include "fio.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"

int read_file(const char *path, uint8_t **buf, size_t *cap) {
    ssize_t nread = 0l;
    FILE *f = fopen(path, "r");
    
    if(f == NULL) {
        DEBUG_PRINTF("Failed opening file %s\n", path);
        return 1;
    }
    do {
        *buf = realloc(*buf, *cap + 1024);
        nread = fread(*buf + *cap, 1, 1024, f);
        if(nread < 0) {
            DEBUG_PRINTF("Failed reading file %s\n", path);
            return 1;
        }
        *buf = realloc(*buf, *cap + nread);
        *cap += nread;
    } while(nread > 0);
    fclose(f);
    return 0;
}

int write_file(const char *path, uint8_t *buf, size_t cap) {
    ssize_t nwrote = 0;
    FILE *f = fopen(path, "w");
    if(f == NULL) {
        DEBUG_PRINTF("Failed opening file %s\n", path);
        return 1;    
    }
    while(cap > 0) {
        nwrote = fwrite(buf, 1, cap, f);
        if(nwrote < 0) {
            DEBUG_PRINTF("Failed writing file %s\n", path);
            return 1;
        }
        buf += nwrote;
        cap -= nwrote;
    }
    fclose(f);
    return 0;
}
