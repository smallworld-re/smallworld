#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead0;
    char buf[8];

    // creat(path, mode) is open(path, O_WRONLY | O_CREAT | O_TRUNC, mode).
    // It creates a new (write-only) file.
    int fd = creat("/tmp/created_by_creat", 0644);
    if (fd < 0) {
        exit(1);
    }
    if (write(fd, "XYZ", 3) != 3) {
        exit(1);
    }

    // Re-creating an existing file truncates it. Write a shorter payload and
    // confirm, through a fresh read-only handle, that only the new content is
    // present -- if truncation had not happened the file would still be 3
    // bytes ("AYZ").
    int fd2 = creat("/tmp/created_by_creat", 0644);
    if (fd2 < 0) {
        exit(1);
    }
    if (write(fd2, "A", 1) != 1) {
        exit(1);
    }
    int rfd = open("/tmp/created_by_creat", O_RDONLY);
    if (rfd < 0) {
        exit(1);
    }
    if (read(rfd, buf, 8) != 1) {
        exit(1);
    }
    if (buf[0] != 'A') {
        exit(1);
    }

    return *good;
}
