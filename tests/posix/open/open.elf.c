#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead0;
    char buf[16];

    // 1. Open an existing file O_RDWR; write/seek/read round-trip.
    int fd = open("/tmp/foobar", O_RDWR);
    if (fd < 0) {
        exit(1);
    }
    if (write(fd, "ABCDEF", 6) != 6) {
        exit(1);
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        exit(1);
    }
    if (read(fd, buf, 6) != 6) {
        exit(1);
    }
    if (memcmp(buf, "ABCDEF", 6) != 0) {
        exit(1);
    }

    // 2. A nonexistent file without O_CREAT fails.
    if (open("/tmp/no_such_file", O_RDONLY) != -1) {
        exit(1);
    }

    // 3. O_CREAT creates the file. This is the MIPS flag gotcha: O_CREAT is
    //    0x40 on the generic ABI but 0x100 on MIPS, so a decoder that is not
    //    architecture-aware would fail to create the file here on MIPS.
    int cfd = open("/tmp/created_by_open", O_RDWR | O_CREAT, 0644);
    if (cfd < 0) {
        exit(1);
    }
    if (write(cfd, "hi", 2) != 2) {
        exit(1);
    }

    // 4. O_APPEND positions writes at the end of the file. The second gotcha:
    //    O_APPEND is 0x400 on the generic ABI but 0x8 on MIPS. A separate
    //    appending handle must land its write past the existing "hi".
    int afd = open("/tmp/created_by_open", O_WRONLY | O_APPEND);
    if (afd < 0) {
        exit(1);
    }
    if (write(afd, "!", 1) != 1) {
        exit(1);
    }
    if (lseek(cfd, 0, SEEK_SET) != 0) {
        exit(1);
    }
    if (read(cfd, buf, 8) != 3) {
        exit(1);
    }
    if (memcmp(buf, "hi!", 3) != 0) {
        exit(1);
    }

    return *good;
}
