#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead0;

    int fd1 = open("/tmp/foobar", O_RDWR);
    if (fd1 < 0) {
        exit(1);
    }
    // Establish some content and advance the shared offset to 8.
    if (write(fd1, "ABCDEFGH", 8) != 8) {
        exit(1);
    }

    int fd2 = dup(fd1);
    if (fd2 < 0) {
        exit(1);
    }

    // dup'd fds share one open file description, so they share the file
    // offset. Moving fd1's offset must be visible through fd2. The old model
    // copied the cursor by value, giving each handle its own offset, so fd2
    // kept the copied 8 and this check failed.
    if (lseek(fd1, 2, SEEK_SET) != 2) {
        exit(1);
    }
    if (lseek(fd2, 0, SEEK_CUR) != 2) {
        exit(1);
    }

    return *good;
}
