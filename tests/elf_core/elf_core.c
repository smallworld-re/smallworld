#include <stdio.h>
#include <stdlib.h>
#include <sys/procfs.h>

struct elf_prstatus foo;
char input_word[64];

int main() {

    if(fscanf(stdin, "%63s", input_word) != 1) {
        return 1;
    }
    __builtin_trap();
}
