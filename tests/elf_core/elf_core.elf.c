#include <stdio.h>
#include <stdlib.h>
#include <sys/procfs.h>

char input_word[64];
int x = 1;

int main() {

    if(fscanf(stdin, "%63s", input_word) != 1) {
        return 1;
    }
    if (x == 1) {
        __builtin_trap();
    }
    puts(input_word);
}
