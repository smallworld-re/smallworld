#include <stdlib.h>

int main(int argc, char *argv[]) {
    div_t res = div(argc, 5);
    return res.quot + res.rem;
}
