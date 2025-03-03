int foo = 0;

int bazgorp(int *bar) {
    return foo + *bar;
}

int main() {
    int bar = 0;
    (void) bazgorp(&bar);
}
