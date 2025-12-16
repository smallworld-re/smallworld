
extern int my_atoi(const char *arg);

int main(int argc, char *argv[]) {
    int out = 0xc001d00d;
    if (argc < 2) {
        return out;
    } 
    return my_atoi(argv[1]);
}
