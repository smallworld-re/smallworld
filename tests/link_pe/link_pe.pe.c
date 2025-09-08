
extern int my_atoi(const char *arg);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return -1;
    } 
    return my_atoi(argv[1]);
}
