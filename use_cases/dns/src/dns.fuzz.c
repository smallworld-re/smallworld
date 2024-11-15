#include "dns.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct dns_message msg;
    size_t off = 0;
    if(parse_dns_message(data, size, &off, &msg)) {
        return 1;
    }
    free_dns_message(&msg);
    return 0;
}
