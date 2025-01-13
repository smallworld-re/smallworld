#include <stdlib.h>
#include <stdio.h>

#include "dns.h"
#include "fio.h"

int main(int argc, char *argv[]) {
    uint8_t            *buf = NULL;
    size_t              cap = 0;
    size_t              off = 0;
    struct dns_message  msg;

    if(argc < 2) {
        return 1;
    }
    if(read_file(argv[1], &buf, &cap)) {
        return 1;
    }
    if(parse_dns_message(buf, cap, &off, &msg)) {
        free(buf);
        return 1;
    }

    printf("DNS Message:\n");
    printf("\tTID:          %04x\n", msg.hdr.tid);
    printf("\tFLAGS:        %04x\n", msg.hdr.flags);
    printf("\t# Questions:  %u\n", msg.hdr.n_qs);
    printf("\t# Answers:    %u\n", msg.hdr.n_as);
    printf("\t# Auth. Rs:   %u\n", msg.hdr.n_arrs);
    printf("\t# Extra Rs:   %u\n", msg.hdr.n_xrrs);

    free_dns_message(&msg);
    free(buf);
    return 0;
}
