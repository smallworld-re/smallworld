#include <stdlib.h>
#include <stdio.h>

#include "dns.h"
#include "fio.h"

void print_dns_question(struct dns_question *q) {
    printf("Question:\n");
    printf("\tName:         %s\n", q->qname);
    printf("\tType:         %u\n", q->qtype);
    printf("\tClass:        %u\n", q->qclass);
}

void print_dns_record(struct dns_record *r) {
    printf("Record:\n");
    printf("\tName:         %s\n", r->name);
    printf("\tType:         %u\n", r->type);
    printf("\tClass:        %u\n", r->class);
}

void print_dns_message(struct dns_message *msg) {
    printf("DNS Message:\n");
    printf("\tTID:          %04x\n", msg->hdr.tid);
    printf("\tFLAGS:        %04x\n", msg->hdr.flags);
    printf("\t# Questions:  %u\n", msg->hdr.n_qs);
    printf("\t# Answers:    %u\n", msg->hdr.n_as);
    printf("\t# Auth. Rs:   %u\n", msg->hdr.n_arrs);
    printf("\t# Extra Rs:   %u\n", msg->hdr.n_xrrs);

    for(int i = 0; i < msg->hdr.n_qs; i++) {
        print_dns_question(&(msg->qs[i]));
    }   
    for(int i = 0; i < msg->hdr.n_as; i++) {
        print_dns_record(&(msg->as[i]));
    }
    for(int i = 0; i < msg->hdr.n_arrs; i++) {
        print_dns_record(&(msg->arrs[i]));
    }
    for(int i = 0; i < msg->hdr.n_xrrs; i++) {
        print_dns_record(&(msg->xrrs[i]));
    }
}

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
    
    print_dns_message(&msg);

    free_dns_message(&msg);
    free(buf);
    return 0;
}
