#include <stdlib.h>

#include "debug.h"
#include "dns.h"
#include "ntoh.h"

int parse_dns_name(const uint8_t *buf, size_t cap, size_t *off,
                    char name[256]) {
    size_t  name_off    = 0;
    uint8_t label_size  = 0;
    char    letter      = '\0';

    while(1) {
        // Recover the label size
        if(cap - *off < 1) {
            // Not enough bytes
            DEBUG_PRINTF("%lu: Not enough bytes for label size at %lu\n", *off, name_off);
            return 1;
        }
        label_size = buf[*off];
        *off += 1;
        
        // Recover the label itself
        if(label_size == 0) {
            // NULL label; end of name
            break;
        } else if((label_size & 0xc0) == 0xc0) {
            // Label is a compressed reference.
            DEBUG_PRINTF("%lu: Compressed references aren't implemented\n", *off);
            return 1;
        } else if ((label_size & 0xc0) == 0x0) {
            // Label is a standard label
            if(name_off + label_size > 255) {
                // Adding label makes name exceed 255 characters
                DEBUG_PRINTF("%lu: Label of size %u at offset %lu exceeds max name size\n", 
                            *off, label_size, name_off);
                return 1;
            }
            if(cap - *off < label_size) {
                // Not enough bytes to read label
                DEBUG_PRINTF("%lu: Not enough bytes for label of size %u at %lu\n",
                            *off, label_size, name_off);
                return 1;
            }
            if(name_off != 0) {
                // Not the first item.  Add a dot.
                name[name_off] = '.';
                name_off += 1;
            }
            // Copy characters from buffer to name
            for(size_t i = 0; i < label_size; i++) {
                letter = buf[*off + i];
                // Check for valid domain name characters
                if((letter >= 'a' && letter <= 'z') |
                    (letter >= '0' && letter <= '9') |
                    (letter == '-')) {
                    name[name_off + i] = letter;
                } else {
                    DEBUG_PRINTF("%lu: Invalid domain name character %c at %lu\n",
                                *off + i, letter, name_off);
                    return 1;
                }
            }
            *off += label_size;
            name_off += label_size;
        } else {
            // Invalid token; the upper 2 bits are weird.
            DEBUG_PRINTF("%lu: Invalid label prefix 0x%02x at %lu\n",
                        *off, label_size, name_off);
            return 1;
        }
    }
    // Add our NULL terminator
    name[name_off] = '\0';
    return 0;
}

int parse_dns_header(const uint8_t *buf, size_t cap, size_t *off,
                    struct dns_header *hdr) {
    // DNS headers are always 12 bytes
    if(cap - *off < 12) {
        DEBUG_PRINTF("%lu: Not enough bytes for DNS header\n", *off);
        return 1;
    }
    // Decode transaction ID
    hdr->tid = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;

    // Decode flags
    hdr->flags = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;
    
    // Decode question count
    hdr->n_qs = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;

    // Decode answer count
    hdr->n_as = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;

    // Decode authority record count
    hdr->n_arrs = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;
    
    // Decode extra record count
    hdr->n_xrrs = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;

    return 0;
}

int parse_dns_question(const uint8_t *buf, size_t cap, size_t *off,
                    struct dns_question *q) {
    // Parse the name field
    if(parse_dns_name(buf, cap, off, q->qname)) {
        DEBUG_PRINTF("%lu: Failed parsing DNS name\n", *off);
        return 1;
    }
    // Questions need 4 bytes after the name
    if(cap - *off < 4) {
        DEBUG_PRINTF("%lu: Not enough bytes for DNS question\n", *off);
        return 1;
    }
    
    // Parse the question type
    q->qtype = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;

    // Parse the question class
    q->qtype = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;

    return 0;
}

int parse_dns_record(const uint8_t *buf, size_t cap, size_t *off,
                    struct dns_record *r) {
    // Parse the name
    if(parse_dns_name(buf, cap, off, r->name)) {
        DEBUG_PRINTF("%lu: Failed parsing DNS name\n", *off);
        return 1;
    }
    
    // Records need at least 10 bytes after the name
    if(cap - *off < 10) {
        DEBUG_PRINTF("%lu: Not enough bytes for DNS record\n", *off);
        return 1;
    }
    
    // Parse the record type
    r->type = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;

    // Parse the record class
    r->class = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;

    // Parse the TTL
    r->ttl = NTOHL(*(uint32_t *)(buf + *off));
    *off += 4;
    
    // Parse rdlen;
    r->rdlen = NTOHS(*(uint16_t *)(buf + *off));
    *off += 2;

    if(cap - *off < r->rdlen) {
        // Not enough bytes to parse rdata
        DEBUG_PRINTF("%lu: Not enough bytes for RDATA of size %lu\n", *off, r->rdlen);
        return 1;
    }
    // Parse rdata
    // You can figure out what's in it later.
    if((r->rdata = malloc(r->rdlen)) == NULL) {
        // Malloc died allocating rdata
        DEBUG_PRINTF("%lu: failed to alloc RDATA of size %lu\n", *off, r->rdlen);
        return 1;
    }
    for(size_t i = 0 ; i < r->rdlen; i++) {
        r->rdata[i] = buf[*off + i];
    }
    *off += r->rdlen;

    return 0;        
}

int parse_dns_record_list(const uint8_t *buf, size_t cap, size_t *off,
                    struct dns_record *rs, size_t n_rs) {
    int ret = 0;

    // NULL out rdata in all structs to indicate unallocated fields.
    for(size_t i = 0; i < n_rs; i++) {
        rs[i].rdata = NULL;
    }
    for(size_t i = 0; i < n_rs; i++) {
        if((ret = parse_dns_record(buf, cap, off, rs + i))) {
            DEBUG_PRINTF("%lu: Failed parsing DNS record %lu\n", *off, i);
            break;
        }
    }
    return ret;
}

int parse_dns_message(const uint8_t *buf, size_t cap, size_t *off, 
                    struct dns_message *msg) {
    int ret = 0;
    
    // NULL out list pointers
    msg->qs = NULL;
    msg->as = NULL;
    msg->arrs = NULL;
    msg->xrrs = NULL;

    // Parse the header
    if(parse_dns_header(buf, cap, off, &(msg->hdr))) {
        DEBUG_PRINTF("%lu: Failed parsing DNS header\n", *off);
        return 1;
    }

    // Parse questions
    do {
        if((msg->qs = malloc(sizeof(struct dns_question) * msg->hdr.n_qs)) == NULL) {
            DEBUG_PRINTF("%lu: Failed allocating %u questions\n",
                        *off, msg->hdr.n_qs);
            ret = 1;
            break;
        }
        for(size_t i = 0; i < msg->hdr.n_qs; i++) {
            if((ret = parse_dns_question(buf, cap, off, msg->qs + i))) {
                DEBUG_PRINTF("%lu: Failed parsing DNS question %lu\n", *off, i);
                break;
            }
        }
        if(ret) {
            break;
        }
        // Parse answers
        do {
            if((msg->as = malloc(sizeof(struct dns_record) * msg->hdr.n_as)) == NULL) {
                DEBUG_PRINTF("%lu: Failed allocating %u answer records\n",
                            *off, msg->hdr.n_as);
                ret = 1;
                break;
            }
            if((ret = parse_dns_record_list(buf, cap, off, msg->as, msg->hdr.n_as))) {
                DEBUG_PRINTF("%lu: Failed parsing DNS answers\n", *off);
                break;
            }
            // Parse Authority records
            do {
                if((msg->arrs = malloc(sizeof(struct dns_record) * msg->hdr.n_arrs)) == NULL) {
                    DEBUG_PRINTF("%lu: Failed allocating %u authority records\n",
                                *off, msg->hdr.n_arrs);
                    ret = 1;
                    break;
                }
                if((ret = parse_dns_record_list(buf, cap, off, msg->arrs, msg->hdr.n_arrs))) {
                    DEBUG_PRINTF("%lu: Failed parsing DNS authority records\n", *off);
                    break;
                } 
                // Parse Extra Records
                do {
                    if((msg->xrrs = malloc(sizeof(struct dns_record) * msg->hdr.n_xrrs)) == NULL) {
                        DEBUG_PRINTF("%lu: Failed allocating %u extra records\n",
                                    *off, msg->hdr.n_xrrs);
                        ret = 1;
                        break;
                    }
                    if((ret = parse_dns_record_list(buf, cap, off, msg->xrrs, msg->hdr.n_xrrs))) {
                        DEBUG_PRINTF("%lu: Failed parsing DNS extra records\n", *off);
                        break;
                    }
                } while(0);
                if(ret && msg->xrrs != NULL) {
                    // In case of failure, clean up extra records
                    free_dns_record_list(msg->xrrs, msg->hdr.n_xrrs);
                    free(msg->xrrs);
                    msg->xrrs = NULL;
                }
            } while(0);
            if(ret && msg->arrs != NULL) {
                // In case of failure, clean up authority records
                free_dns_record_list(msg->arrs, msg->hdr.n_arrs);
                free(msg->arrs);
                msg->arrs = NULL;
            }
        } while(0);
        if(ret && msg->as != NULL) {
            // In case of failure, clean up answers
            free_dns_record_list(msg->as, msg->hdr.n_as);
            free(msg->as);
            msg->as = NULL;
        }
    } while(0);
    if(ret && msg->qs != NULL) {
        // In case of failure, clean up questions
        free(msg->qs);
        msg->qs = NULL;
    }
    return ret;
}

void free_dns_record_list(struct dns_record *rs, size_t n_rs) {
    for(size_t i = 0; i < n_rs; i++) {
        if(rs[i].rdata != NULL) {
            free(rs[i].rdata);
            rs[i].rdata = NULL;
        }
    }
}

void free_dns_message(struct dns_message *msg) {
    // qs is a single flat array.  Clear it
    if(msg->qs != NULL) {
        free(msg->qs);
        msg->qs = NULL;
    }
    
    // The rest are lists of records
    if(msg->as != NULL) {
        free_dns_record_list(msg->as, msg->hdr.n_as);
        free(msg->as);
        msg->as = NULL;
    }

    if(msg->arrs != NULL) {
        free_dns_record_list(msg->arrs, msg->hdr.n_arrs);
        free(msg->arrs);
        msg->arrs = NULL;
    }

    if(msg->xrrs != NULL) {
        free_dns_record_list(msg->xrrs, msg->hdr.n_xrrs);
        free(msg->xrrs);
        msg->xrrs = NULL;
    }
}
