#ifndef FAKEDNS_DNS_H
#define FAKEDNS_DNS_H

#include <stdint.h>
#include <stddef.h>

enum dns_type {
    DNS_TYPE_A      = 1,    // Host Address
    DNS_TYPE_NS     = 2,    // Name Server
    DNS_TYPE_MD     = 3,    // Mail Destination (Obsolete; use MX)
    DNS_TYPE_MF     = 4,    // Mail Forwarder (Obsolete; use MX)
    DNS_TYPE_CNAME  = 5,    // Canonical name for an alias
    DNS_TYPE_SOA    = 6,    // Start of a Zone Authority
    DNS_TYPE_MB     = 7,    // Mailbox Domain (Experimental)
    DNS_TYPE_MG     = 8,    // Mail Group Member (Experimental)
    DNS_TYPE_MR     = 9,    // Mail Rename Domain (Experimental)
    DNS_TYPE_NULL   = 10,   // Null record (Experimental)
    DNS_TYPE_WKS    = 11,   // Well-known Service Description
    DNS_TYPE_PTR    = 12,   // Domain Name Pointer
    DNS_TYPE_HINFO  = 13,   // Host Information
    DNS_TYPE_MINFO  = 14,   // Mailbox or Mail List Info
    DNS_TYPE_MX     = 15,   // Mail Exchange
    DNS_TYPE_TXT    = 16,   // Text String
};

enum dns_class {
    DNS_CLASS_IN    = 1,    // Internet
    DNS_CLASS_CS    = 2,    // CSNET (Obsolete; used for examples in obsolete RFCs)
    DNS_CLASS_CH    = 3,    // CHAOS
    DNS_CLASS_HS    = 4,    // Hesiod
};

enum dns_qtype {
    DNS_QTYPE_A     = 1,    // Host Address
    DNS_QTYPE_NS    = 2,    // Name Server
    DNS_QTYPE_MD    = 3,    // Mail Destination (Obsolete; use MX)
    DNS_QTYPE_MF    = 4,    // Mail Forwarder (Obsolete; use MX)
    DNS_QTYPE_CNAME = 5,    // Canonical name for an alias
    DNS_QTYPE_SOA   = 6,    // Start of a Zone Authority
    DNS_QTYPE_MB    = 7,    // Mailbox Domain (Experimental)
    DNS_QTYPE_MG    = 8,    // Mail Group Member (Experimental)
    DNS_QTYPE_MR    = 9,    // Mail Rename Domain (Experimental)
    DNS_QTYPE_NULL  = 10,   // Null record (Experimental)
    DNS_QTYPE_WKS   = 11,   // Well-known Service Description
    DNS_QTYPE_PTR   = 12,   // Domain Name Pointer
    DNS_QTYPE_HINFO = 13,   // Host Information
    DNS_QTYPE_MINFO = 14,   // Mailbox or Mail List Info
    DNS_QTYPE_MX    = 15,   // Mail Exchange
    DNS_QTYPE_TXT   = 16,   // Text String 
    DNS_QTYPE_AXFR  = 252,  // Request for entire zone
    DNS_QTYPE_MAILB = 253,  // Request for all mailbox-related records (MB, MG, or MR)
    DNS_QTYPE_MAILA = 254,  // Request for all mail agent records (obsolete; use MX)
    DNS_QTYPE_ALL   = 255,  // Request for all records 
};

enum dns_qclass {
    DNS_QCLASS_IN   = 1,    // Internet
    DNS_QCLASS_CS   = 2,    // CSNET (Obsolete; used for examples in obsolete RFCs)
    DNS_QCLASS_CH   = 3,    // CHAOS
    DNS_QCLASS_HS   = 4,    // Hesiod
    DNS_QCLASS_ALL  = 255,  // Any class
};

// DNS Header
struct dns_header {
    uint16_t    tid;    // Transatction ID
    uint16_t    flags;  // Header flags
    uint16_t    n_qs;   // Number of questions
    uint16_t    n_as;   // Number of Answers
    uint16_t    n_arrs; // Number of Authority RRs
    uint16_t    n_xrrs; // Number of Additional RRs
};

// DNS Question
struct dns_question {
    char            qname[256]; // Question name
    enum dns_qtype  qtype;      // Question type
    enum dns_qclass qclass;     // Question class
};

// DNS Resource Record
struct dns_record {
    char            name[256];  // Resource domain name
    enum dns_type   type;       // Resource type
    enum dns_class  class;      // Resource class
    uint32_t        ttl;        // "Shelf-life" of cached record in seconds
    uint16_t        rdlen;      // Length of record data
    uint8_t        *rdata;      // Untyped record data
};

struct dns_message {
    struct dns_header   hdr;
    struct dns_question *qs;
    struct dns_record *as;
    struct dns_record *arrs;
    struct dns_record *xrrs;
};

int parse_dns_header(const uint8_t *buf, size_t cap, size_t *off,
                    struct dns_header *hdr);

int parse_dns_question(const uint8_t *buf, size_t cap, size_t *off,
                    struct dns_question *q);

int parse_dns_record(const uint8_t *buf, size_t cap, size_t *off,
                    struct dns_record *r);

int parse_dns_record_list(const uint8_t *buf, size_t cap, size_t *off,
                    struct dns_record *rs, size_t n_rs);

int parse_dns_message(const uint8_t *buf, size_t cap, size_t *off, 
                    struct dns_message *msg); 

void free_dns_record_list(struct dns_record *rs, size_t n_rs);

void free_dns_message(struct dns_message *msg);

#endif//FAKEDNS_DNS_H
