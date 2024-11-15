#ifndef FAKEDNS_FIO_H
#define FAKEDNS_FIO_H

#include <stddef.h>
#include <stdint.h>

int read_file(const char *path, uint8_t **buf, size_t *cap);
int write_file(const char *path, uint8_t *buf, size_t cap);

#endif//FAKEDNS_FIO_H
