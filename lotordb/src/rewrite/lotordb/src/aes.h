// Auth: smurfd, 2024 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#ifndef AES_H
#define AES_H 1
#include <stdint.h>
#define KEYSIZE1 sizeof(uint32_t) * 4
#define KEYSIZE2 sizeof(uint32_t) * 8

void cipher(uint32_t *ret, uint32_t *key, uint32_t *block);
void inv_cipher(uint32_t *ret, uint32_t *key, uint32_t *block);
#endif
// Code grabbed from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf and massaged
