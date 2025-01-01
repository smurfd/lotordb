// Auth: smurfd, 2024 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#ifndef AES_H
#define AES_H 1
#include <stdint.h>
#define KEYSIZE1 sizeof(uint32_t) * 4
#define KEYSIZE2 sizeof(uint32_t) * 8
#define u64 unsigned long long int // because linux uint64_t is not same as on mac

void cipher(uint32_t *ret, const uint32_t *key, const uint32_t *block);
void inv_cipher(uint32_t *ret, const uint32_t *key, const uint32_t *block);

void GCM_AUTHENC(uint8_t *c, uint8_t *t, const uint8_t *key, const uint8_t *iv, const uint8_t *plain, const uint8_t *aad, const uint32_t lenx);
void GCM_AUTHDEC(uint8_t *plain, uint8_t *t, const uint8_t *key, const uint8_t *iv, const uint8_t *c, const uint8_t *aad, const uint8_t *tag);
#endif
// Code grabbed from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf and massaged
