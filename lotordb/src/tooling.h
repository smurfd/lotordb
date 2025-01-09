#ifndef HASH_TOOLING_H
#define HASH_TOOLING_H 1
#include <stdint.h>
#define LEN 4096
#define u64 unsigned long long int // because linux uint64_t is not same as on mac
void bit_hex_str(char hs[], const uint8_t *d, const int len);
void bit_pack(u64 big[], const uint8_t byte[]);
void bit_unpack(uint8_t byte[], const u64 big[]);
int base64enc(char ed[], const uint8_t *data, int inl);
int base64dec(uint8_t dd[], const char *data, int inl);
#endif
