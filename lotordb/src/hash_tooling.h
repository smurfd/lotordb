#ifndef HASH_TOOLING_H
#define HASH_TOOLING_H 1
#include <stdint.h>

static char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
void bit_hex_str(char hs[], const uint8_t *d, const int len);
#endif
