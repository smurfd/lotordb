// Auth: smurfd, 2025 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include "../../../hash.h"
#include "ecc.h"

static inline u64 u64rnd(void) {
  u64 f7 = 0x7fffffffffffffff;
  int r[5], f = open("/dev/urandom", O_RDONLY);
  int rr = read(f, &r, sizeof r);
  close(f);
  if (rr < 0) return -1;
  return (r[0] & f7) << 48 ^ (r[1] & f7) << 35 ^ (r[2] & f7) << 22 ^ (r[3] & f7) << 9 ^ (r[4] & f7) >> 4;
}

// L = 3072, N = 256 (3072 / 8 = 384)
void ecc_sign_gen(void) {
  char e[384] = {0}, hash[666];
  u64 k = u64rnd();
  hash_new((char*)hash, (uint8_t*)"some string to hash");
  memcpy(e, hash, 384);
}
// ECDSA
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
// https://www.rfc-editor.org/rfc/rfc6979
// https://www.rfc-editor.org/rfc/rfc4050
