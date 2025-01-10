// Auth: smurfd, 2025 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <math.h>
#include "../../../hash.h"
#include "ecc.h"

static inline void u64rnd_array(uint8_t h[], u64 k[], int len) {
  u64 f7 = 0x7fffffffffffffff;
  int r[2*len], f = open("/dev/urandom", O_RDONLY);
  int rr = read(f, &r, sizeof r);
  close(f);
  if (rr >= 0)
  for (int i = 0; i < len; ++i) {
    h[i] = (uint8_t)(r[i] & f7);
    k[i] = (u64)(r[i] & f7);
  }
}

// montgomerys ladder
// Pt multiplication
// curve E: (y*y) = (x*x*x) + ax + b
void ecc_pt_add(pt R, pt P, pt Q) {
  //u64 yt = (Q.y - P.y) / (Q.x - P.x);
  //R.x = yt*yt - P.x - Q.x;
  //R.y = yt*(P.x - R.x) - P.y;
  u64 yt[6] = {0};
  for (int i = 0; i < 6; i++) {
    yt[i] = (Q.y[i] - P.y[i]) / (Q.x[i] - P.x[i]);
    R.x[i] = yt[i]*yt[i] - P.x[i] - Q.x[i];
    R.y[i] = yt[i]*(P.x[i] - R.x[i]) - P.y[i];
  }
}

void ecc_pt_double(pt R, pt P) {
  pt tmp;
  memcpy(tmp.x, P.x, 6 * sizeof(u64));
  memcpy(tmp.y, P.y, 6 * sizeof(u64));
  ecc_pt_add(R, tmp, tmp);
}

void ecc_pt_multiplication(pt R0, pt R1, pt P) {
  int m = 6, di = 1;
  pt *Ptmp = malloc(sizeof(struct pt));
  memset(R0.x, 0, 6 * sizeof(u64));
  memset(R0.y, 0, 6 * sizeof(u64));
  memcpy(R1.x, P.x, 6 * sizeof(u64));
  memcpy(R1.y, P.y, 6 * sizeof(u64));
  for (int i = m; i >= 0; i--) {
    if (di == 0) {
      ecc_pt_add(R1, R0, R1);
      ecc_pt_double(R0, R0);
    } else {
      ecc_pt_add(R0, R0, R1);
      ecc_pt_double(R1, R1);
    }
    ecc_pt_add(*Ptmp, R0, P);
    //assert(memcmp(&R1, &Ptmp, sizeof(struct pt)) == 0);
  }
  free(Ptmp);
}

// For Alice to sign a message m, she follows these steps:
//   1. Calculate e = HASH(m), // HASH is a crypto hash function like SHA2, with the output converted to an int.
//   2. Let z be the leftmost Ln bits of e, where Ln is the bit length of group order n (z can be greater but not longer than n)
//   3. Select a cryptographically secure random int k from [1, n-1]
//   4. Calculate the curve point (x1, y1) = k x G
//   5. Calculate r = x1 mod n. If r == 0, goto step 3
//   6. Calculate s = k-1(z + rda) mod n. If s == 0, goto step 3
//   7. The signature is the pair (r, s). And (r, -s mod n) is also a valid signature
// L = 3072, N = 256 (3072 / 8 = 384)
void ecc_sign_gen(void) {
  char e[384] = {0}, hash[666] = {0}, z[384] = {0};
  pt curvep, curveg, pk;
  u64 k[6] = {0}, x1 = 0, y1 = 0, r = 1, s = 0, st = 0, n = 1;
  uint8_t h[6] = {0};
  hash_new((char*)hash, (uint8_t*)"some string to hash");
  memcpy(e, hash, 384);
  memcpy(z, hash, 384);
  while (r != 0) {
    //k = u64rnd();
    u64rnd_array(h, k, 6);
    ecc_pt_multiplication(pk, curvep, curveg); //incorrect curveg
    curvep.x[1] = (curveg.x[1] * k[1]);
    curvep.y[1] = (curveg.y[1] * k[1]);
    r = MOD(curvep.x[1], n);
    st = pow(k[1], -1);
  }
}
// ECDSA
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
// https://www.rfc-editor.org/rfc/rfc6979
// https://www.rfc-editor.org/rfc/rfc4050
