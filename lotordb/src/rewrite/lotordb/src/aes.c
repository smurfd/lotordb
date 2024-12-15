// Auth: smurfd, 2024 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "aes.h"

// TODO: Figure out later how to generate these
static const uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t reverse_sbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// TODO: Fix always have 1st argument as return value if needed
static unsigned long long str_to_bin(const char *s) {
  unsigned long long i = 0;
  while (*s) {
    i <<= 1;
    i += *s++ - '0';
  }
  return i;
}

static void long_to_bin(uint8_t *ret, u64 num) {
  uint8_t i = 0;
  while (num != 0) {
    ret[i++] = num % 2;
    num /= 2;
  }
}

static u64 bin_to_long(uint8_t *bin) {
  uint8_t num[128] = {0};
  u64 dec = 0, base = 1;
  memcpy(num, bin, 128 * sizeof(uint8_t));
  for (uint8_t i = 127; i >= 0; i--) {
    if (num[i] == 1) dec += base;
    base *= 2;
  }
  return dec;
}

static uint8_t times(uint8_t x) {
  return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

uint8_t *right_pad_to_multiple_of_16_bytes(uint8_t *input, int len) {
  while (len++ % 16 != 0) {
    input[len] = 0;
  }
  return input;
}

/*

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

void initialize_aes_sbox(uint8_t sbox[256]) {
  uint8_t p = 1, q = 1;
  
  // loop invariant: p * q == 1 in the Galois field
  do {
    // multiply p by 3
    p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

    // divide q by 3 (equals multiplication by 0xf6)
    q ^= q << 1;
    q ^= q << 2;
    q ^= q << 4;
    q ^= q & 0x80 ? 0x09 : 0;

    // compute the affine transformation
    uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

    sbox[p] = xformed ^ 0x63;
  } while (p != 1);

  // 0 is a special case since it has no inverse
  sbox[0] = 0x63;
}

static void ShiftRows(AES_BYTE *b, int Nb, char *t)
{
  AES_BYTE *temp = alloca(AES_WS*Nb);
  int i, j;

  memcpy(temp, b, AES_WS*Nb);

  for (i = 0; i < AES_WS; i++) {
    for (j = 0; j < Nb; j++) {
      b[j*AES_WS + i] = temp[(j + t[i] + Nb) % Nb * AES_WS + i];
    }
  }
}
*/

static void copystate(state_t *state, state_t *in) {
  memcpy(state->state, in->state, 4 * NB * sizeof(uint8_t));
}

static void statefromarr(state_t *state, const uint8_t in[16]) {
  memcpy(state->state, in, 4 * NB * sizeof(uint8_t));
}

static void arrfromstate(uint8_t s[16], state_t *state) {
  memcpy(s, state->state, 4 * NB * sizeof(uint8_t));
}

static void xorarr(uint8_t *r, const uint8_t *X, const uint8_t *Y) {
  for (uint8_t i = 0; i < 4 * NB * sizeof(uint8_t); i++) {
    r[i] = X[i] ^ Y[i];
  }
}

static void rcon(uint8_t *wrd, const uint8_t a) {
  uint8_t c = 1;
  for (uint8_t i = 0; i < a - 1; i++) {
    c = (c << 1) ^ (((c >> 7) & 1) * 0x1b);
  }
  wrd[0] = c;
  wrd[1] = wrd[2] = wrd[3] = 0;
}

#define AES(x, y) 0 // TODO: fix : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf // also return length
#define POLYVAL(x, y) 0 // TODO: fix
//#define POLYVAL() ByteReverse(GHASH(ByteReverse(H) * x, ByteReverse(X_1), ByteReverse(X_2), ...))
//  returns Its result is S_s, where S is defined by the iteration S_0 = 0; S_j = dot(S_{j-1} + X_j, H), for j = 1..s.
//  POLYVAL takes a field element, H, and a series of field elements X_1, ..., X_s.  Its result is S_s, where S is defined by the iteration S_0 = 0; S_j = dot(S_{j-1} + X_j, H), for j = 1..s.
// https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/Galois%20Counter%20Mode%20with%20Secure%20Short%20Tags.pdf
// https://medium.com/codex/aes-how-the-most-advanced-encryption-actually-works-b6341c44edb9
// https://networkbuilders.intel.com/docs/networkbuilders/advanced-encryption-standard-galois-counter-mode-optimized-ghash-function-technology-guide-1693300747.pdf

// https://datatracker.ietf.org/doc/html/rfc8452#appendix-A

// https://blog.0x7d0.dev/education/how-aes-is-implemented/
// https://github.com/m3y54m/aes-in-c?tab=readme-ov-file#the-rijndael-key-schedule

// AES https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
void ADDROUNDKEY(state_t *state, const uint8_t *key) {
  state_t *temp = malloc(sizeof(state_t));
  memset(temp, 0, sizeof(state_t));
  copystate(temp, state);
  for (uint8_t i = 0; i < 16; ++i) {
    temp->state[i % 4][i / 4] = state->state[i % 4][i / 4] ^ key[(i % 4) + 4 * (i / 4)];
  }
  copystate(state, temp);
  free(temp);
}

void SUBBYTES(state_t *state) {
  for (uint8_t i = 0; i < 16; i++) {
    state->state[i / 4][i % 4] = sbox[state->state[i / 4][i % 4]];
  }
}

void INVSUBBYTES(state_t *state) {
  for (uint8_t i = 0; i < 16; i++) {
    state->state[i % 4][i / 4] = reverse_sbox[state->state[i % 4][i / 4]];
  }
}

void SHIFTROWS(state_t *state) {
  uint8_t temp[4] = {0};
  memcpy(temp, state->state[1], 4 * sizeof(uint8_t));
  state->state[1][0] = temp[1];
  state->state[1][1] = temp[2];
  state->state[1][2] = temp[3];
  state->state[1][3] = temp[0];

  memcpy(temp, state->state[2], 4 * sizeof(uint8_t));
  state->state[2][0] = temp[1];
  state->state[2][1] = temp[2];
  state->state[2][2] = temp[3];
  state->state[2][3] = temp[0];

  memcpy(temp, state->state[3], 4 * sizeof(uint8_t));
  state->state[3][0] = temp[1];
  state->state[3][1] = temp[2];
  state->state[3][2] = temp[3];
  state->state[3][3] = temp[0];
}

void INVSHIFTROWS(state_t *state) {
  uint8_t temp[4] = {0};
  memcpy(temp, state->state[1], 4 * sizeof(uint8_t));
  state->state[1][0] = temp[3];
  state->state[1][1] = temp[0];
  state->state[1][2] = temp[1];
  state->state[1][3] = temp[2];

  memcpy(temp, state->state[2], 4 * sizeof(uint8_t));
  state->state[2][0] = temp[3];
  state->state[2][1] = temp[0];
  state->state[2][2] = temp[1];
  state->state[2][3] = temp[2];

  memcpy(temp, state->state[3], 4 * sizeof(uint8_t));
  state->state[3][0] = temp[3];
  state->state[3][1] = temp[0];
  state->state[3][2] = temp[1];
  state->state[3][3] = temp[2];
}

void mixcolumn(uint8_t *state) {
  uint8_t t = state[0] ^ state[1] ^ state[2] ^ state[3];
  uint8_t u = state[0];
  state[0] ^= t ^ times(state[0] ^ state[1]);
  state[1] ^= t ^ times(state[1] ^ state[2]);
  state[2] ^= t ^ times(state[2] ^ state[3]);
  state[3] ^= t ^ times(state[3] ^ u);
}

void MIXCOLUMNS(state_t *state) {
  mixcolumn(state->state[0]);
  mixcolumn(state->state[1]);
  mixcolumn(state->state[2]);
  mixcolumn(state->state[3]);
}

void INVMIXCOLUMNS(state_t *state) {
  for (uint8_t i = 0; i < 4; ++i) {
    uint8_t u = times(times(state->state[i][0] ^ state->state[i][2]));
    uint8_t v = times(times(state->state[i][1] ^ state->state[i][3]));
    state->state[i][0] ^= u;
    state->state[i][1] ^= v;
    state->state[i][2] ^= u;
    state->state[i][3] ^= v;
  }
  MIXCOLUMNS(state);
}

void SUBWORD(uint8_t *word) {
  word[0] = sbox[word[0]];
  word[1] = sbox[word[1]];
  word[2] = sbox[word[2]];
  word[3] = sbox[word[3]];
}

void ROTWORD(uint8_t *word) {
  uint8_t temp = word[0];
  for (uint8_t i = 0; i < 4; i++) {
    word[i] = word[i + 1];
  }
  word[3] = temp;
}

void KEYEXPANSION(uint8_t w[], const uint8_t key[]) {
  uint8_t tmp[6] = {0}, rc[6] = {0};
  memcpy(w, key, 4 * NK * sizeof(uint8_t));
  for (uint8_t i = 4 * NK; i < 4 * NB * (14 + 1); i += 4) {
    memcpy(tmp, w, 4 * sizeof(uint8_t));
    if (i / 4 % NK == 0) {
      ROTWORD(tmp);
      SUBWORD(tmp);
      rcon(rc, i / (4 * NK));
      for (uint8_t k = 0; k < 4; k++) {
        tmp[k] = tmp[k] ^ rc[k];
      }
    } else if (NK > 6 && i / 4 % NK == 4) {
      SUBWORD(tmp);
    }
    for (uint8_t j = 0; j < 4; ++j) {
      w[i + j] = w[i + j - 4 * NK] ^ tmp[j];
    }
  }
}

//
// Encrypt a block of data
static void encrypt_block(uint8_t *out, const uint8_t *in, const uint8_t *rk) {
  state_t *state = malloc(sizeof(state_t));
  statefromarr(state, in);
  ADDROUNDKEY(state, rk);
  for (uint32_t round = 1; round <= NR - 1; round++) {
    SUBBYTES(state);
    SHIFTROWS(state);
    MIXCOLUMNS(state);
    ADDROUNDKEY(state, rk + round * 4 * NB);
  }
  SUBBYTES(state);
  SHIFTROWS(state);
  ADDROUNDKEY(state, rk + NR * 4 * NB);
  arrfromstate(out, state);
  free(state);
}

//
// Decrypt a block of data
static void decrypt_block(uint8_t *out, const uint8_t *in, const uint8_t *rk) {
  state_t *state = malloc(sizeof(state_t));
  statefromarr(state, in);
  ADDROUNDKEY(state, rk + NR * 4 * NB);
  for (uint32_t round = NR - 1; round >= 1; round--) {
    INVSUBBYTES(state);
    INVSHIFTROWS(state);
    ADDROUNDKEY(state, rk + round * 4 * NB);
    INVMIXCOLUMNS(state);
  }
  INVSUBBYTES(state);
  INVSHIFTROWS(state);
  ADDROUNDKEY(state, rk);
  arrfromstate(out, state);
  free(state);
}

void ciph_encryptcbc(uint8_t *out, const uint8_t *in, const uint8_t *key, const uint8_t *iv) {
  uint8_t block[NB * NR] = {0}, roundkeys[4 * NB * (NR + 1)] = {0};
  KEYEXPANSION(roundkeys, key);
  memcpy(block, iv, BBL);
  for (uint32_t i = 0; i < BBL; i += BBL) {
    xorarr(block, block, (in + i));
    encrypt_block((out + i), block, roundkeys);
    memcpy(block, (out + i), BBL);
  }
}

void ciph_decryptcbc(uint8_t *out, const uint8_t *in, const uint8_t *key, const uint8_t *iv) {
  uint8_t block[NB * NR] = {0}, roundkeys[4 * NB * (NR + 1)] = {0};
  KEYEXPANSION(roundkeys, key);
  memcpy(block, iv, BBL);
  for (uint32_t i = 0; i < BBL; i += BBL) {
    decrypt_block((out + i), (in + i), roundkeys);
    xorarr((out + i), block, (out + i));
    memcpy(block, in + i, BBL);
  }
}
/*
void ciph_cryptcfb(uint8_t *out, const uint8_t *in, const uint8_t *key, const uint8_t *iv, bool dec) {
  uint8_t block[NB * NR] = {0}, encryptedblock[NB * NR] = {0}, roundkeys[4 * NB * (NR + 1)] = {0};
  KEYEXPANSION(roundkeys, key);
  memcpy(block, iv, BBL);
  for (uint32_t i = 0; i < BBL; i += BBL) {
    encrypt_block(encryptedblock, block, roundkeys);
    xorarr((out + i), (in + i), encryptedblock);
    if (dec) memcpy(block, in + i, BBL);
    else memcpy(block, (out + i), BBL);
  }
}

// AES256(in, key) = CIPHER(in, KEYEXPANSION(key))
// 128, 192, 256 (Nk = 4, 6, 8: Nr = 10, 12, 14), assume 256: Nk = 8, Nr = 14
void CIPHER(state_t state, uint8_t **in, uint8_t *w) {
  uint8_t *wtmp = NULL, Nr = 14;
  memcpy(state.state, &in, 4 * 4 * sizeof(uint8_t));
  memcpy(wtmp, w, 4 * sizeof(uint8_t));
  ADDROUNDKEY(state, wtmp);
  for (uint8_t round = 1; round < Nr - 1; round++) {
    SUBBYTES(state);
    SHIFTROWS(state);
    MIXCOLUMNS(state);
    memcpy(wtmp, w + (4 * round), 4 * sizeof(uint8_t));
    ADDROUNDKEY(state, wtmp);
  }
  SUBBYTES(state);
  SHIFTROWS(state);
  memcpy(wtmp, w + (4 * Nr), 4 * sizeof(uint8_t));
  ADDROUNDKEY(state, wtmp);
}

void INVCIPHER(state_t *state, uint8_t *in, uint8_t *w) {
  uint8_t *wtmp = malloc(16);
  memcpy(state->state, in, 4 * NB * sizeof(uint8_t));
  memcpy(wtmp, w + (4 * NK), 4 * NB * sizeof(uint8_t));
  ADDROUNDKEY(state, wtmp);
  for (uint8_t round = NK - 1; round >= 1; round--) {
    INVSHIFTROWS(state);
    INVSUBBYTES(state);
    memcpy(wtmp, w + (4 * round), 4 * NB * sizeof(uint8_t));
    ADDROUNDKEY(state, wtmp);
    INVMIXCOLUMNS(state);
  }
  INVSHIFTROWS(state);
  INVSUBBYTES(state);
  memcpy(wtmp, w, 4 * NB * sizeof(uint8_t));
  ADDROUNDKEY(state, wtmp);
  free(wtmp);
}

void EQINVCIPHER(state_t *state, uint8_t *in, uint8_t *dw) {
  uint8_t *wtmp = malloc(16);
  memcpy(state->state, in, 4 * NB * sizeof(uint8_t));
  memcpy(wtmp, dw + (4 * NK), 4 * NB * sizeof(uint8_t));
  ADDROUNDKEY(state, wtmp);
  for (uint8_t round = NK - 1; round >= 1; round--) {
    INVSUBBYTES(state);
    INVSHIFTROWS(state);
    INVMIXCOLUMNS(state);
    memcpy(wtmp, dw + (4 * round), 4 * NB * sizeof(uint8_t));
    ADDROUNDKEY(state, wtmp);
    INVMIXCOLUMNS(state);
  }
  INVSUBBYTES(state);
  INVSHIFTROWS(state);
  memcpy(wtmp, dw, 4 * NB * sizeof(uint8_t));
  ADDROUNDKEY(state, wtmp);
  free(wtmp);
}

// EIC = EQINVCIPHER
void KEYEXPANSIONEIC(uint8_t *dw, uint8_t *key) {
  int i = 0, Nr = 4, Nk = 8;
  uint8_t *w = malloc(32);
  while (i <= Nk - 1) {
    memcpy(&w[i], key + (4 * i), 4);
    memcpy(&dw[i], &w[i], 4);
    i += 1;
  }
  while (i <= 4 * Nr + 3) {
    uint32_t temp = w[i - 1];
    if (i % Nk == 0) {
      ROTWORD(temp);
      SUBWORD(temp);
      temp = temp ^ rcon[i / Nk];
    } else if (Nk > 6 && i % Nk == 4) {
      SUBWORD(temp);
    }
    w[i] = w[i - Nk] ^ temp;
    dw[i] = w[i];
    i += 1;
  }
    uint8_t *tmp = malloc(32*sizeof(uint8_t));
    state_t *state = (state_t*) malloc(sizeof(state_t)*2);
  for (uint8_t round = 1; round <= Nr - 1; round++) {
    i = 4 * round;
    memcpy(tmp, dw + i, 4 * sizeof(uint8_t));
    memcpy(state->state[round], tmp, 4 * sizeof(uint8_t));
    INVMIXCOLUMNS(state);
    memcpy(tmp, state->state[round], 4 * sizeof(uint8_t));
    memcpy(dw + i, tmp, 4 * sizeof(uint8_t));
  }
}
*/


// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// 6.3 multiply
void mul(uint8_t *Z, uint8_t *BITX, uint8_t *BITY) {
  uint8_t V[128], R[128] = {1, 1, 1, 0, 0, 0, 0, 1}, BITV[128]; // R = 11100001 || 0 ^ 120
  u64 RDEC = 0;
  memcpy(V, BITY, 128);
  RDEC = BIN2LONG(R);
  for (int i = 0; i < 128; i++) {
    if (BITX[i] == 0) Z[i+1] = Z[i];
    if (BITX[i] == 1) Z[i+1] = Z[i] ^ V[i];
    LONG2BIN(BITV, V[i]); // Take LSB1 of V[i] below
    if (BITV[127] == 0) V[i+1] = V[i] >> 1;
    if (BITV[127] == 1) V[i+1] = (V[i] >> 1) ^ RDEC;
  }
}

// 6.4 for GHASH
// In effect, the GHASH function calculates: (X1*Hm) ^ (X2*Hm-1) ^ ... ^ (Xm-1*H2) ^ (Xm*H)
void ghash(uint8_t **Y, uint8_t **X, uint8_t **H, int m) { // X must be 128*m length
  uint8_t RET[128][128]; // TODO: we assume m=128
  for (int i = 1; i < m; i++) {
    mul(RET[i], X[i], H[m-(i-1)]); // LONG2BIN(X[i])? LONG2BIN(H[m-(i-i)])?
  }
  for (int i = 1; i < m; i++) {
    xorarr(Y[i], RET[i-1], RET[i]);
  }
}

uint32_t little_endian_uint32(uint8_t x) {
  x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0xFF00FF);
  return (x << 16) | (x >> 16);
}

u64 little_endian_uint64(u64 x) {
  x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
  x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
  return (x << 32) | (x >> 32);
}

uint32_t read_little_endian_uint32(uint8_t *x) {
  uint32_t result;
  memcpy(&result, x, sizeof(result));
  return result;
}

// // https://www.rfc-editor.org/rfc/rfc8452.html
// return message_authentication_key, message_encryption_key
void derive_keys(uint8_t *key_generating_key, uint8_t *nonce, uint8_t **message_authentication_key, uint8_t **message_encryption_key) {
  uint8_t *tmp1 = NULL, *tmp2 = NULL, AESSIZE = 8;
  memcpy(tmp1, AES(key_generating_key, little_endian_uint32(0) + nonce), 8 * AESSIZE);
  memcpy(tmp2, AES(key_generating_key, little_endian_uint32(1) + nonce), 8 * AESSIZE);
  memcpy(message_authentication_key + (0 * AESSIZE), tmp1, 8 * AESSIZE);
  memcpy(message_authentication_key + (8 * AESSIZE), tmp2, 8 * AESSIZE);

  memcpy(tmp1, AES(key_generating_key, little_endian_uint32(2) + nonce), 8 * AESSIZE);
  memcpy(tmp2, AES(key_generating_key, little_endian_uint32(3) + nonce), 8 * AESSIZE);
  memcpy(message_encryption_key + (0 * AESSIZE), tmp1, 8 * AESSIZE);
  memcpy(message_encryption_key + (8 * AESSIZE), tmp2, 8 * AESSIZE);

  // always assume keylength == 32, if not, check length of key_generating_key == 32
  memcpy(tmp1, AES(key_generating_key, little_endian_uint32(4) + nonce), 8 * AESSIZE);
  memcpy(tmp2, AES(key_generating_key, little_endian_uint32(5) + nonce), 8 * AESSIZE);
  memcpy(message_encryption_key + (16 * AESSIZE), tmp1, 8 * AESSIZE);
  memcpy(message_encryption_key + (24 * AESSIZE), tmp2, 8 * AESSIZE);
}

uint8_t *AES_CTR(uint8_t *key, uint8_t *initial_counter_block, uint8_t *in, u64 inlen) {
  uint8_t todo, *block = malloc(32);
  memcpy(block, initial_counter_block, 32);
  uint8_t *output = NULL;
  while (inlen > 0) {
    uint8_t *keystream_block = AES(key, block);
    block[0] = read_little_endian_uint32(&block[0]);
    block[1] = read_little_endian_uint32(&block[1]);
    block[2] = read_little_endian_uint32(&block[2]);
    block[3] = read_little_endian_uint32(&block[3]);

    block[0] = little_endian_uint32(*(&block[0]+1));
    block[1] = little_endian_uint32(*(&block[1]+1));
    block[2] = little_endian_uint32(*(&block[2]+1));
    block[3] = little_endian_uint32(*(&block[3]+1));

    u64 keystream_blocklen = 16; // TODO: fix correct length
    if (inlen < keystream_blocklen) todo = inlen;
    else todo = keystream_blocklen;
    for (int j = 0; j < todo; j++) {
      output = output + (keystream_block[j] ^ in[j]);
    }
    memcpy(in, &in, todo);
  }
  free(block);
  return output;
}

uint8_t *encrypt(uint8_t *key_generating_key, uint8_t *nonce, uint8_t *plaintext, u64 plaintextlen, uint8_t *additional_data, u64 additional_datalen) {
  if (plaintextlen > 68719476736 || additional_datalen > 68719476736) { // 2 ^ 36 == 68719476736
    printf("Input text / data to long, exiting\n");
    exit(0);
  }
  uint8_t **message_authentication_key = NULL, **message_encryption_key = NULL;
  derive_keys(key_generating_key, nonce, message_encryption_key, message_authentication_key);
  //u64 length_block = little_endian_uint64(additional_datalen * 8) + little_endian_uint64(plaintextlen * 8);
  //uint8_t *padded_plaintext = right_pad_to_multiple_of_16_bytes(plaintext, plaintextlen);
  //uint8_t *padded_ad = right_pad_to_multiple_of_16_bytes(additional_data, additional_datalen);
  u64 *S_s = POLYVAL(message_authentication_key, right_pad_to_multiple_of_16_bytes(additional_data, additional_datalen) + right_pad_to_multiple_of_16_bytes(plaintext, plaintextlen) + (little_endian_uint64(additional_datalen * 8) + little_endian_uint64(plaintextlen * 8)));//padded_ad + padded_plaintext + length_block);
  for (int i = 0; i < 12; i++) {
    S_s[i] ^= nonce[i];
  }
  S_s[15] &= 0x7f;
  uint8_t *tag = NULL, *counter_block = NULL;
  memcpy(tag, AES(message_encryption_key, S_s), 16); // TODO: fix correct length
  counter_block[15] |= 0x80;
  uint8_t *ret = NULL;
  memcpy(ret, AES_CTR(*message_encryption_key, counter_block, plaintext, plaintextlen), 32); // TODO: fix correct length
  memcpy(ret + 32, tag, 16); // TODO: fix correct length
  return ret;
}

uint8_t *decrypt(uint8_t *key_generating_key,uint8_t *nonce, uint8_t *ciphertext, u64 ciphertextlen, uint8_t *additional_data, u64 additional_datalen) {
  if (ciphertextlen < 16 || ciphertextlen > (68719476736 + 16) || additional_datalen > 68719476736) { // 2 ^ 36 == 68719476736
    printf("Cipher text / data to long, exiting\n");
    exit(0);
  }
  uint8_t **message_authentication_key = NULL, **message_encryption_key = NULL;
  derive_keys(key_generating_key, nonce, message_encryption_key, message_authentication_key);
  uint8_t *tag = NULL, *counter_block = NULL, *ct = NULL;
  memcpy(tag, ciphertext, ciphertextlen - 16);
  memcpy(counter_block, tag, ciphertextlen - 16);
  counter_block[15] |= 0x80;
  memcpy(ct, ciphertext, ciphertextlen - 16); // take end of ciphertext, from ciphertextlen - 16
  uint8_t *plaintext = AES_CTR(*message_encryption_key, counter_block, ct, ciphertextlen - 16);
  //u64 plaintextlen = ciphertextlen; // TODO: incorrect
  //u64 length_block = little_endian_uint64(additional_datalen * 8) + little_endian_uint64(plaintextlen * 8);
  //uint8_t *padded_plaintext = right_pad_to_multiple_of_16_bytes(plaintext, plaintextlen);
  //uint8_t *padded_ad = right_pad_to_multiple_of_16_bytes(additional_data, additional_datalen);
  u64 *S_s = POLYVAL(message_authentication_key, right_pad_to_multiple_of_16_bytes(additional_data, additional_datalen) + right_pad_to_multiple_of_16_bytes(plaintext, ciphertextlen) + (little_endian_uint64(additional_datalen * 8) + little_endian_uint64(ciphertextlen * 8)));//padded_ad + padded_plaintext + length_block);
  for (int i = 0; i < 12; i++) {
    S_s[i] ^= nonce[i];
  }
  S_s[15] &= 0x7f;
  uint8_t *expected_tag = AES(message_encryption_key, S_s);
  u64 expected_taglen = 32; // TOOD: fix
  u64 xor_sum = 0;
  for (int i = 0; i < expected_taglen; i++) {
    xor_sum |= expected_tag[i] ^ tag[i];
  }
  if (xor_sum != 0) {
    exit(0);
  }
  return plaintext;
}

//
// hmm where did i get these from? what paper?!?!
void multiply(u64 R[]) {
  R[25] = 0x06;
  for (int i = 7; i >= 0; --i) {
    for (int j = 3; j >= 0; --j) {
      if (R[16+j] == 1) {
        R[0] = R[0] + R[25];
        for (int k = 0; k < 4; ++k) {
          R[8+j+k] = R[8+j+k] ^ R[20+k];
        }
      } else {
        for (int k = 0; k < 4; ++k) {
          R[24] = R[24] ^ R[20+k];
        }
      }
    }
    for (int k = 15; k > 6; k--) {
      R[k] = R[k] << 1;
    }
  }
}

void modreduce(u64 K[]) {
  u64 A = (K[31] & BIN(1)) << 6, B = (K[31] & BIN(10)) << 5, C = (K[31] & BIN(1111111));
  K[16] = K[16] ^ ((A ^ B ^ C) << 1);
  K[8] = K[8] ^ K[24] ^ ((K[23] << 7) | K[24] >> 1) ^ ((K[23] << 6) | K[24] >> 2) ^ ((K[23] << 1) | K[24] >> 7);
  K[0] = K[0] ^ K[16] ^ (K[16] >> 2) ^ (K[16] >> 7);
  for (int i = 1; i < 8; ++i) {
    K[i+8] = K[i+8] ^ K[i+24] ^ ((K[i+23] << 7) | K[i+24] >> 1) ^ ((K[i+23] << 6) | K[i+24] >> 2) ^ ((K[i+23] << 1) | K[i+24] >> 7);
    K[i] = K[i] ^ K[i+16] ^ ((K[i+15] << 7) | K[i+16] >> 1) ^ ((K[i+15] << 6) | K[i+16] >> 2) ^ ((K[i+15] << 1) | K[i+16] >> 7);
  }
}

// translated from asm
void st(u64 Z) {
  u64 K0=0, K1=0, K2=0, K3=0, K4=0, K5=0, K6=0, K7=0; //
  u64 C4=0, C5=0, C6=0, C7=0; //

  // ROUND32 // 1
  u64 C0 = Z+0, C1 = Z+1, C2 = Z+2, C3 = Z+3; // 2-5
  C4 = C4 ^ C0; // 6
  C5 = C5 ^ C1; // 7
  C6 = C6 ^ C2; // 8
  C7 = C7 ^ C3; // 9

  C0 = K0; // 10
  C2 = K2; // 11
  C4 = K4; // 12
  C6 = K6; // 13

  // ROUND32 // 14
  C4 = Z + 12; // 15
  C5 = Z + 13; // 16
  C6 = Z + 14; // 17
  C7 = Z + 15; // 18

  C0 = C0 ^ K0; // 19
  C1 = C1 ^ K1; // 20
  C2 = C2 ^ K2; // 21
  C3 = C3 ^ K3; // 22

  C4 = C4 ^ C0; // 23
  C5 = C5 ^ C1; // 24
  C6 = C6 ^ C2; // 25
  C7 = C7 ^ C3; // 26

  C0 = C0 ^ K4; // 27
  C1 = C1 ^ K5; // 28
  C2 = C2 ^ K6; // 29
  C3 = C3 ^ K7; // 30

  // ROUND32 // 31
  K0 = K0 ^ C0; // 32
  K1 = K1 ^ C1; // 33
  K2 = K2 ^ C2; // 34
  K3 = K3 ^ C3; // 35

  K4 = K4 ^ C4; // 36
  K5 = K5 ^ C5; // 37
  K6 = K6 ^ C6; // 38
  K7 = K7 ^ C7; // 39

  C0 = Z + 4; // 40
  C1 = Z + 5; // 41
  C2 = Z + 6; // 42
  C3 = Z + 7; // 43
  C4 = Z + 8; // 44
  C5 = Z + 9; // 45
  C6 = Z + 10; // 46
  C7 = Z + 11; // 47
}

// good read:
//   https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
//   https://www.cse.wustl.edu/~jain/cse571-11/ftp/l_05aes.pdf
//   https://ie.u-ryukyu.ac.jp/~wada/design04/spec_e.html
//   https://blog.0x7d0.dev/education/how-aes-is-implemented/

// https://github.com/m3y54m/aes-in-c?tab=readme-ov-file#the-rijndael-key-schedule
// https://en.wikipedia.org/wiki/Rijndael_S-box
// https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/Galois%20Counter%20Mode%20with%20Secure%20Short%20Tags.pdf
// https://medium.com/codex/aes-how-the-most-advanced-encryption-actually-works-b6341c44edb9
// https://networkbuilders.intel.com/docs/networkbuilders/advanced-encryption-standard-galois-counter-mode-optimized-ghash-function-technology-guide-1693300747.pdf

// https://datatracker.ietf.org/doc/html/rfc8452#appendix-A

// https://blog.0x7d0.dev/education/how-aes-is-implemented/
// https://github.com/m3y54m/aes-in-c?tab=readme-ov-file#the-rijndael-key-schedule

// Code grabbed from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf and massaged
// mixedcolumns solve from https://github.com/p4-team/crypto-commons/blob/master/crypto_commons/symmetrical/aes.py#L243
