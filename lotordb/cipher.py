#!/usr/bin/env python3
from lotordb.vars import Vars
import threading

# From https://raw.githubusercontent.com/smurfd/lightssl/master/src/lightciphers.c


class Cipher(threading.Thread):
  def __init__(self):
    self.vars = Vars()

  def shift_rows(self, s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

  def invshift_rows(self, s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

  def sub_bytes(self, s):
    for i in range(4):
      for j in range(4):
        s[i][j] = self.vars.SBOX[s[i][j]]

  def invsub_bytes(self, s):
    for i in range(4):
      for j in range(4):
        s[i][j] = self.vars.SBOXINV[s[i][j]]

  def mix_columns(self, s):
    for i in range(4):
      for k in range(4):
        for j in range(4):
          if self.vars.MIX[i][k] == 1:
            s[i][j] ^= s[k][j]
          else:
            s[i][j] ^= self.vars.GF[self.vars.MIX[i][k]][s[k][j]]

  def invmix_columns(self, s):
    for i in range(4):
      for k in range(4):
        for j in range(4):
          s[i][j] ^= self.vars.GF[self.vars.MIXINV[i][k]][s[k][j]]

  def add_roundkey(self, s, w):
    for i in range(4):
      for j in range(4):
        s[i][j] ^= w[i][j]

  def rcon(self, w, a):
    c = 1
    for i in range(a - 1):
      c = (c << 1) ^ (((c >> 7) & 1) * 0x1B)
    w[0] = c
    w[1] = w[2] = w[3] = 0


if __name__ == '__main__':
  print('Cipher')
  c = Cipher()


"""
//
//
static void key_expansion(uint8_t w[], const uint8_t key[]) {
  uint8_t tmp[4], rc[4];

  memcpy(w, key, NK4 * sizeof(uint8_t));
  for (int i = NK4; i < 4 * NB * (NR + 1); i += 4) {
    memcpy(tmp, w, 4 * sizeof(uint8_t));
    if (i / 4 % NK == 0) {
      rot_word(tmp);
      sub_word(tmp);
      rcon(rc, i / (4 * NK));
      for (int k = 0; k < 4; k++)
        tmp[k] = tmp[k] ^ rc[k];
    } else if (NK > 6 && i / 4 % NK == 4)
      sub_word(tmp);
    for (int j = 0; j < 4; ++j)
      w[i + j] = w[i + j - 4 * NK] ^ tmp[j];
  }
}

//
// xor two arrays
static void xor(uint8_t *c, const uint8_t *a, const uint8_t *b, const uint32_t len) {
  for (uint32_t i = 0; i < len; i++)
    c[i] = a[i] ^ b[i];
}

//
// Encrypt a block of data
static void encrypt_block(uint8_t out[], const uint8_t in[], const uint8_t *rk) {
  uint8_t state[4][NB] = {{0}, {0}};

  state_from_arr(state, in);
  add_roundkey(state, rk);
  for (uint32_t round = 1; round <= NR - 1; round++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_roundkey(state, rk + round * 4 * NB);
  }
  sub_bytes(state);
  shift_rows(state);
  add_roundkey(state, rk + NR * 4 * NB);
  arr_from_state(out, state);
}

//
// Decrypt a block of data
static void decrypt_block(uint8_t out[], const uint8_t in[], const uint8_t *rk) {
  uint8_t state[4][NB] = {{0}, {0}};

  state_from_arr(state, in);
  add_roundkey(state, rk + NR * 4 * NB);
  for (uint32_t round = NR - 1; round >= 1; round--) {
    invsub_bytes(state);
    invshift_rows(state);
    add_roundkey(state, rk + round * 4 * NB);
    invmix_columns(state);
  }
  invsub_bytes(state);
  invshift_rows(state);
  add_roundkey(state, rk);
  arr_from_state(out, state);
}

//
// k = key, o = out, cbc = cbc(true) or cfb, dec = decrypt(true) or encrypt
// https://medium.com/asecuritysite-when-bob-met-alice/a-bluffers-guide-to-aes-modes-ecb-cbc-cfb-and-all-that-jazz-4180f1882e16
void ciph_crypt(uint8_t out[], const uint8_t in[], const uint8_t key[], const uint8_t *iv, const bool cbc, bool dec) {
  uint8_t block[NB * NR] = {0}, encryptedblock[NB * NR] = {0}, roundkeys[4 * NB * (NR + 1)] = {0};

  key_expansion(roundkeys, key);
  memcpy(block, iv, BBL);
  if (cbc) // CBC
    for (uint32_t i = 0; i < BBL; i += BBL) {
      if (dec) {
        decrypt_block((out + i), (in + i), roundkeys);
        xor((out + i), block, (out + i), BBL);
        memcpy(block, in + i, BBL);
      } else {
        xor(block, block, (in + i), BBL);
        encrypt_block((out + i), block, roundkeys);
        memcpy(block, (out + i), BBL);
      }
    }
  else // CFB
    for (uint32_t i = 0; i < BBL; i += BBL) {
      encrypt_block(encryptedblock, block, roundkeys);
      xor((out + i), (in + i), encryptedblock, BBL);
      if (dec) memcpy(block, in + i, BBL);
      else memcpy(block, (out + i), BBL);
    }
}


int main(void) {
  uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, out[BBL] = {0}, in[BBL];

  ciph_crypt(out, plain, key, iv, true, false);
  ciph_crypt(in, out, key, iv, true, true);
  assert(memcmp(plain, in, BBL * sizeof(uint8_t)) == 0);
  printf("OK\n");
}


// AES
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
// https://www.rfc-editor.org/rfc/rfc3565
// https://www.rfc-editor.org/rfc/rfc3565
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

// Cipher Key = 60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81
// 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4
// Nk = 8
// w0 = 603deb10 w1 = 15ca71be w2 = 2b73aef0 w3 = 857d7781
// w4 = 1f352c07 w5 = 3b6108d7 w6 = 2d9810a3 w7 = 0914dff4
// C.3 AES-256 (Nk=8, Nr=14)
// PLAINTEXT: 00112233445566778899aabbccddeeff
// KEY: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
"""
