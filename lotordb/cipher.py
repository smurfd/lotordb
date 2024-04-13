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
        print(s[i][j])
        s[i][j] = self.vars.SBOX[s[i][j] // 16][s[i][j] % 16]

  def invsub_bytes(self, s):
    for i in range(4):
      for j in range(4):
        s[i][j] = self.vars.SBOX[s[i][j] // 16][s[i][j] % 16]
        # s[i][j] = self.vars.SBOXINV[s[i][j]]

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
    # print(len(s), len(s[0]), len(s[0][0]))
    for i in range(4):
      for j in range(4):
        s[i][j] ^= w[i + 4 * j]  # w[i][j]

  def rcon(self, w, a):
    c = 1
    for i in range(a - 1):
      c = (c << 1) ^ (((c >> 7) & 1) * 0x1B)
    w[0] = c
    w[1] = w[2] = w[3] = 0

  def xor(self, ret, x, y, ln):
    print(ln)
    print(len(ret), len(x), len(y))
    for i in range(ln):
      ret[i] = x[i] ^ y[i]

  def rot_word(self, w):
    temp = w[0]
    for i in range(4):
      w[i] = w[i + 1]
      if i == 3:
        w[3] = temp

  def sub_word(self, w):
    for i in range(4):
      w[i] = self.vars.SBOX[w[i] // 16][w[i] % 16]

  def state_from_arr(self, s, ina):
    s = [list(ina[i : i + 4]) for i in range(0, len(ina), 4)]
    if s:
      pass

  def arr_from_state(self, s, ina):
    s = bytes(sum(ina, []))
    if s:
      pass

  def key_expansion(self, w, key):
    rc = [0] * 4
    for i in range(32, 240, 4):
      if (i // 4 % 8) == 0:
        self.rot_word(w)
        self.sub_word(w)
        self.rcon(rc, i // 32)
        for k in range(4):
          w[k] = w[k] ^ rc[k]
      elif i // 4 % 8 == 4:
        self.sub_word(w)
      for j in range(4):
        w[i + j] = w[i + j - 32] ^ w[j]

  def encrypt_block(self, out, ina, rk):
    s = [[0] * 4] * 4  # [[0,0,0,0],[0,0,0,0]]
    print(s, s[1][1])
    self.state_from_arr(s, ina)
    self.add_roundkey(s, rk)
    for i in range(14):
      self.sub_bytes(s)
      self.shift_rows(s)
      self.mix_columns(s)
      self.add_roundkey(s, rk)  # + i * 16)
    self.sub_bytes(s)
    self.shift_rows(s)
    self.add_roundkey(s, rk)  # + 14 * 16)
    self.arr_from_state(out, s)

  def decrypt_block(self, out, ina, rk):
    s = [[0] * 4] * 4  # [[0,0,0,0],[0,0,0,0]]
    self.state_from_arr(s, ina)
    self.add_roundkey(s, rk)  # + 224)
    for i in range(14, 0, -1):
      self.invsub_bytes(s)
      self.invshift_rows(s)
      self.add_roundkey(s, rk)  # + i * 16)
      self.invmix_columns(s)
    self.invsub_bytes(s)
    self.invshift_rows(s)
    self.add_roundkey(s, rk)
    self.arr_from_state(out, s)

  # [4 * NB * (NR + 1)] 4 * 4 * (14+1)
  def ciph_crypt(self, out, ina, key, iv, cbc, dec):
    b, eb, rk = [0] * 56, [0] * 56, [0] * 240
    self.key_expansion(rk, key)
    b = list(iv)
    if cbc:
      for i in range(0, 16, 16):
        if dec:
          self.decrypt_block(out, ina, rk)  # out[:i], ina[:i], rk)
          self.xor(out, b, out, 16)  # out[:i], b, out[:i], 16)
          b = ina  # ina[:i]
        else:
          print(len(ina), len(ina[:i]))
          self.xor(b, b, ina, 16)  # ina[:i], 16)# ina[:i], 128)
          self.encrypt_block(out, b, rk)  # out[:i], b, rk)
          b = out[:i]
    else:
      for i in range(0, 16, 16):
        self.encrypt_block(eb, b, rk)
        self.xor(out, ina, eb, 16)  # out[:i], ina[:i], eb, 16)
        if dec:
          b = ina  # b = ina[:i]
        else:
          b = out
          # b = out[:i]


if __name__ == '__main__':
  print('Cipher')
  c = Cipher()
  plain = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
  iv = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
  key = [
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1A,
    0x1B,
    0x1C,
    0x1D,
    0x1E,
    0x1F,
  ]
  ina, out = [0] * 16, [0] * 16

  c.ciph_crypt(out, plain, key, iv, True, False)
  c.ciph_crypt(ina, out, key, iv, True, True)
  print(ina)
  print(plain)

"""
// NK=8, NR=14, NK4=8*4
//



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
