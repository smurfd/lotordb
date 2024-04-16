#!/usr/bin/env python3
from lotordb.vars import Vars
import threading

# From https://raw.githubusercontent.com/smurfd/lightssl/master/src/lightciphers.c


class Cipher(threading.Thread):
  def __init__(self):
    self.vars = Vars()

  def shift_row(self, s, i):
    return s[i][1:] + s[i][:1]

  def invshift_row(self, s, i):
    return [s[i][-1]] + s[i][:-1]

  def shift_rows(self, s):
    s[1] = self.shift_row(s, 1)
    s[2] = self.shift_row(s, 2)
    s[3] = self.shift_row(s, 3)
    return s

  def invshift_rows(self, s):
    s[1] = self.invshift_row(s, 1)
    s[2] = self.invshift_row(s, 2)
    s[3] = self.invshift_row(s, 3)
    return s

  def sub_bytes(self, s):
    for i in range(4):
      for j in range(4):
        st = s[i][j]
        s[i][j] = self.vars.SBOX[st // 16][st % 16]
    return s

  def invsub_bytes(self, s):
    for i in range(4):
      for j in range(4):
        st = s[i][j]
        s[i][j] = self.vars.SBOXINV[st // 16][st % 16]
    return s

  def add_roundkey(self, s, w):
    for j in range(4):
      for i in range(4):
        s[i][j] ^= w[i + 4 * j]
    return s

  def xt(self, a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

  # "borrowed" from https://github.com/boppreh/aes
  def mix_single_column(self, a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ self.xt(a[0] ^ a[1])
    a[1] ^= t ^ self.xt(a[1] ^ a[2])
    a[2] ^= t ^ self.xt(a[2] ^ a[3])
    a[3] ^= t ^ self.xt(a[3] ^ u)
    return a

  # "borrowed" from https://github.com/boppreh/aes
  def mix_columns(self, s):
    return [self.mix_single_column(s[i]) for i in range(4)]

  # "borrowed" from https://github.com/boppreh/aes
  def invmix_columns(self, s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
      u = self.xt(self.xt(s[i][0] ^ s[i][2]))
      v = self.xt(self.xt(s[i][1] ^ s[i][3]))
      s[i][0] ^= u
      s[i][1] ^= v
      s[i][2] ^= u
      s[i][3] ^= v
    return self.mix_columns(s)

  def rcon(self, w, a):
    c = 1
    for _ in range(a - 1):
      c = self.xt(c)
    return [c, 0, 0, 0]

  def xor(self, x, y, ln):
    return [x[i] ^ y[i] for i in range(ln)]

  def rot_word(self, w):
    temp = w[0]
    w[:3] = [w[i + 1] for i in range(3)]
    w[3] = temp
    return w

  def sub_word(self, w):
    return [self.vars.SBOX[w[i] // 16][w[i] % 16] for i in range(4)]

  def state_from_arr(self, ina):
    return [list(ina[i : i + 4]) for i in range(0, len(ina), 4)]

  def arr_from_state(self, ina):
    return sum(ina, [])

  def key_expansion(self, key):
    rc, tmp, w = [0] * 4, [0] * 4, [0] * 240
    w[:32] = key[:32]
    for i in range(32, 240, 4):
      tmp[:3] = w[:3]
      if (i // 4) % 8 == 0:
        tmp = self.rot_word(tmp)
        tmp = self.sub_word(tmp)
        rc = self.rcon(rc, i // 32)
        for k in range(4):
          tmp[k] ^= rc[k]
      elif (i // 4) % 8 == 4:
        tmp = self.sub_word(tmp)
      for j in range(4):
        w[i + j] = w[i + j - 32] ^ tmp[j]
    return w

  def encrypt_block(self, ina, rk):
    s = [[0] * 4] * 4
    s = self.state_from_arr(ina)
    s = self.add_roundkey(s, rk)
    for i in range(1, 13):
      s = self.sub_bytes(s)
      s = self.shift_rows(s)
      s = self.mix_columns(s)
      s = self.add_roundkey(s, rk[: i * 16])
    s = self.sub_bytes(s)
    s = self.shift_rows(s)
    s = self.add_roundkey(s, rk[: 14 * 16])
    return self.arr_from_state(s)

  def decrypt_block(self, ina, rk):
    s = [[0] * 4] * 4
    s = self.state_from_arr(ina)
    s = self.add_roundkey(s, rk[:224])
    for i in range(13, 1, -1):
      s = self.invsub_bytes(s)
      s = self.invshift_rows(s)
      s = self.add_roundkey(s, rk[: i * 16])
      s = self.invmix_columns(s)
    s = self.invsub_bytes(s)
    s = self.invshift_rows(s)
    s = self.add_roundkey(s, rk)
    return self.arr_from_state(s)

  def ciph_crypt(self, ina, key, iv, cbc, dec):
    b, eb, rk, out = [0] * 56, [0] * 56, [0] * 240, [0] * 16
    rk = self.key_expansion(key)
    b = iv
    if cbc:
      for i in range(0, len(ina), 16):
        if dec:
          out[i:] = self.decrypt_block(ina[i:], rk)
          out[i:] = self.xor(b, out[i:], 16)
          b = ina[i:]
        else:
          b = self.xor(b, ina[i:], 16)
          out[i:] = self.encrypt_block(b, rk)
          b = out[i:]
    else:
      for i in range(0, len(ina), 16):
        eb = self.encrypt_block(b, rk)
        out[i:] = self.xor(ina[i:], eb, 16)
        b = out[i:] if not dec else ina[i:]
    return out


if __name__ == '__main__':
  print('Cipher')
  c = Cipher()
  plain = [i for i in range(ord('a'), ord('q'))]
  key = [i for i in range(0x20)]
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = c.ciph_crypt(plain, key, [0xFF for _ in range(16)], True, False)
  ina = c.ciph_crypt(out, key, [0xFF for _ in range(16)], True, True)
  assert plain == ina
  out = c.ciph_crypt(plain, key, [0xFF for _ in range(16)], False, False)
  ina = c.ciph_crypt(out, key, [0xFF for _ in range(16)], False, True)
  assert plain == ina

"""

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
