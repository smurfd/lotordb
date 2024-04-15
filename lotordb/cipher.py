#!/usr/bin/env python3
from lotordb.vars import Vars
import threading

# From https://raw.githubusercontent.com/smurfd/lightssl/master/src/lightciphers.c


class Cipher(threading.Thread):
  def __init__(self):
    self.vars = Vars()

  """
  def shift_rows(self, s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]
    return s

  def invshift_rows(self, s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
    return s
  """
  # def shift_row(self, s, i, n):
  #  tmp = [0]*4
  #  print("shift ----- ", s[i], s[n])
  #  tmp = s[i]
  #  s[i] = tmp
  #  return s

  def shift_row(self, s, i):
    # print("S1", s[i])
    # s[i] = s[i][1:]+s[i][:1]
    # print("S2", s[i])
    return s[i][1:] + s[i][:1]

  def invshift_row(self, s, i):
    # print("S3", s[i])
    # s[i] = s[i][:n]+s[i][n:]
    # s[i] = [s[i][-1]] + s[i][:-1]
    # print("S4", s[i])
    return [s[i][-1]] + s[i][:-1]

  def shift_rows(self, s):
    print('SSSSS', s[1], s)
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

  """
  def mix_columns(self, s):
    tmps = [[0] * 4] * 4
    tmps = s
    print("SSSSSSS1", tmps, s)
    for i in range(4):
      for k in range(4):
        for j in range(4):
          #print("mix", self.vars.MIX[i][k], s[k][j])
          if self.vars.MIX[i][k] == 1:
            tmps[i][j] ^= s[k][j]
          else:
            tmps[i][j] ^= self.vars.GF[self.vars.MIX[i][k]][s[k][j]]
            #print("mix1", self.vars.GF[self.vars.MIX[i][k]][s[k][j]])
    #s = tmps
    for i in range(4):
      for j in range(4):
        s[i][j] = tmps[i][j]
    #print("mix col", s, tmps, len(s))
    print("SSSSSSS1", tmps, s)
    return s

  def invmix_columns(self, s):
    tmps = [[0] * 4] * 4
    tmps = s
    print("AAAA", s)
    for i in range(4):
      for k in range(4):
        for j in range(4):
          tmps[i][j] ^= self.vars.GF[self.vars.MIXINV[i][k]][s[k][j]]
    for i in range(4):
      for j in range(4):
        s[i][j] = tmps[i][j]
    #print("invmix col", s, tmps)
    return s
  """

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
    print('MIX', t, u, a[0], a[1], a[2], a[3])
    a[0] ^= t ^ self.xt(a[0] ^ a[1])
    a[1] ^= t ^ self.xt(a[1] ^ a[2])
    a[2] ^= t ^ self.xt(a[2] ^ a[3])
    a[3] ^= t ^ self.xt(a[3] ^ u)
    return a

  # "borrowed" from https://github.com/boppreh/aes
  def mix_columns(self, s):
    print('SSSSS21', s)
    for i in range(4):
      self.mix_single_column(s[i])
    print('SSSSS22', s)
    return s

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
    self.mix_columns(s)
    return s

  def rcon(self, w, a):
    c = 1
    for i in range(a - 1):
      c = self.xt(c)  # c = (c << 1) ^ (((c >> 7) & 1) * 0x1B)
    w[0] = c
    w[1] = w[2] = w[3] = 0
    print('rcon', w)
    return w

  def xor(self, ret, x, y, ln):
    print(ln)
    print(len(ret), len(x), len(y))
    for i in range(ln):
      ret[i] = x[i] ^ y[i]
    return ret

  def rot_word(self, w):
    temp = w[0]
    for i in range(4):
      # w[i] = w[i + 1]
      if i == 3:
        w[3] = temp
        break
      w[i] = w[i + 1]
    return w

  def sub_word(self, w):
    for i in range(4):
      w[i] = self.vars.SBOX[w[i] // 16][w[i] % 16]
    return w

  def state_from_arr(self, s, ina):
    s = [list(ina[i : i + 4]) for i in range(0, len(ina), 4)]
    print('sa', s, '---', ina)
    return s
    # if s:
    #  pass
    # return s

  def arr_from_state(self, s, ina):
    print('ina', ina)
    # print("ina", set(ina))
    s = sum(ina, [])
    # s = list(set(ina))#bytes(sum(ina, []))
    print('sb', s, '---', ina)
    return s
    # if s:
    #  pass
    # return s

  def key_expansion(self, w, key):
    rc, tmp = [0] * 4, [0] * 4
    print('w', w, len(key))
    # w[32:] = key[32:]
    for i in range(32):
      w[i] = key[i]
    print(w, key)
    for i in range(32, 240, 4):
      for k in range(4):
        tmp[k] = w[k]
      if (i // 4) % 8 == 0:
        tmp = self.rot_word(tmp)
        # w = self.rot_word(w)
        # w = self.sub_word(w)
        tmp = self.sub_word(tmp)
        rc = self.rcon(rc, i // 32)
        for k in range(4):
          tmp[k] = tmp[k] ^ rc[k]
          # w[k] = w[k] ^ rc[k]
      elif (i // 4) % 8 == 4:
        tmp = self.sub_word(tmp)
        # w = self.sub_word(w)
      for j in range(4):
        w[i + j] = w[i + j - 32] ^ tmp[j]
        # w[i + j] = w[i + j - 32] ^ w[j]
    return w

  def encrypt_block(self, out, ina, rk):
    s = [[0] * 4] * 4  # [[0,0,0,0],[0,0,0,0]]
    print(s, s[1][1])
    print('rk', len(rk))
    s = self.state_from_arr(s, ina)
    s = self.add_roundkey(s, rk)
    for i in range(1, 13):
      s = self.sub_bytes(s)
      s = self.shift_rows(s)
      s = self.mix_columns(s)
      s = self.add_roundkey(s, rk[: i * 16])  # rk[i * 16:(i+1)*16])  # + i * 16)
    s = self.sub_bytes(s)
    s = self.shift_rows(s)
    print('enc s1', s)
    s = self.add_roundkey(s, rk[: 14 * 16])  # + 14 * 16)
    print('enc s2', s)
    out = self.arr_from_state(out, s)
    print('arrfromstate', out)
    return out
    # enc s1 [[77, 77, 77, 77], [77, 77, 77, 77], [77, 77, 77, 77], [77, 77, 77, 77]]
    # enc s2 [[111, 110, 110, 110], [111, 110, 110, 110], [111, 110, 110, 110], [111, 110, 110, 110]]
    # return out

  def decrypt_block(self, out, ina, rk):
    print('rk', len(rk))
    s = [[0] * 4] * 4  # [[0,0,0,0],[0,0,0,0]]
    s = self.state_from_arr(s, ina)
    s = self.add_roundkey(s, rk[:224])  # + 224)
    for i in range(13, 1, -1):
      s = self.invsub_bytes(s)
      s = self.invshift_rows(s)
      s = self.add_roundkey(s, rk[: i * 16])  # [i*16:(i+1)*16])#rk[i * 16:])  # + i * 16)
      s = self.invmix_columns(s)
    s = self.invsub_bytes(s)
    s = self.invshift_rows(s)
    s = self.add_roundkey(s, rk)
    out = self.arr_from_state(out, s)
    print('arry', out)
    return out
    # return out

  # [4 * NB * (NR + 1)] 4 * 4 * (14+1)
  def ciph_crypt(self, ina, key, iv, cbc, dec):
    b, eb, rk, out = [0] * 56, [0] * 56, [0] * 240, [0] * 16
    rk = self.key_expansion(rk, key)
    b = iv  # list(iv)

    print('iv', iv, len(iv))
    print('iv', b, len(b))
    print('rk', rk)
    if cbc:
      for i in range(0, 16, 16):
        if dec:
          out[i:] = self.decrypt_block(out[i:], ina[i:], rk)  # out[:i], ina[:i], rk)
          out[i:] = self.xor(out[i:], b, out[i:], 16)  # out[:i], b, out[:i], 16)
          b = ina[i:]
          # self.decrypt_block(out[i:], ina[i:], rk)  # out[:i], ina[:i], rk)
          # self.xor(out[i:], b[i:], out, 16)  # out[:i], b, out[:i], 16)
          # print("i", ina[i:], ina[:i])
          # b[0:i] = ina[i:]
        else:
          print('::', len(ina), len(ina[:i]), ina[:i], ina[i:])
          b = self.xor(b, b, ina[i:], 16)  # ina[:i], 16)# ina[:i], 128)
          out[i:] = self.encrypt_block(out[i:], b, rk)  # out[:i], b, rk)
          print('o', out)
          b = out[i:]
          # print(len(ina), len(ina[:i]))
          # self.xor(b, b, ina[i:], 16)  # ina[:i], 16)# ina[:i], 128)
          # self.encrypt_block(out[i:], b, rk)  # out[:i], b, rk)
          # print("o", out[i:], out[:i])
          # b[0:i] = out[i:]#[:i]
    else:
      for i in range(0, 16, 16):
        eb = self.encrypt_block(eb, b, rk)
        out = self.xor(out, ina, eb, 16)  # out[:i], ina[:i], eb, 16)
        if dec:
          b = ina[i:]  # [i:]  # b = ina[:i]
        else:
          b = out[i:]  # [i:]
          # b = out[:i]
    print('cip out', out)
    return out


"""
[155, 92, 20, 186, 185, 240, 96, 55, 232, 92, 27, 221, 228, 89, 193, 38]
[0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255]

[64, 247, 42, 101, 177, 124, 0, 234, 18, 1, 28, 173, 144, 210, 68, 130]
[0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255]
"""

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

  out = c.ciph_crypt(plain, key, iv, True, False)
  print('----------------')
  o = out
  print('ivvvv', iv)
  print('kkkk', key)
  iv = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
  ina = c.ciph_crypt(out, key, iv, True, True)
  print('----')
  print(o)
  print(out)
  print(ina)
  print(plain)
  # assert plain == ina

  """
  ina, out = [0] * 16, [0] * 16

  out = c.ciph_crypt(plain, key, iv, False, False)
  iv = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
  ina = c.ciph_crypt(out, key, iv, False, True)
  print(ina)
  print(plain)
  """

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
