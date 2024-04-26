#!/usr/bin/env python3
from hmac import new as new_hmac, compare_digest
from hashlib import pbkdf2_hmac
from typing import Union, List, Tuple, Any
from lotordb.vars import Vars
import threading, secrets


# From https://raw.githubusercontent.com/smurfd/lightssl/master/src/lightciphers.c
class Cipher(threading.Thread):
  def __init__(self) -> None:
    self.vars = Vars()

  def shift_row(self, s, i) -> List:
    return s[i][1:] + s[i][:1]

  def invshift_row(self, s, i) -> List:
    return [s[i][-1]] + s[i][:-1]

  def shift_rows(self, s) -> List:
    s[1] = self.shift_row(s, 1)
    s[2] = self.shift_row(s, 2)
    s[3] = self.shift_row(s, 3)
    return s

  def invshift_rows(self, s) -> List:
    s[1] = self.invshift_row(s, 1)
    s[2] = self.invshift_row(s, 2)
    s[3] = self.invshift_row(s, 3)
    return s

  def sub_bytes(self, s) -> List:
    for i in range(4):
      for j in range(4):
        st = s[i][j]
        s[i][j] = self.vars.SBOX[st // 16][st % 16]
    return s

  def invsub_bytes(self, s) -> List:
    for i in range(4):
      for j in range(4):
        st = s[i][j]
        s[i][j] = self.vars.SBOXINV[st // 16][st % 16]
    return s

  def add_roundkey(self, s, w) -> List:
    for j in range(4):
      for i in range(4):
        s[i][j] ^= w[i + 4 * j]
    return s

  def xt(self, a) -> int:
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

  # "borrowed" from https://github.com/boppreh/aes
  def mix_single_column(self, a) -> List:
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ self.xt(a[0] ^ a[1])
    a[1] ^= t ^ self.xt(a[1] ^ a[2])
    a[2] ^= t ^ self.xt(a[2] ^ a[3])
    a[3] ^= t ^ self.xt(a[3] ^ u)
    return a

  # "borrowed" from https://github.com/boppreh/aes
  def mix_columns(self, s) -> List:
    return [self.mix_single_column(s[i]) for i in range(4)]

  # "borrowed" from https://github.com/boppreh/aes
  def invmix_columns(self, s) -> List:
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
      u = self.xt(self.xt(s[i][0] ^ s[i][2]))
      v = self.xt(self.xt(s[i][1] ^ s[i][3]))
      s[i][0] ^= u
      s[i][1] ^= v
      s[i][2] ^= u
      s[i][3] ^= v
    return self.mix_columns(s)

  def rcon(self, w, a) -> List:
    c = 1
    (c := self.xt(c) for _ in range(a - 1))
    return [c, 0, 0, 0]

  def xor(self, x, y, ln) -> List:
    # print("xor", len(x), len(y), ln)
    return [x[i] ^ y[i] for i in range(ln)]

  def rot_word(self, w) -> List:
    temp = w[0]
    return [w[i + 1] for i in range(3)] + [temp]

  def sub_word(self, w) -> List:
    return [self.vars.SBOX[w[i] // 16][w[i] % 16] for i in range(4)]

  def state_from_arr(self, ina) -> List:
    return [list(ina[i : i + 4]) for i in range(0, len(ina), 4)]

  def arr_from_state(self, ina) -> List:
    return sum(ina, [])

  def key_expansion(self, key) -> List:
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

  def encrypt_block(self, ina, rk) -> List:
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

  def decrypt_block(self, ina, rk) -> List:
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

  def get_key_hmac_iv(self, password, salt, workload=100000) -> Tuple:
    stretched = pbkdf2_hmac('sha256', password, salt, workload, self.vars.KEY + self.vars.KEY + self.vars.HMAC)
    aes_key, stretched = stretched[: self.vars.KEY], stretched[self.vars.KEY :]
    hmac_key, stretched = stretched[: self.vars.HMAC], stretched[self.vars.HMAC :]
    return aes_key, hmac_key, stretched[: self.vars.KEY]

  def get_encrypt(self, key, ina, out, pad=0) -> bytes:
    s = False if not isinstance(ina, (str, bytes)) else True
    print('enc ina', ina)
    key = bytes(key) if isinstance(key, (bytes, list)) else key.encode('utf-8')
    ina = bytes(ina) if isinstance(ina, (bytes, list)) else ina.encode('utf-8')
    salt = secrets.token_bytes(self.vars.SALT)
    key, hmac_key, _ = self.get_key_hmac_iv(key, salt, 100000)
    out = bytes(out)
    hmac = new_hmac(hmac_key, salt + out, 'sha256').digest()
    assert len(hmac) == self.vars.HMAC
    print('padded:', pad, len(out), hmac)
    return hmac + salt + out + int(pad).to_bytes(1, 'big') + int(s).to_bytes(1, 'big')

  def get_decrypt(self, key, ina) -> Tuple:
    key = bytes(key) if isinstance(key, (bytes, list)) else key.encode('utf-8')
    s = ina[len(ina) - 1]
    p = ina[len(ina) - 2 : len(ina) - 1][0]
    print('INA', s, p, ina, len(ina))
    print('INNN', ina)
    ina = ina[: len(ina) - 2]
    print('INNN', ina)

    hmac, ina = ina[: self.vars.HMAC], ina[self.vars.HMAC : len(ina)]
    salt, ina = ina[: self.vars.SALT], ina[self.vars.SALT :]
    # ina=ina[:len(ina)-p-1]
    print('INA', hmac, salt)
    print('g_d', type(key), type(salt), type(ina))
    if type(key) != type(salt):
      salt = bytes(salt)
      if type(salt) != type(ina):
        ina = bytes(ina)
    # if not isinstance(salt, bytes):
    #  salt = bytes(salt)
    # if not isinstance(ina, bytes):
    #  ina = bytes(ina)
    key, hmac_key, _ = self.get_key_hmac_iv(key, salt, 100000)
    expected_hmac = new_hmac(hmac_key, salt + ina, 'sha256').digest()
    print('hmac', type(hmac), type(expected_hmac))
    if type(hmac) != type(expected_hmac):
      hmac = bytes(hmac)
    print('hmac', type(hmac), type(expected_hmac))
    print('hmac', hmac)
    print('e_hmac', expected_hmac)
    assert compare_digest(hmac, expected_hmac), 'cipher incorrect'
    return ina, s, p

  # CBC
  def encrypt_cbc(self, ina: Union[List, bytes, str, Tuple], key: Union[List, bytes], iv) -> Union[Tuple, bytes, List]:
    rk, out = [0] * 240, [0] * 16
    b: Union[List[Any], bytes, str] = [0] * 56
    pad: int = 0
    if len(ina) % 16:
      pad = 16 - (len(ina) % 16)
      print('padding', pad, len(ina))
      if isinstance(ina, list):
        ina = ina + ([0] * pad)
      elif isinstance(ina, bytes):
        ina = ina + bytes([0] * pad)
    if isinstance(ina, str):
      ina = ina.encode('UTF-8')
    rk = self.key_expansion(key)
    b = iv
    for i in range(0, len(ina), 16):
      b = self.xor(b, ina[i:], 16)
      out[i:] = self.encrypt_block(b, rk)
      b = out[i:]
    print('befiore get_encrypt')
    return self.get_encrypt(key, ina, out, pad)

  # CBC
  def decrypt_cbc(self, ina: Union[List, bytes, str, Tuple], key: Union[List, bytes], iv) -> Union[bytes, List]:
    rk, out = [0] * 240, [0] * 16
    b: Union[List[Any], bytes, str, Tuple] = [0] * 56
    rk = self.key_expansion(key)
    b = iv
    print('ina cbc', ina)
    ina, s, p = self.get_decrypt(key, ina)
    for i in range(0, len(ina), 16):
      out[i:] = self.decrypt_block(ina[i:], rk)
      out[i:] = self.xor(b, out[i:], 16)
      b = ina[i:]
    print(type(p))
    if isinstance(p, int):
      ln = p
    else:
      ln = int.from_bytes(p, 'big')
    # ln = int.from_bytes(p, "big") if isinstance(b, bytes) else p
    out = out[: len(out) - ln]  # int.from_bytes(p, "big")]
    # out = out[:len(out)-int.from_bytes(p, "big")]
    # print("dec", int.from_bytes(p, "big"), out)
    return ''.join(map(str, (chr(i) for i in out))).encode('UTF-8') if s else out

  # CFB
  def encrypt_cfb(self, ina: Union[List, bytes, str, Tuple], key: Union[List, bytes], iv) -> Union[Tuple, bytes, List]:
    eb, rk, out = [0] * 56, [0] * 240, [0] * 16
    b: Union[List[Any], bytes, str] = [0] * 56
    pad: int = 0
    if len(ina) % 16:
      pad = 16 - (len(ina) % 16)
      print('padding', pad, len(ina))
      if isinstance(ina, list):
        ina = ina + ([0] * pad)
      elif isinstance(ina, bytes):
        ina = ina + bytes([0] * pad)
    if isinstance(ina, str):
      ina = ina.encode('UTF-8')
    rk = self.key_expansion(key)
    b = iv
    for i in range(0, len(ina), 16):
      eb = self.encrypt_block(b, rk)
      out[i:] = self.xor(ina[i:], eb, 16)
      b = out[i:]
    return self.get_encrypt(key, ina, out, pad)

  # CFB
  def decrypt_cfb(self, ina: Union[List, bytes, str, Tuple], key: Union[List, bytes], iv) -> Union[bytes, List]:
    eb, rk, out = [0] * 56, [0] * 240, [0] * 16
    b: Union[List[Any], bytes, str, Tuple] = [0] * 56
    rk = self.key_expansion(key)
    b = iv
    print('ina cbc', ina)
    ina, s, p = self.get_decrypt(key, ina)
    for i in range(0, len(ina), 16):
      eb = self.encrypt_block(b, rk)
      out[i:] = self.xor(ina[i:], eb, 16)
      b = ina[i:]
    print(type(p))
    if isinstance(p, int):
      ln = p
    else:
      ln = int.from_bytes(p, 'big')
    # ln = int.from_bytes(p, "big") if isinstance(b, bytes) else p
    out = out[: len(out) - ln]  # int.from_bytes(p, "big")]
    # out = out[: len(out) - int.from_bytes(p, 'big')]
    # print('dec', int.from_bytes(p, 'big'), out)
    return ''.join(map(str, (chr(i) for i in out))).encode('UTF-8') if s else out


if __name__ == '__main__':
  print('Cipher')
  cipher = Cipher()
  plain = [i for i in range(ord('b'))]  # , ord('p'))]
  key = [i for i in range(0x20)]
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  # if len(plain) % 16:
  #  print("P", len(plain) % 16)
  #  plain = plain+([0]*(16-(len(plain) % 16)))
  #  print("p", plain, len(plain))
  out = cipher.encrypt_cbc(plain, key, [0xFF for _ in range(16)])  # type: ignore
  print('OUT', len(out))
  ina = cipher.decrypt_cbc(out, key, [0xFF for _ in range(16)])  # type: ignore
  print(ina)
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
