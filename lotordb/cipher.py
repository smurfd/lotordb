#!/usr/bin/env python3
from hmac import new as new_hmac, compare_digest
from lotordb.vars import Vars, DbIndex, DbData
from typing import Union, List, Tuple, Any
from hashlib import pbkdf2_hmac
import threading, secrets, gzip


# TODO: fix type: ignore
# From https://raw.githubusercontent.com/smurfd/lightssl/master/src/lightciphers.c
class Cipher(threading.Thread):
  def __init__(self, key: List = [i for i in range(0x20)], iv: List = [0xFF for _ in range(16)]) -> None:
    self.vars = Vars()
    self.key = key
    self.iv = iv

  def shift_row(self, s, i) -> List:
    return s[i][1:] + s[i][:1]

  def invshift_row(self, s, i) -> List:
    return [s[i][-1]] + s[i][:-1]

  def shift_rows(self, s) -> List:
    s[1], s[2], s[3] = self.shift_row(s, 1), self.shift_row(s, 2), self.shift_row(s, 3)
    return s

  def invshift_rows(self, s) -> List:
    s[1], s[2], s[3] = self.invshift_row(s, 1), self.invshift_row(s, 2), self.invshift_row(s, 3)
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
    c: int = 1
    (c := self.xt(c) for _ in range(a - 1))
    return [c, 0, 0, 0]

  def xor(self, x, y, ln) -> List:
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

  def len_salt_hash(self, ln) -> int:
    if ln % 16:  # handle padded data
      ln += ln % 16
    return ln + self.vars.SALT + self.vars.HMAC + 2  # the 2 is for padding byte and string

  def key_expansion_and_iv(self, key) -> Tuple:
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
    return w, self.iv

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
    s = False if not isinstance(ina, str) else True
    key = bytes(key) if isinstance(key, (bytes, list)) else key.encode('utf-8')
    ina = bytes(ina) if isinstance(ina, (bytes, list, bytearray)) else ina.encode('utf-8')
    salt = secrets.token_bytes(self.vars.SALT)
    key, hmac_key, _ = self.get_key_hmac_iv(key, salt, 100000)
    out = bytes(out)
    hmac = new_hmac(hmac_key, salt + out, 'sha256').digest()
    assert len(hmac) == self.vars.HMAC
    return hmac + salt + out + int(pad).to_bytes(1, 'big') + int(s).to_bytes(1, 'big')

  def get_decrypt(self, key, ina) -> Tuple:
    key = bytes(key) if isinstance(key, (bytes, list)) else key.encode('utf-8')
    s, p, ina = ina[len(ina) - 1], ina[len(ina) - 2 : len(ina) - 1][0], ina[: len(ina) - 2]  # handle padded byte and string byte
    hmac, ina = ina[: self.vars.HMAC], ina[self.vars.HMAC : len(ina)]
    salt, ina = ina[: self.vars.SALT], ina[self.vars.SALT :]
    if type(key) != type(salt):
      salt = bytes(salt)
      if type(salt) != type(ina):
        ina = bytes(ina)
    key, hmac_key, _ = self.get_key_hmac_iv(key, salt, 100000)
    expected_hmac = new_hmac(hmac_key, salt + ina, 'sha256').digest()
    if type(hmac) != type(expected_hmac):
      hmac = bytes(hmac)
    assert compare_digest(hmac, expected_hmac), 'cipher incorrect'
    return ina, s, p

  def pad_data(self, ina) -> Tuple:
    pad: int = 0
    if len(ina) % 16:
      pad = 16 - (len(ina) % 16)
      ina = ina + bytes([0] * pad) if isinstance(ina, (bytes, bytearray)) else ina + ([0] * pad)
    elif isinstance(ina, str):
      ina = ina.encode('UTF-8')
    return pad, ina

  def get_iv_rk(self) -> Tuple:
    rk, out = [0] * 240, [0] * 16
    iv: Union[List[Any], bytes, str] = [0] * 56
    rk, iv = self.key_expansion_and_iv(self.key)
    return iv, rk, out

  # CBC
  def encrypt_cbc(self, ina: Union[List, bytes, str, Tuple]) -> Union[Tuple, bytes, List]:
    pad, ina = self.pad_data(ina)
    iv, rk, out = self.get_iv_rk()
    for i in range(0, len(ina), 16):
      out[i:] = self.encrypt_block(self.xor(iv, ina[i:], 16), rk)
      iv = out[i:]
    return self.get_encrypt(self.key, ina, out, pad)

  # CBC
  def decrypt_cbc(self, ina: Union[List, bytes, str, Tuple]) -> Union[bytes, List]:
    iv, rk, out = self.get_iv_rk()
    ina, s, p = self.get_decrypt(self.key, ina)
    for i in range(0, len(ina), 16):
      out[i:] = self.xor(iv, self.decrypt_block(ina[i:], rk), 16)
      iv = ina[i:]
    out = out[: len(out) - p if isinstance(p, int) else int.from_bytes(p, 'big')]
    return ''.join(map(str, (chr(i) for i in out))).encode('UTF-8') if s else out

  # CFB
  def encrypt_cfb(self, ina: Union[List, bytes, str, Tuple]) -> Union[Tuple, bytes, List]:
    pad, ina = self.pad_data(ina)
    iv, rk, out = self.get_iv_rk()
    for i in range(0, len(ina), 16):
      out[i:] = self.xor(ina[i:], self.encrypt_block(iv, rk), 16)
      iv = out[i:]
    return self.get_encrypt(self.key, ina, out, pad)

  # CFB
  def decrypt_cfb(self, ina: Union[List, bytes, str, Tuple]) -> Union[bytes, List]:
    iv, rk, out = self.get_iv_rk()
    ina, s, p = self.get_decrypt(self.key, ina)
    for i in range(0, len(ina), 16):
      out[i:] = self.xor(ina[i:], self.encrypt_block(iv, rk), 16)
      iv = ina[i:]
    out = out[: len(out) - p if isinstance(p, int) else int.from_bytes(p, 'big')]
    return ''.join(map(str, (chr(i) for i in out))).encode('UTF-8') if s else out

  def encrypt_index(self, p):
    iv, rk, out = self.get_iv_rk()
    pad, p = self.pad_data(p)
    for i in range(0, len(p), 16):
      out[i:] = self.encrypt_block(self.xor(iv, p[i:], 16), rk)
      iv = out[i:]
    return self.get_encrypt(self.key, p, out, pad)

  def decrypt_index(self, index_packed):
    iv, rk, out = self.get_iv_rk()
    ina, s, pp = self.get_decrypt(self.key, index_packed)
    for i in range(0, len(ina), 16):
      out[i:] = self.xor(iv, self.decrypt_block(ina[i:], rk), 16)
      iv = ina[i:]
    out = out[: len(out) - pp if isinstance(pp, int) else int.from_bytes(pp, 'big')]
    ret = ''.join(map(str, (chr(i) for i in out))).encode('UTF-8') if s else out
    return DbIndex(*(int.from_bytes(ret[i : i + 8]) for i in range(0, 64, 8)), ''.join(chr(y) for y in ret[64:]))

  def decrypt_data(self, data_packed):
    iv, rk, out = self.get_iv_rk()
    ina, s, pp = self.get_decrypt(self.key, data_packed)
    if s or pp:
      pass  # TODO: string or padded, needed now?
    for i in range(0, len(ina), 16):
      out[i:] = self.xor(iv, self.decrypt_block(ina[i:], rk), 16)
      iv = ina[i:]
    outdata = gzip.decompress(bytes([i for i in out[48 : len(out)]]))
    return DbData(*(int.from_bytes(out[i : i + 8]) for i in range(0, 48, 8)), outdata)

  def get_decrypted_data(self, d):
    ret: List = []
    u: List = [0, 48, 8]
    v: List = [48, 4096, 8]
    for i in range(len(d) // 4096):
      j = i * 4096
      ret += [DbData(*[int.from_bytes(d[j + k : j + k + 8]) for k in range(*u)], [int.from_bytes(d[j + k : j + k + 8]) for k in range(*v)])]
    return ret


"""
// AES
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
// https://www.rfc-editor.org/rfc/rfc3565
// https://www.rfc-editor.org/rfc/rfc3565
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
"""
