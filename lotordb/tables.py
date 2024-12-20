#!/usr/bin/env python3
import struct, gzip, threading, mmap, socket, secrets, io, os
from typing import List, Union, BinaryIO, IO
from lotordb.vars import DbIndex, DbData, Vars
from lotordb.cipher import Cipher


# TODO: where are we in index/data files
# TODO: figure out encrypted data length dynamicly?


# Sending byte array: time 0.4790!!! (python 3.11.7)
# gzip command: time 1.539226
class Tables(threading.Thread):  # Table store
  def __init__(self, fn='') -> None:
    self.fi: Union[None, BinaryIO, IO] = None
    self.fd: Union[None, BinaryIO, IO] = None
    self.fimm: Union[None, BinaryIO] = None
    self.fdmm: Union[None, BinaryIO] = None
    self.fn = (fn + '.dbindex', fn + '.dbdata')
    self.size: int = 4048
    self.index: Union[DbIndex, None] = None
    self.data: Union[DbData, None] = None
    self.cip = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
    self.ssl_sock: Union[socket.socket, None] = None
    if fn:
      self.open_index_file(self.fn[0], 'ab+')
      self.open_data_file(self.fn[1], 'ab+')
    else:
      self.fi = io.BufferedRandom  # type: ignore
      self.fd = io.BufferedRandom  # type: ignore

  def __exit__(self) -> None:
    self.close_file()
    self.join()

  def set_sock(self, sslsock):
    self.ssl_sock = sslsock
    return self

  def set_index_data(self, index: DbIndex, data: DbData):
    self.index = index
    self.data = data

  def close_file(self) -> None:
    self.fi.close() if self.fi and not self.fi.closed else None
    self.fd.close() if self.fd and not self.fd.closed else None

  def open_index_file(self, filename: str, rwd: str) -> None:
    self.fi = open(filename, rwd)

  def open_data_file(self, filename: str, rwd: str) -> None:
    self.fd = open(filename, rwd)

  def read_index(self):
    self.open_index_file(self.fn[0], 'rb+')
    self.fimm = mmap.mmap(self.fi.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return self.fimm.read() if self.fimm else b''

  def read_data(self):
    self.open_data_file(self.fn[1], 'rb+')
    self.fdmm = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return self.fdmm.read() if self.fimm else b''

  def write_index(self, index):
    self.open_index_file(self.fn[0], 'ab+') if self.fi.closed else None
    self.fi.write(index), len(index) if self.fi else b''

  def write_data(self, data):
    self.open_data_file(self.fn[1], 'ab+') if self.fd.closed else None
    self.fd.write(data) if self.fd else b''

  def index_to_bytearray_encrypt(self, index):
    b: List = []
    var: List = [index.index, index.dbindex, index.database, index.table, index.row, index.col, index.segments, index.seek]
    packed: List[Union[bytes, None]] = [None] * 8
    packed[:7] = [struct.pack('>Q', c) for c in var]
    packed[8] = struct.pack('>255s', bytes(index.file.ljust(255, ' '), 'UTF-8'))
    [b.extend(i) for i in packed]
    return self.encrypt(bytes(b))

  def data_to_bytearray_encrypt(self, data, index):
    b: List = []
    if isinstance(data, DbData) and data and data.data:
      pvr: List = [struct.pack('>Q', c) for c in [data.index, data.database, data.table, data.relative, data.row, data.col]]
      gzd: List = gzip.compress(struct.pack('>%dQ' % len(data.data), *data.data), compresslevel=3)
      gzl: int = len(gzd)
      gzlsize: int = gzl // self.size
      if isinstance(index.seek, bytes) and self.fd:
        index.seek = struct.pack('>Q', self.fd.tell()) if not struct.unpack('>Q', index.seek) else 0
        self.fd.seek(struct.unpack('>Q', index.seek)[0], 0)
      # Calculate diff between length of gz data, if not divisable with self.size, add 1 to zlen
      zlen: int = (gzlsize) if not (gzl - ((gzlsize) * self.size) > 0) else (gzlsize) + 1
      [b.extend(pvr[i]) for i in range(6)]
      [b.extend(gzd[i * self.size : (i + 1) * self.size]) for i in range(zlen)]
      return self.encrypt(bytes(b))

  def data_to_bytearray_encrypt_segment(self, data, index):
    b: List = []
    dad: DbData = DbData(1, 1, 1, 1, 1, 1, [])
    for i in range(0, len(data.data), Vars.SEGM):
      dad.data = data.data[i : i + Vars.SEGM]
      b.extend(self.data_to_bytearray_encrypt(dad, index))
    return bytes(b)

  def encrypt(self, p):
    iv, rk, out = self.cip.get_iv_rk()
    pad, p = self.cip.pad_data(p)
    for i in range(0, len(p), 16):
      out[i:] = self.cip.encrypt_block(self.cip.xor(iv, p[i:], 16), rk)
      iv = out[i:]
    return self.cip.get_encrypt(self.cip.key, p, out, pad)

  def recv_encrypted_index(self):
    size = self.ssl_sock.recv(8) if self.ssl_sock else ()
    return self.ssl_sock.recv(int.from_bytes(size)) if self.ssl_sock else ()

  def recv_encrypted_data(self):
    size = self.ssl_sock.recv(8) if self.ssl_sock else ()
    return self.ssl_sock.recv(int.from_bytes(size)) if self.ssl_sock else ()

  def send(self, ssl_sock, enc_i, enc_d):
    snd: bytes = bytearray()
    snd.extend(struct.pack('>Q', len(enc_i)))
    snd.extend(enc_i)
    snd.extend(struct.pack('>Q', len(enc_d)))
    snd.extend(enc_d)
    ssl_sock.send(snd)

  def decrypt_index(self, index_packed):
    iv, rk, out = self.cip.get_iv_rk()
    ina, s, pp = self.cip.get_decrypt(self.cip.key, index_packed)
    for i in range(0, len(ina), 16):
      out[i:] = self.cip.xor(iv, self.cip.decrypt_block(ina[i:], rk), 16)
      iv = ina[i:]
    out = out[: len(out) - pp if isinstance(pp, int) else int.from_bytes(pp, 'big')]
    ret = ''.join(map(str, (chr(i) for i in out))).encode('UTF-8') if s else out
    return DbIndex(*(int.from_bytes(ret[i : i + 8]) for i in range(0, 64, 8)), ''.join(chr(y) for y in ret[64:]))

  def decrypt_data(self, data_packed):
    iv, rk, out = self.cip.get_iv_rk()
    ina, s, pp = self.cip.get_decrypt(self.cip.key, data_packed)
    if s or pp:
      pass  # TODO: string or padded, needed now?
    for i in range(0, len(ina), 16):
      out[i:] = self.cip.xor(iv, self.cip.decrypt_block(ina[i:], rk), 16)
      iv = ina[i:]
    outdata = gzip.decompress(bytes([i for i in out[48 : len(out)]]))
    return DbData(*(int.from_bytes(out[i : i + 8]) for i in range(0, 48, 8)), outdata)

  def decrypt_bytearray_to_index(self, index):
    return self.decrypt_index(index)

  def decrypt_bytearray_to_data_segmented(self, data):
    dad: DbData = DbData(1, 1, 1, 1, 1, 1, [])
    dret: DbData = DbData(1, 1, 1, 1, 1, 1, [])
    for i in range(0, len(data), Vars.ZSIZ):
      dad = self.decrypt_data(data[i : i + Vars.ZSIZ])
      dret.data.extend(dad.data)
    return dret

  def decrypt_bytearray_to_data(self, data):
    return self.decrypt_data(data)

  def table_temp(self):
    with open('.lib/bin.b', 'ab') as f:
      for i in range(20):
        packedheader = 123456789  # len = 27
        name = 'John'.ljust(20)[:20]  # len = 20
        age = 32 + i  # len = 6
        height = 6.0  # len = 8
        data = packedheader.to_bytes(packedheader.bit_length() + 7 // 8) + name.encode() + age.to_bytes(age.bit_length() + 7 // 8) + bytes(struct.pack('d', height)) + b' ' * (512-(27+6+8+20))
        # TODO: encrypt data before write, data = 512 bytes
        f.write(data)
    with open('.lib/bin.b', 'rb') as f:
      len = 512  # 27+6+8+20
      fs = os.path.getsize('.lib/bin.b')
      chunk = fs // len
      print(f'size of the file: {fs} and number of chunks: {fs // len}')
      f.seek(len * 10, 0)
      data = f.read(len)
      # Decrypt data
      pkh, name, age, h = data[0:27], data[27:47], data[47:53], data[53:61]
      #print(f'11th entry: {name} {int.from_bytes(age, 'big')} {struct.unpack('d', h)[0]} {int.from_bytes(pkh, 'big')}')
      print('Searching for age 42: ', end='')
      f.seek(0, 0)
      for i in range(fs // len):
        data = f.read(len)
        pkh, name, age, h = data[0:27], data[27:47], data[47:53], data[53:61]
        if int.from_bytes(age, 'big') == 42:
          print('found')
          return 1
    return 0
