#!/usr/bin/env python3
from typing import List, Union, BinaryIO, IO
import struct, gzip, threading, mmap, socket, secrets
from lotordb.vars import DbIndex, DbData
from lotordb.cipher import Cipher
import io


# Sending byte array: time 0.4790!!! (python 3.11.7)
# gzip command: time 1.539226
class Tables(threading.Thread):  # Table store
  def __init__(self, fn='') -> None:
    threading.Thread.__init__(self, group=None)
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
    self.start()

  def __exit__(self) -> None:
    self.close_file()
    self.join(timeout=0.1)

  def open_index_file(self, filename: str, rwd: str) -> None:
    self.fi = open(filename, rwd)

  def open_data_file(self, filename: str, rwd: str) -> None:
    self.fd = open(filename, rwd)

  def close_file(self) -> None:
    self.fi.close() if self.fi and not self.fi.closed else None
    self.fd.close() if self.fd and not self.fd.closed else None

  def set_index_data(self, index: DbIndex, data: DbData):
    self.index = index
    self.data = data

  def set_ssl_socket(self, sslsock):
    self.ssl_sock = sslsock

  def index_to_bytearray_encrypt(self, index, cip):
    b: bytes = bytearray()
    var: List = [index.index, index.dbindex, index.database, index.table, index.row, index.col, index.segments, index.seek]
    packed: List[Union[bytes, None]] = [None] * 8
    packed[:7] = [struct.pack('>Q', c) for c in var]
    packed[8] = struct.pack('>255s', bytes(index.file.ljust(255, ' '), 'UTF-8'))
    [b.extend(i) for i in packed]
    return cip.encrypt_index(b)

  def decrypt_bytearray_to_index(self, indexba, cip):
    return cip.decrypt_index2(indexba)

  def send_encrypted_index(self, index):
    self.ssl_sock.send(struct.pack('>Q', len(index))) if self.ssl_sock else b''
    self.ssl_sock.send(index) if self.ssl_sock else b''

  def recv_encrypted_index(self):
    size = self.ssl_sock.recv(8) if self.ssl_sock else ()
    return self.ssl_sock.recv(int.from_bytes(size)) if self.ssl_sock else ()

  def send_encrypted_data(self, data):
    self.ssl_sock.send(struct.pack('>Q', len(data))) if self.ssl_sock else b''
    self.ssl_sock.send(data) if self.ssl_sock else b''

  def recv_encrypted_data(self):
    size = self.ssl_sock.recv(8) if self.ssl_sock else ()
    return self.ssl_sock.recv(int.from_bytes(size)) if self.ssl_sock else ()

  def data_to_bytearray_encrypt(self, data, index, cip):
    b: bytes = bytearray()
    if isinstance(data, DbData) and data and data.data:
      pvr: List = [struct.pack('>Q', c) for c in [data.index, data.database, data.table, data.relative, data.row, data.col]]
      gzd: bytes = gzip.compress(bytearray(data.data), compresslevel=3)
      gzl: int = len(gzd)
      gzlsize: int = gzl // self.size
      if isinstance(index.seek, bytes) and self.fd:
        if not struct.unpack('>Q', index.seek):
          index.seek = struct.pack('>Q', self.fd.tell())
        self.fd.seek(struct.unpack('>Q', index.seek)[0], 0)
      # Calculate diff between length of gz data, if not divisable with self.size, add 1 to zlen
      zlen: int = (gzlsize) if not (gzl - ((gzlsize) * self.size) > 0) else (gzlsize) + 1
      [b.extend(pvr[i]) for i in range(6)]
      [b.extend(gzd[i * self.size : (i + 1) * self.size]) for i in range(zlen)]
      return cip.encrypt_index(b)

  def decrypt_bytearray_to_data(self, databa, cip):
    return cip.decrypt_data2(databa)

  def write_index3(self, index):
    self.open_index_file(self.fn[0], 'ab+') if self.fi.closed else None
    self.fi.write(index) if self.fi else b''

  def write_data3(self, data):
    self.open_data_file(self.fn[1], 'ab+') if self.fd.closed else None
    self.fd.write(data) if self.fd else b''

  def read_index3(self):
    self.open_index_file(self.fn[0], 'rb+')
    self.fimm = mmap.mmap(self.fi.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return self.fimm.read() if self.fimm else b''

  def read_data3(self):
    self.open_data_file(self.fn[1], 'rb+')
    self.fdmm = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return self.fdmm.read() if self.fimm else b''
