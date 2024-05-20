#!/usr/bin/env python3
from typing import List, Union, BinaryIO, IO  # , Tuple, Any
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

  """
  def init_index(self, index: Union[DbIndex, Tuple, None]) -> DbIndex:
    if isinstance(index, DbIndex) and index and isinstance(index.file, str):
      var: List = [index.index, index.dbindex, index.database, index.table, index.row, index.col, index.segments, index.seek]
      packed: List[Union[bytes, None]] = [None] * 8
      packed[:7] = [struct.pack('>Q', c) for c in var]
      packed[8] = struct.pack('>255s', bytes(index.file.ljust(255, ' '), 'UTF-8'))
      return DbIndex(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], packed[6], packed[7], packed[8])
    return DbIndex(*index)  # type: ignore

  def init_data(self, data: Union[DbData, Tuple, None], index: DbIndex) -> Union[DbData, List]:
    if isinstance(data, DbData) and data and data.data:
      pvr: List = [struct.pack('>Q', c) for c in [data.index, data.database, data.table, data.relative, data.row, data.col]]
      gzd: bytes = gzip.compress(bytearray(data.data), compresslevel=3)
      gzd = struct.pack('>%dQ' % len(gzd), *gzd)
      gzl: int = len(gzd)
      gzlsize: int = gzl // self.size
      ret: List = []
      if isinstance(index.seek, bytes) and self.fd:
        if not struct.unpack('>Q', index.seek):
          index.seek = struct.pack('>Q', self.fd.tell())
        self.fd.seek(struct.unpack('>Q', index.seek)[0], 0)
      # Calculate diff between length of gz data, if not divisable with self.size, add 1 to zlen
      zlen: int = (gzlsize) if not (gzl - ((gzlsize) * self.size) > 0) else (gzlsize) + 1
      for i in range(zlen):
        ret += [DbData(pvr[0], pvr[1], pvr[2], pvr[3], pvr[4], pvr[5], gzd[i * self.size : (i + 1) * self.size])]
      if len(ret[len(ret) - 1].data) % self.size:  # If data is not self.size, fill out data to be self.size
        ret[len(ret) - 1].data += bytes([0] * (self.size - len(ret[len(ret) - 1].data)))
      if not index.segments == zlen:  # Set number of segments to zlen
        index.segments = struct.pack('>Q', zlen)
      return ret
    return DbData(*data)  # type: ignore

  def write_index2(self, index: DbIndex, cip) -> None:
    var: List = [index.index, index.dbindex, index.database, index.table, index.row, index.col, index.segments, index.seek]
    index_bytearr = [c for c in var]
    index_bytearr.extend(map(ord, index.file.ljust(255, ' ')))  # type: ignore
    index_encrypted = cip.encrypt_index(index_bytearr)
    self.fi.write(index_encrypted) if self.fi else b''

  def write_data2(self, i: DbIndex, d, cip) -> None:
    segmented_data, i.segments = cip.segment_data(i, d)
    encrypted_data = cip.encrypt_list_data(segmented_data)
    self.fd.write(encrypted_data) if self.fd else b''

  def read_index2(self, index, cip) -> Union[Any, DbIndex, List, None]:
    self.open_index_file(self.fn[0], 'rb+')
    self.fimm = mmap.mmap(self.fi.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    r = self.fimm.read() if self.fimm else b''
    ret = DbIndex(*(cip.decrypt_index(r))) if len(r) == 322 else [DbIndex(*(cip.decrypt_index(r[i : i + 322]))) for i in range(0, len(r), 322)]  # type: ignore
    if isinstance(ret, DbIndex) and ret.segments != index.segments:
      ret.segments = index.segments
    elif isinstance(ret, list):
      ret[0].segments = index.segments  # TODO: which index segment shoul be updated!?
    return ret

  def read_data2(self, index: DbIndex, cip) -> List:
    data_list: List = []
    ret: List = []
    ln: int = 1 if not isinstance(index, list) else len(index)
    self.open_data_file(self.fn[1], 'rb+')
    self.fdmm = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    data_list += [cip.decrypt_list_data(self.fdmm.read(194)) for i in range(ln)]  # type: ignore
    if len(data_list) <= 4096 and isinstance(data_list, bytes):
      return cip.get_decrypted_data(data_list)
    elif isinstance(data_list, bytes):
      return [cip.get_decrypted_data(data_list[i : i + 4096]) for i in range(0, len(data_list), 4096)]
    elif isinstance(data_list, list):
      for j in range(len(data_list)):
        if len(data_list[j]) <= 4096:
          ret += [cip.get_decrypted_data(data_list[j])]
        else:
          for i in range(0, len(data_list[j]), 4096):
            ret += [cip.get_decrypted_data(data_list[j][i : i + 4096])]
      return ret

  def send_index(self, index: DbIndex) -> None:
    b: bytes = bytearray()
    [b.extend(i) for i in [index.index, index.dbindex, index.database, index.table, index.row, index.col, index.segments, index.seek, index.file]]  # type: ignore
    self.ssl_sock.send(b) if self.ssl_sock else b''

  def send_data(self, data: DbData) -> None:
    b: bytes = bytearray()
    [b.extend(i) for i in [data.index, data.database, data.table, data.relative, data.row, data.col, data.data]]  # type: ignore
    self.ssl_sock.send(b) if self.ssl_sock else b''

  def recv_index(self, size: int = 319) -> Tuple:
    r = self.ssl_sock.recv(size) if self.ssl_sock else ()  # Size of DbIndex, below separate per variable
    return (r[0:8], r[8:16], r[16:24], r[24:32], r[32:40], r[40:48], r[48:56], r[56:64], r[64:319])

  def recv_data(self, size: int = 4096) -> Tuple:
    r = self.ssl_sock.recv(size) if self.ssl_sock else ()  # Size of DbData, below separate per variable
    return (r[0:8], r[8:16], r[16:24], r[24:32], r[32:40], r[40:48], r[48:4096])
  """

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
