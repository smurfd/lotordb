#!/usr/bin/env python3
from typing import List, Union, BinaryIO, Tuple, IO, Any
import struct, gzip, threading, mmap, socket, secrets
from lotordb.vars import DbIndex, DbData
from lotordb.cipher import Cipher


# Maby? https://renatocunha.com/2015/11/ctypes-mmap-rwlock/
# Before mmap : time 6.3838
# After mmap  : time 6.3694
# After compress level1: time 4.9225
# 4.4616 python 3.11.7
# 4.0892 python 3.12.2
# After compress befor pack: time 0.8563!!!!! (python 3.11.7)
# After compress befor pack without double get_data: time 0.7963!!!!! (python 3.11.7)
# Sending byte array: time 0.4790!!! (python 3.11.7)
# gzip command: time 1.539226
class Tables(threading.Thread):  # Table store
  def __init__(self, fn) -> None:
    threading.Thread.__init__(self, group=None)
    self.fi: Union[None, BinaryIO, IO] = None
    self.fd: Union[None, BinaryIO, IO] = None
    self.fimm: Union[None, BinaryIO] = None
    self.fdmm: Union[None, BinaryIO] = None
    self.fn = (fn + '.dbindex', fn + '.dbdata')
    self.open_index_file(self.fn[0], 'ab+')
    self.open_data_file(self.fn[1], 'ab+')
    self.size: int = 4048
    self.index: Union[DbIndex, None] = None
    self.data: Union[DbData, None] = None
    self.cip = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
    self.ssl_sock: Union[socket.socket, None] = None
    self.start()

  def __exit__(self) -> None:
    self.close_file()
    self.join(timeout=0.1)

  def open_index_file(self, filename: str, rwd: str) -> None:
    self.fi = open(filename, rwd)
    print('ind', filename)

  def open_data_file(self, filename: str, rwd: str) -> None:
    self.fd = open(filename, rwd)

  def close_file(self) -> None:
    if self.fi and not self.fi.closed:
      self.fi.close()
    if self.fd and not self.fd.closed:
      self.fd.close()

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
      ret: List = []
      if isinstance(index.seek, bytes) and self.fd:
        if not struct.unpack('>Q', index.seek):
          index.seek = struct.pack('>Q', self.fd.tell())
        self.fd.seek(struct.unpack('>Q', index.seek)[0], 0)
      # Calculate diff between length of gz data, if not divisable with self.size, add 1 to zlen
      zlen: int = (gzl // self.size) if not (gzl - ((gzl // self.size) * self.size) > 0) else (gzl // self.size) + 1
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
    print(self.fi)
    if self.fi:
      print('hi,', index_encrypted)
      print(self.fi.write(index_encrypted))

  def write_data2(self, i: DbIndex, d, cip) -> None:
    segmented_data, seg = cip.segment_data(i, d)
    i.segments = seg
    encrypted_data = cip.encrypt_list_data(segmented_data)
    if self.fd:
      self.fd.write(encrypted_data)

  def read_index2(self, index, cip) -> Union[Any, DbIndex, List, None]:
    self.open_index_file(self.fn[0], 'rb+')
    self.fimm = mmap.mmap(self.fi.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    x = self.fimm.read() if self.fimm else b''
    ret = DbIndex(*(cip.decrypt_index(x))) if len(x) == 322 else [DbIndex(*(cip.decrypt_index(x[i : i + 322]))) for i in range(0, len(x), 322)]  # type: ignore
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
    # if self.ssl_sock:
    #  self.ssl_sock.send(b)
    self.ssl_sock.send(b) if self.ssl_sock else b''

  def send_data(self, data: DbData) -> None:
    b: bytes = bytearray()
    [b.extend(i) for i in [data.index, data.database, data.table, data.relative, data.row, data.col, data.data]]  # type: ignore
    if self.ssl_sock:
      self.ssl_sock.send(b)

  def recv_index(self, size: int = 319) -> Tuple:
    if self.ssl_sock:
      r = self.ssl_sock.recv(size)  # Size of DbIndex, below separate per variable
    return (r[0:8], r[8:16], r[16:24], r[24:32], r[32:40], r[40:48], r[48:56], r[56:64], r[64:319])

  def recv_data(self, size: int = 4096) -> Tuple:
    if self.ssl_sock:
      r = self.ssl_sock.recv(size)  # Size of DbData, below separate per variable
    return (r[0:8], r[8:16], r[16:24], r[24:32], r[32:40], r[40:48], r[48:4096])

  def set_index_data(self, index: DbIndex, data: DbData):
    self.index = index
    self.data = data

  def set_ssl_socket(self, sslsock):
    self.ssl_sock = sslsock


if __name__ == '__main__':
  print('Table')
