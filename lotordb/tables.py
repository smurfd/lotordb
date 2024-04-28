#!/usr/bin/env python3
from dataclasses import dataclass, field, fields
from typing import List, Union, BinaryIO, Tuple, IO
import struct, gzip, time, threading, mmap, socket, secrets
from lotordb.cipher import Cipher

# Thinking out loud about how to do a database
"""
index[320] (read data when server starts)
[index 8b, dbindex 8b, database 8b, table 8b, row 8b, col 8b, datasegments 8b, seek in file 8b, filename 256str]

ex: small data, 1st index, 1st db and 1st table. 1st row and 1st column
[0x1, '/tmp/db.db', 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0]

ex: big data, 2st index, 1st db and 1st table. 2nd row and 1st column (0x20 * 4000) data
[0x2, '/tmp/db.db', 0x2, 0x1, 0x1, 0x1, 0x1, 0x1, 0x20, 4096]


data[4096]
[index 8b, database 8b, table 8b, relative 8b, row 8b, col 8b, data 4048b]

ex: small data, 1st index, 1st db and 1st table. 1st row and 1st column
[0x1, 0x1, 0x1, 0x0, 0x1, 0x1, b'some data here']

ex: big data, 2st index, 1st db and 1st table. 2st row and 1st column
[0x2, 0x1, 0x1, 0x0, 0x1, 0x1, b'a shit ton of data way more than 4000b']
[   , 0x1, 0x1, 0x2, 0x1, 0x1, b'a shit ton of data way more than 4000b']
[   , 0x1, 0x1, 0x2, 0x1, 0x1, b'a shit ton of data way more than 4000b']
[   , 0x1, 0x1, 0x2, 0x1, 0x1, b'a shit ton of data way more than 4000b']
[   , 0x1, 0x1, 0x2, 0x1, 0x1, b'a shit ton of data way more than 4000b']

inserting:
add entry to index
add entry to data(if zipped data exceeds 4000 add to more segments)

retrieving:
...

----------------------------------------------
"""


@dataclass
class DbIndex:
  index: Union[bytes, int, None] = field(default=b'', init=True)
  dbindex: Union[bytes, int, None] = field(default=b'', init=True)
  database: Union[bytes, int, None] = field(default=b'', init=True)
  table: Union[bytes, int, None] = field(default=b'', init=True)
  row: Union[bytes, int, None] = field(default=b'', init=True)
  col: Union[bytes, int, None] = field(default=b'', init=True)
  segments: Union[bytes, int, None] = field(default=b'', init=True)
  seek: Union[bytes, int, None] = field(default=b'', init=True)
  file: Union[bytes, str, None] = field(default=b'db.dbindex', init=True)

  def __iter__(self):
    return (getattr(self, f.name) for f in fields(self))


@dataclass
class DbData:
  index: Union[bytes, int, None] = field(default=b'', init=True)
  database: Union[bytes, int, None] = field(default=b'', init=True)
  table: Union[bytes, int, None] = field(default=b'', init=True)
  relative: Union[bytes, int, None] = field(default=b'', init=True)
  row: Union[bytes, int, None] = field(default=b'', init=True)
  col: Union[bytes, int, None] = field(default=b'', init=True)
  data: Union[bytes, list, None] = field(default=b'', init=True)

  def __iter__(self):
    return (getattr(self, f.name) for f in fields(self))


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
    self.start()

  def __exit__(self) -> None:
    self.close_file()
    self.join(timeout=0.1)

  def open_index_file(self, filename: str, rwd: str) -> None:
    self.fi = open(filename, rwd)

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

  def get_index(self, index: DbIndex) -> List:
    unpacked: List[Union[int, Tuple, None]] = [None] * 8
    var: List = [index.index, index.dbindex, index.database, index.table, index.row, index.col, index.segments, index.seek]
    unpacked[:7] = [struct.unpack('>Q', var[c]) for c in range(8)]
    if isinstance(index.file, bytes):
      unpacked[8] = struct.unpack('>255s', index.file)[0].decode('UTF-8').rstrip(' ')
    return unpacked

  def get_data(self, index: DbIndex, data: List) -> Tuple[list, bytes]:
    dat: bytes = b''
    ret: List = []
    if isinstance(index.segments, bytes):
      for i in range(struct.unpack('>Q', index.segments)[0]):
        dat += data[i].data
        ret += [struct.unpack('>Q', c) for c in [data[i].index, data[i].database, data[i].table, data[i].relative, data[i].row, data[i].col]]
    return ret, gzip.decompress(bytearray(struct.unpack('>%dQ' % (len(dat) // 8), dat)))

  def write_index(self, i: DbIndex) -> None:
    cip = [
      self.cip.encrypt_cbc(i.index, self.cip.key, self.cip.iv),  # type: ignore
      self.cip.encrypt_cbc(i.dbindex, self.cip.key, self.cip.iv),  # type: ignore
      self.cip.encrypt_cbc(i.database, self.cip.key, self.cip.iv),  # type: ignore
      self.cip.encrypt_cbc(i.table, self.cip.key, self.cip.iv),  # type: ignore
      self.cip.encrypt_cbc(i.row, self.cip.key, self.cip.iv),  # type: ignore
      self.cip.encrypt_cbc(i.col, self.cip.key, self.cip.iv),  # type: ignore
      self.cip.encrypt_cbc(i.segments, self.cip.key, self.cip.iv),  # type: ignore
      self.cip.encrypt_cbc(i.seek, self.cip.key, self.cip.iv),  # type: ignore
      self.cip.encrypt_cbc(i.file, self.cip.key, self.cip.iv),  # type: ignore
    ]
    [self.fi.write(x) for x in cip if self.fi]  # type: ignore

  def write_data(self, i: DbIndex, d: List) -> None:
    if i and isinstance(i.segments, bytes):
      for b in range(struct.unpack('>Q', i.segments)[0]):
        cip = [
          self.cip.encrypt_cbc(d[b].index, self.cip.key, self.cip.iv),
          self.cip.encrypt_cbc(d[b].database, self.cip.key, self.cip.iv),
          self.cip.encrypt_cbc(d[b].table, self.cip.key, self.cip.iv),
          self.cip.encrypt_cbc(d[b].relative, self.cip.key, self.cip.iv),
          self.cip.encrypt_cbc(d[b].row, self.cip.key, self.cip.iv),
          self.cip.encrypt_cbc(d[b].col, self.cip.key, self.cip.iv),
          self.cip.encrypt_cbc(d[b].data, self.cip.key, self.cip.iv),
        ]
        [self.fd.write(x) for x in cip if self.fd]  # type: ignore

  def len_salt_hash(self, ln, c) -> int:
    if ln % 16:  # handle padded data
      ln += ln % 16
    ln += self.cip.vars.SALT + self.cip.vars.HMAC + 2
    return ln

  def read_index(self) -> Union[DbIndex, None]:
    self.open_index_file(self.fn[0], 'rb+')
    self.fimm = mmap.mmap(self.fi.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    rd = [0] * 9
    if self.fdmm:
      for j in range(9):
        rd[j] = self.cip.decrypt_cbc(self.fdmm.read(self.len_salt_hash([8, 8, 8, 8, 8, 8, 8, 8, 255][j], self.cip)), self.cip.key, self.cip.iv)  # type: ignore
    return DbIndex(*(rd))  # type: ignore

  def read_data(self, index: DbIndex) -> List:
    if isinstance(index.segments, bytes):
      lngt: int = struct.unpack('>Q', index.segments)[0]
    self.open_data_file(self.fn[1], 'rb+')
    self.fdmm = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    r = [0] * lngt
    for k in range(lngt):
      rd = [0] * 7
      if self.fdmm:
        for j in range(7):
          rd[j] = self.cip.decrypt_cbc(self.fdmm.read(self.len_salt_hash([8, 8, 8, 8, 8, 8, 4048][j], self.cip)), self.cip.key, self.cip.iv)  # type: ignore
      r.extend(DbData(*(rd)))  # type: ignore
    return r

  def send_index(self, sock: socket.socket, index: DbIndex) -> None:
    b: bytes = bytearray()
    [b.extend(i) for i in [index.index, index.dbindex, index.database, index.table, index.row, index.col, index.segments, index.seek, index.file]]  # type: ignore
    sock.send(b)

  def send_data(self, sock: socket.socket, data: DbData) -> None:
    b: bytes = bytearray()
    [b.extend(i) for i in [data.index, data.database, data.table, data.relative, data.row, data.col, data.data]]  # type: ignore
    sock.send(b)

  def recv_index(self, sock: socket.socket, size: int = 319) -> Tuple:
    r = sock.recv(size)  # Size of DbIndex, below separate per variable
    return (r[0:8], r[8:16], r[16:24], r[24:32], r[32:40], r[40:48], r[48:56], r[56:64], r[64:319])

  def recv_data(self, sock: socket.socket, size: int = 4096) -> Tuple:
    r = sock.recv(size)  # Size of DbData, below separate per variable
    return (r[0:8], r[8:16], r[16:24], r[24:32], r[32:40], r[40:48], r[48:4096])

  def set_index_data(self, index: DbIndex, data: DbData):
    self.index = index
    self.data = data


if __name__ == '__main__':
  print('Table')
  context: List = [123] * 124  # 100000025
  tot = time.perf_counter()
  tables = Tables('.lib/db1')
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  index: DbIndex = tables.init_index(ind)
  data = tables.init_data(dad, index)  # 500mb
  if isinstance(index, DbIndex):
    tables.get_index(index)
    tables.write_index(index)
    if isinstance(data, list):
      tables.write_data(index, data)
      index2 = tables.read_index()
      data2 = tables.read_data(index)
      if isinstance(index2, DbIndex):
        tables.get_data(index2, data2)
  print('time {:.4f}'.format(time.perf_counter() - tot))
