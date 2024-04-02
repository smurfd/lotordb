#!/usr/bin/env python3
from dataclasses import dataclass, field
from typing import List, Union, BinaryIO, Tuple
import struct, gzip, time, threading, mmap

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
  index: Union[bytes, None] = field(default=b'', init=True)
  dbindex: Union[bytes, None] = field(default=b'', init=True)
  database: Union[bytes, None] = field(default=b'', init=True)
  table: Union[bytes, None] = field(default=b'', init=True)
  row: Union[bytes, None] = field(default=b'', init=True)
  col: Union[bytes, None] = field(default=b'', init=True)
  segments: Union[bytes, None] = field(default=b'', init=True)
  seek: Union[bytes, None] = field(default=b'', init=True)
  file: Union[bytes, None] = field(default=b'db.dbindex', init=True)


@dataclass
class DbData:
  index: Union[bytes, None] = field(default=b'', init=True)
  database: Union[bytes, None] = field(default=b'', init=True)
  table: Union[bytes, None] = field(default=b'', init=True)
  relative: Union[bytes, None] = field(default=b'', init=True)
  row: Union[bytes, None] = field(default=b'', init=True)
  col: Union[bytes, None] = field(default=b'', init=True)
  data: Union[bytes, None] = field(default=b'', init=True)


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
class Files(threading.Thread):
  def __init__(self, fn) -> None:
    threading.Thread.__init__(self, group=None)
    self.fi: Union[None, BinaryIO] = None
    self.fd: Union[None, BinaryIO] = None
    self.fimm: Union[None, BinaryIO] = None
    self.fdmm: Union[None, BinaryIO] = None
    self.fn = (fn + '.dbindex', fn + '.dbdata')
    self.open_index_file(self.fn[0], 'ab+')
    self.open_data_file(self.fn[1], 'ab+')
    self.size = 4048
    self.start()

  def __exit__(self) -> None:
    self.close_file()
    self.join(timeout=0.1)

  def open_index_file(self, filename, rwd) -> None:
    self.fi = open(filename, rwd)

  def open_data_file(self, filename, rwd) -> None:
    self.fd = open(filename, rwd)

  def close_file(self) -> None:
    if self.fi and not self.fi.closed:
      self.fi.close()
    if self.fd and not self.fd.closed:
      self.fd.close()

  def init_index(self, index, dbindex, database, table, row, col, segments, seek, file) -> DbIndex:
    var: List = [index, dbindex, database, table, row, col, segments, seek]
    if isinstance(index, bytes):  # Assume everything is in bytes
      return DbIndex(index, dbindex, database, table, row, col, segments, seek, file)
    else:
      packed: List[Union[bytes, None]] = [None] * 8
      packed[:7] = [struct.pack('>Q', c) for c in var]
      packed[8] = struct.pack('>255s', bytes(file.ljust(255, ' '), 'UTF-8'))
      return DbIndex(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], packed[6], packed[7], packed[8])

  def init_data(self, index, database, table, relative, row, col, data, dbi) -> Union[DbData, List]:
    if isinstance(index, bytes):  # Assume everything is in bytes
      return DbData(index, database, table, relative, row, col, data)
    else:
      pvr: List = [struct.pack('>Q', c) for c in [index, database, table, relative, row, col]]
      gzd: bytes = gzip.compress(bytearray(data), compresslevel=3)
      gzd = struct.pack('>%dQ' % len(gzd), *gzd)
      gzl: int = len(gzd)
      ret: List = []
      if self.fd:
        if not struct.unpack('>Q', dbi.seek):
          dbi.seek = struct.pack('>Q', self.fd.tell())
        self.fd.seek(struct.unpack('>Q', dbi.seek)[0], 0)
      # Calculate diff between length of gz data, if not divisable with self.size, add 1 to zlen
      zlen: int = (gzl // self.size) if not (gzl - ((gzl // self.size) * self.size) > 0) else (gzl // self.size) + 1
      for i in range(zlen):
        ret += [DbData(pvr[0], pvr[1], pvr[2], pvr[3], pvr[4], pvr[5], gzd[i * self.size : (i + 1) * self.size])]
      if len(ret[len(ret) - 1].data) % self.size:  # If data is not self.size, fill out data to be self.size
        ret[len(ret) - 1].data += bytes([0] * (self.size - len(ret[len(ret) - 1].data)))
      if not dbi.segments == zlen:  # Set number of segments to zlen
        dbi.segments = struct.pack('>Q', zlen)
      return ret

  def get_index(self, dbi) -> List:
    unpacked: List[Union[int, Tuple, None]] = [None] * 8
    var: List = [dbi.index, dbi.dbindex, dbi.database, dbi.table, dbi.row, dbi.col, dbi.segments, dbi.seek]
    unpacked[:7] = [struct.unpack('>Q', var[c]) for c in range(8)]
    unpacked[8] = struct.unpack('>255s', dbi.file)[0].decode('UTF-8').rstrip(' ')
    return unpacked

  def get_data(self, dbi, dbd) -> Tuple[list, bytes]:
    dat: bytes = b''
    ret: List = []
    for i in range(struct.unpack('>Q', dbi.segments)[0]):
      dat += dbd[i].data
      ret += [struct.unpack('>Q', c) for c in [dbd[i].index, dbd[i].database, dbd[i].table, dbd[i].relative, dbd[i].row, dbd[i].col]]
    return ret, gzip.decompress(bytearray(struct.unpack('>%dQ' % (len(dat) // 8), dat)))

  def write_index(self, i) -> None:  # i, dbindex
    [self.fi.write(c) for c in [i.index, i.dbindex, i.database, i.table, i.row, i.col, i.segments, i.seek, i.file] if self.fi]

  def write_data(self, i, d) -> None:  # i: DbIndex, d: DbData
    for b in range(struct.unpack('>Q', i.segments)[0]):
      [self.fd.write(c) for c in [d[b].index, d[b].database, d[b].table, d[b].relative, d[b].row, d[b].col, d[b].data] if self.fd]

  def read_index(self) -> Union[DbIndex, None]:
    self.open_index_file(self.fn[0], 'rb+')
    self.fimm = mmap.mmap(self.fi.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return DbIndex(*(self.fimm.read([8, 8, 8, 8, 8, 8, 8, 8, 255][c]) for c in range(9) if self.fimm))

  def read_data(self, dbi) -> List:
    lngt: int = struct.unpack('>Q', dbi.segments)[0]
    self.open_data_file(self.fn[1], 'rb+')
    self.fdmm = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return [DbData(*(self.fdmm.read([8, 8, 8, 8, 8, 8, 4048][c]) for c in range(7) if self.fdmm)) for i in range(lngt)]

  def send_index(self, sock, index) -> None:
    b = bytearray()
    b.extend(index.index)
    b.extend(index.dbindex)
    b.extend(index.database)
    b.extend(index.table)
    b.extend(index.row)
    b.extend(index.col)
    b.extend(index.segments)
    b.extend(index.seek)
    b.extend(index.file)
    sock.send(b)

  def send_data(self, sock, data) -> None:
    b = bytearray()
    b.extend(data.index)
    b.extend(data.database)
    b.extend(data.table)
    b.extend(data.relative)
    b.extend(data.row)
    b.extend(data.col)
    b.extend(data.data)
    sock.send(b)

  def recv_index(self, sock, size=256) -> Tuple:
    x = sock.recv(319)
    return (x[0:8], x[8:16], x[16:24], x[24:32], x[32:40], x[40:48], x[48:56], x[56:64], x[64:319])

  def recv_data(self, sock, size=4096) -> Tuple:
    x = sock.recv(4096)
    return (x[0:8], x[8:16], x[16:24], x[24:32], x[32:40], x[40:48], x[48:4096])


if __name__ == '__main__':
  print('DB')
  data: List = [123] * 100000025
  tot = time.perf_counter()
  f = Files('.lib/db1')
  a = f.init_index(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  b = f.init_data(1, 1, 1, 1, 1, 1, data, a)  # 500mb
  f.get_index(a)
  f.write_index(a)
  f.write_data(a, b)
  a2 = f.read_index()
  b2 = f.read_data(a)
  d3, d4 = f.get_data(a2, b2)
  print('time {:.4f}'.format(time.perf_counter() - tot))
