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


# TODO: mmap instead of read/write
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
# After compress level: time 4.9225
class Files(threading.Thread):
  def __init__(self, fn) -> None:
    threading.Thread.__init__(self, group=None)
    self.thread = threading.Thread()
    self.fi: Union[None, BinaryIO] = None
    self.fd: Union[None, BinaryIO] = None
    self.fimm: Union[None, BinaryIO] = None
    self.fdmm: Union[None, BinaryIO] = None
    self.fn = (fn + '.dbindex', fn + '.dbdata')
    self.open_index_file(self.fn[0], 'ab+')
    self.open_data_file(self.fn[1], 'ab+')
    self.size = 4048
    self.thread.start()
    self.start()

  def __exit__(self) -> None:
    self.close_file()
    self.join()

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
    packed: List[Union[bytes, None]] = [None] * 8
    var: List = [index, dbindex, database, table, row, col, segments, seek]
    packed[:7] = [struct.pack('>Q', var[c]) for c in range(8)]
    packed[8] = struct.pack('>255s', bytes(file.ljust(255, ' '), 'UTF-8'))
    return DbIndex(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], packed[6], packed[7], packed[8])

  def init_data(self, index, database, table, relative, row, col, data, dbi) -> Union[DbData, List]:
    packed: List[Union[bytes, None]] = [None] * 7
    var: List = [index, database, table, relative, row, col]
    ret: List = []
    t = time.perf_counter()
    tt = threading.Thread()
    tt.start()
    gzd: bytes = gzip.compress(struct.pack('>%dQ' % (len(data)), *data), compresslevel=1)
    tt.join(timeout=0.1)
    print('gzip compress time {:.4f}'.format(time.perf_counter() - t))
    if not struct.unpack('>Q', dbi.seek) and self.fd:
      dbi.seek = struct.pack('>Q', self.fd.tell())
    if self.fd:
      self.fd.seek(struct.unpack('>Q', dbi.seek)[0], 0)
    # Calculate diff between length of gz data, if not divisable with self.size, add 1 to j
    j: int = (len(gzd) // self.size) if not (len(gzd) - ((len(gzd) // self.size) * self.size) > 0) else (len(gzd) // self.size) + 1
    for i in range(j):
      packed[:6] = [struct.pack('>Q', var[c]) for c in range(6)]
      ret.append(DbData(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], gzd[i * self.size : (i + 1) * self.size]))
    if len(ret[len(ret) - 1].data) % self.size:
      ret[len(ret) - 1].data += bytes([0] * (self.size - len(ret[len(ret) - 1].data)))  # Fill out data to be 4048 in size
    if not dbi.segments == j:
      dbi.segments = struct.pack('>Q', j)
    return ret

  def get_index(self, dbi) -> List:
    unpacked: List[Union[int, Tuple, None]] = [None] * 8
    var: List = [dbi.index, dbi.dbindex, dbi.database, dbi.table, dbi.row, dbi.col, dbi.segments, dbi.seek]
    unpacked[:7] = [struct.unpack('>Q', var[c]) for c in range(8)]
    unpacked[8] = struct.unpack('>255s', dbi.file)[0].decode('UTF-8').rstrip(' ')
    return unpacked

  def get_data(self, dbi, dbd) -> Tuple[list, Tuple]:
    ret: List = []
    dat: bytes = b''
    for i in range(struct.unpack('>Q', dbi.segments)[0]):
      var: List = [dbd[i].index, dbd[i].database, dbd[i].table, dbd[i].relative, dbd[i].row, dbd[i].col]
      dat += dbd[i].data
      ret.append([struct.unpack('>Q', var[c]) for c in range(6)])
    tt = threading.Thread()
    tt.start()
    uncdat = gzip.decompress(dat)
    tt.join(timeout=0.1)
    return ret, struct.unpack('>%dQ' % (len(uncdat) // 8), uncdat)

  def write_index(self, dbi) -> None:
    var: List = [dbi.index, dbi.dbindex, dbi.database, dbi.table, dbi.row, dbi.col, dbi.segments, dbi.seek, dbi.file]
    [self.fi.write(var[c]) for c in range(9) if self.fi]

  def write_data(self, dbi, dbd) -> None:
    for i in range(struct.unpack('>Q', dbi.segments)[0]):
      var: List = [dbd[i].index, dbd[i].database, dbd[i].table, dbd[i].relative, dbd[i].row, dbd[i].col, dbd[i].data]
      [self.fd.write(var[c]) for c in range(7) if self.fd]

  def read_index(self) -> Union[DbIndex, None]:
    # self.close_file()
    self.open_index_file(self.fn[0], 'rb+')
    self.fimm = mmap.mmap(self.fi.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return DbIndex(*(self.fimm.read([8, 8, 8, 8, 8, 8, 8, 8, 255][c]) for c in range(9) if self.fimm))

  def read_data(self, dbi) -> List:
    # self.close_file()
    self.open_data_file(self.fn[1], 'rb+')
    self.fdmm = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return [
      DbData(*(self.fdmm.read([8, 8, 8, 8, 8, 8, 4048][c]) for c in range(7) if self.fdmm)) for i in range(struct.unpack('>Q', dbi.segments)[0])
    ]


if __name__ == '__main__':
  print('DB')
  tot = time.perf_counter()
  t = time.perf_counter()
  f = Files('.lib/db1')
  print('construct time {:.4f}'.format(time.perf_counter() - t))
  t = time.perf_counter()
  a = f.init_index(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  print('init_index time {:.4f}'.format(time.perf_counter() - t))
  t = time.perf_counter()
  b = f.init_data(1, 1, 1, 1, 1, 1, [123] * 100000025, a)
  print('init_data time {:.4f}'.format(time.perf_counter() - t))
  t = time.perf_counter()
  f.get_index(a)
  print('get_index time {:.4f}'.format(time.perf_counter() - t))
  t = time.perf_counter()
  d1, d2 = f.get_data(a, b)
  print('get_data time {:.4f}'.format(time.perf_counter() - t))
  # t = time.perf_counter()
  # assert list(d2) == [123] * 100000025
  # print('assert time {:.4f}'.format(time.perf_counter() - t))
  t = time.perf_counter()
  f.write_index(a)
  print('write_index time {:.4f}'.format(time.perf_counter() - t))
  t = time.perf_counter()
  f.write_data(a, b)
  print('write_data time {:.4f}'.format(time.perf_counter() - t))
  t = time.perf_counter()
  a2 = f.read_index()
  print('read_index time {:.4f}'.format(time.perf_counter() - t))
  t = time.perf_counter()
  b2 = f.read_data(a)
  print('read_data time {:.4f}'.format(time.perf_counter() - t))
  t = time.perf_counter()
  d3, d4 = f.get_data(a2, b2)
  print('get_data time {:.4f}'.format(time.perf_counter() - t))
  # print(f.fd.tell())
  # print(f.fd.seek(0, io.SEEK_END))
  # print(f.fd.tell())
  print('time {:.4f}'.format(time.perf_counter() - tot))
