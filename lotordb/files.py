#!/usr/bin/env python3
from dataclasses import dataclass, field
from typing import List, Union, BinaryIO, Tuple
import struct, gzip, time, threading

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


class Files(threading.Thread):
  def __init__(self, fn) -> None:
    threading.Thread.__init__(self, group=None)
    self.fi: Union[None, BinaryIO] = None
    self.fd: Union[None, BinaryIO] = None
    self.fn = (fn + '.dbindex', fn + '.dbdata')
    self.open_index_file(self.fn[0], 'ab+')
    self.open_data_file(self.fn[1], 'ab+')
    self.size = 4048
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
    packed: List[Union[bytes, None]] = [None] * 9
    var: List = [index, dbindex, database, table, row, col, segments, seek]
    packed[:7] = [struct.pack('>Q', var[c]) for c in range(8)]
    packed[8] = struct.pack('>255s', bytes(file.ljust(255, ' '), 'UTF-8'))
    return DbIndex(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], packed[6], packed[7], packed[8])

  def init_data(self, index, database, table, relative, row, col, data, dbi) -> Union[DbData, List]:
    packed: List[Union[bytes, None]] = [None] * 7
    gzd: bytes = gzip.compress(struct.pack('>%dQ' % (len(data)), *data))
    var: List = [index, database, table, relative, row, col]
    ret: List = []
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
    unpacked: List[Union[int, Tuple, None]] = [None] * 9
    var: List = [dbi.index, dbi.dbindex, dbi.database, dbi.table, dbi.row, dbi.col, dbi.segments, dbi.seek]
    unpacked[:7] = [struct.unpack('>Q', var[c]) for c in range(8)]
    unpacked[8] = struct.unpack('>255s', dbi.file)[0].decode('UTF-8').rstrip(' ')
    return unpacked

  def get_data(self, dbi, dbd) -> Tuple[list, Tuple]:
    ret: List = []
    dat: bytes = b''
    for i in range(struct.unpack('>Q', dbi.segments)[0]):
      unpacked: List[Union[int, Tuple, None]] = [None] * 7
      var: List = [dbd[i].index, dbd[i].database, dbd[i].table, dbd[i].relative, dbd[i].row, dbd[i].col]
      unpacked[:6] = [struct.unpack('>Q', var[c]) for c in range(6)]
      dat += dbd[i].data
      ret.append(unpacked)
    uncdat = gzip.decompress(dat)
    return ret, struct.unpack('>%dQ' % (len(uncdat) // 8), uncdat)

  def write_index(self, dbi) -> None:
    var: List = [dbi.index, dbi.dbindex, dbi.database, dbi.table, dbi.row, dbi.col, dbi.segments, dbi.seek, dbi.file]
    [self.fi.write(var[c]) for c in range(9) if self.fi]

  def write_data(self, dbi, dbd) -> None:
    for i in range(int(''.join(map(str, dbi.segments)))):
      var: List = [dbd[i].index, dbd[i].database, dbd[i].table, dbd[i].relative, dbd[i].row, dbd[i].col, dbd[i].data]
      [self.fd.write(var[c]) for c in range(7) if self.fd]

  def read_index(self) -> Union[DbIndex, None]:
    self.close_file()
    self.open_index_file(self.fn[0], 'rb+')
    return DbIndex(*(self.fi.read([8, 8, 8, 8, 8, 8, 8, 8, 255][c]) for c in range(9) if self.fi))

  def read_data(self, dbi) -> List:
    self.close_file()
    self.open_data_file(self.fn[1], 'rb+')
    return [DbData(*(self.fd.read([8, 8, 8, 8, 8, 8, 4048][c]) for c in range(7) if self.fd)) for i in range(int(''.join(map(str, dbi.segments))))]


if __name__ == '__main__':
  print('DB')
  t = time.perf_counter()
  print('time {:.4f}'.format(time.perf_counter() - t))
  f = Files('.lib/db1')
  a = f.init_index(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  b = f.init_data(1, 1, 1, 1, 1, 1, [123] * 100000025, a)
  f.get_index(a)
  d1, d2 = f.get_data(a, b)
  assert list(d2) == [123] * 100000025
  f.write_index(a)
  f.write_data(a, b)
  a2 = f.read_index()
  b2 = f.read_data(a)
  print('time {:.4f}'.format(time.perf_counter() - t))
