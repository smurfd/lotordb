#!/usr/bin/env python3
from dataclasses import dataclass, field
from typing import List, Union, BinaryIO, Tuple
import struct, gzip, time

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


class Files:
  def __init__(self, fn) -> None:
    self.f: Union[None, BinaryIO] = None
    self.fn = (fn + '.dbindex', fn + '.dbdata')
    self.open_file(self.fn[0], 'ab+')
    self.size = 4048

  def __exit__(self) -> None:
    self.close_file()

  def open_file(self, filename, rwd) -> None:
    self.f = open(filename, rwd)

  def close_file(self) -> None:
    if self.f and not self.f.closed:
      self.f.close()

  def init_index(self, index, dbindex, database, table, row, col, segments, seek, file) -> DbIndex:
    packed: List[Union[bytes, None]] = [None] * 9
    packed[0] = struct.pack('>Q', index)
    packed[1] = struct.pack('>Q', dbindex)
    packed[2] = struct.pack('>Q', database)
    packed[3] = struct.pack('>Q', table)
    packed[4] = struct.pack('>Q', row)
    packed[5] = struct.pack('>Q', col)
    packed[6] = struct.pack('>Q', segments)
    packed[7] = struct.pack('>Q', seek)
    packed[8] = struct.pack('>255s', bytes(file.ljust(255, ' '), 'UTF-8'))
    return DbIndex(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], packed[6], packed[7], packed[8])

  def init_data(self, index, database, table, relative, row, col, data, dbi) -> Union[DbData, List]:
    packed: List[Union[bytes, None]] = [None] * 7
    gzd: bytes = gzip.compress(struct.pack('>%dQ' % (len(data)), *data))
    print('GZD', len(gzd))
    if len(gzd) <= self.size:
      packed[0] = struct.pack('>Q', index)
      packed[1] = struct.pack('>Q', database)
      packed[2] = struct.pack('>Q', table)
      packed[3] = struct.pack('>Q', relative)
      packed[4] = struct.pack('>Q', row)
      packed[5] = struct.pack('>Q', col)
      gzda = bytearray(gzd)
      gzda.extend(bytes([0] * (self.size - len(gzd))))  # Fill out data to be 4048 in size
      packed[6] = gzda
      return DbData(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], packed[6])
    elif len(gzd) > self.size:
      ret: List = []
      # Calculate diff between length of gz data, if not divisable with self.size, add 1 to j
      j: int = (len(gzd) // self.size) if not (len(gzd) - ((len(gzd) // self.size) * self.size) > 0) else (len(gzd) // self.size) + 1
      for i in range(j):
        packed[0] = struct.pack('>Q', index)
        packed[1] = struct.pack('>Q', database)
        packed[2] = struct.pack('>Q', table)
        packed[3] = struct.pack('>Q', relative)
        packed[4] = struct.pack('>Q', row)
        packed[5] = struct.pack('>Q', col)
        if not dbi.segments == j:
          dbi.segments = j.to_bytes(8, 'big')
        gzdd = gzd[i * self.size : (i + 1) * self.size]
        if not len(gzdd) == self.size:
          gzdd = bytearray(gzdd)
          print('AAAAA', self.size - len(gzdd))
          gzdd.extend(bytes([0] * (self.size - len(gzdd))))  # Fill out data to be 4048 in size
        ret.append(DbData(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], gzdd))
      return ret
    return []

  def get_index(self, dbi) -> List:
    unpacked: List[Union[int, Tuple, None]] = [None] * 9
    unpacked[0] = struct.unpack('>Q', dbi.index)
    unpacked[1] = struct.unpack('>Q', dbi.dbindex)
    unpacked[2] = struct.unpack('>Q', dbi.database)
    unpacked[3] = struct.unpack('>Q', dbi.table)
    unpacked[4] = struct.unpack('>Q', dbi.row)
    unpacked[5] = struct.unpack('>Q', dbi.col)
    unpacked[6] = struct.unpack('>Q', dbi.segments)
    unpacked[7] = struct.unpack('>Q', dbi.seek)
    unpacked[8] = struct.unpack('>255s', dbi.file)[0].decode('UTF-8').rstrip(' ')
    return unpacked

  def get_data(self, dbi, dbd) -> Tuple[list, bytes]:
    ret: List = []
    dat: bytes = b''
    for i in range(int(''.join(map(str, dbi.segments)))):
      unpacked: List[Union[int, Tuple, None]] = [None] * 7
      unpacked[0] = struct.unpack('>Q', dbd[i].index)
      unpacked[1] = struct.unpack('>Q', dbd[i].database)
      unpacked[2] = struct.unpack('>Q', dbd[i].table)
      unpacked[3] = struct.unpack('>Q', dbd[i].relative)
      unpacked[4] = struct.unpack('>Q', dbd[i].row)
      unpacked[5] = struct.unpack('>Q', dbd[i].col)
      dat += dbd[i].data
      ret.append(unpacked)
    return ret, dat.rstrip(b'\x00')


if __name__ == '__main__':
  print('DB')
  t = time.perf_counter()
  print('time {:.4f}'.format(time.perf_counter() - t))
  f = Files('.lib/db1')
  a = f.init_index(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  b = f.init_data(1, 1, 1, 1, 1, 1, [123] * 10000025, a)
  f.get_index(a)
  d1, d2 = f.get_data(a, b)
  print(len(d2))
  print('time {:.4f}'.format(time.perf_counter() - t))
