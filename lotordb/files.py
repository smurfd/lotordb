#!/usr/bin/env python3
from dataclasses import dataclass, field
from typing import List, Union, BinaryIO
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

  def init_data(self, index, database, table, relative, row, col, data) -> Union[DbData, List]:
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
        ret.append(DbData(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], gzd[i * self.size : (i + 1) * self.size]))
      return ret
    return []


if __name__ == '__main__':
  print('DB')
  t = time.perf_counter()
  print('time {:.4f}'.format(time.perf_counter() - t))
  f = Files('.lib/db1')
  a = f.init_index(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  b = f.init_data(1, 1, 1, 1, 1, 1, [123] * 10000025)
  print('time {:.4f}'.format(time.perf_counter() - t))
  # print(a)
  # print(b)
  print('smurfd', gzip.compress('smurfd'.encode('UTF-8')))
