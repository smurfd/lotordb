#!/usr/bin/env python3
from dataclasses import dataclass, field
from typing import List, Union, BinaryIO
import struct, gzip

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

  def init_data(self, index, database, table, relative, row, col, data) -> DbData:
    d = (data + 4048 * [0])[:4048]
    packed: List[Union[bytes, None]] = [None] * 7
    packed[0] = struct.pack('>Q', index)
    packed[1] = struct.pack('>Q', database)
    packed[2] = struct.pack('>Q', table)
    packed[3] = struct.pack('>Q', relative)
    packed[4] = struct.pack('>Q', row)
    packed[5] = struct.pack('>Q', col)
    packed[6] = struct.pack('>%dQ' % 4048, *d)
    return DbData(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], packed[6])


if __name__ == '__main__':
  print('DB')
  f = Files('.lib/db1')
  f.init_index(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  f.init_data(1, 1, 1, 1, 1, 1, [111, 1222])
  print('smurfd', gzip.compress('smurfd'.encode('UTF-8')))
"""

@dataclass
class Row:
  nrrows: int = field(default=False, init=False)  # number of rows
  nrrow: int = field(default=False, init=False)  # number for this row
  data: list[Any]  # data for a row


@dataclass
class Table:
  nrtbls: int = field(default=False, init=False)  # number of tables
  nrtbl: int = field(default=False, init=False)  # this tables nr
  colnames: list[str]  # column names
  r: Row


@dataclass
class Db:
  nrdbs: int = field(default=False, init=False)  # total number of databases
  nrdb: int = field(default=False, init=False)  # this database number
  dbname: str  # database name
  nrtbl: int = field(default=False, init=False)  # number of tables in database
  tblnames: list[str]  # table names
  fn: str  # database filename
  tbl: Table


class LotordbFile:
  def __init__(self) -> None:
    self.f: Union[None, BinaryIO] = None

  def open_file(self, filename, rwd) -> None:
    self.f = open(filename, rwd)

  def close_file(self) -> None:
    if self.f and not self.f.closed:
      self.f.close()

  def read_header_from_file(self, filename) -> None:
    self.f = open(filename, 'ab+')
    print('---------')
    print(self.f)
    data = self.f.read()
    print(data)
    print(len(data))
    print(type(data[0]))
    print(
      data[0],
      data[1],
      data[2],
      data[3],
      data[4],
      data[5],
      data[6],
      data[7],
    )
    print(data[15], data[16], data[17])
    # print(struct.unpack('>32768Q', data))
    for i in range(len(data)):
      print(type(data[i]))
    print(struct.unpack('>s', bytes(data[389])))
    print(data.decode('UTF-8'))

  def read_dbheader_from_file(self) -> None:
    pass

  def read_table_header_from_file(self) -> None:
    pass

  def read_data_row_from_file(self) -> None:
    pass

  def create_db_file(self, filename) -> None:
    self.open_file(filename, 'ab+')

  def modify_nr_from_file(self, nr, mnr) -> bytes:
    dbs = binascii.unhexlify(nr.rstrip())
    dbsint = int.from_bytes(dbs, 'big') + mnr
    return binascii.hexlify(dbsint.to_bytes(len(dbs), 'big'))

  def add_db_to_file(self, db) -> None:
    self.pack_db(db)

  def pack_write_to_file(self, packed) -> None:
    if self.f:
      self.f.seek(0)
      self.f.write(packed[0])
      print('write')
      # [self.f.write(p) for p in packed if p]

  def pack_db(self, db) -> None:
    packed: List[Union[bytes, None]] = [None] * 6
    packed[0] = struct.pack('>Q', db.nrdbs)
    packed[1] = struct.pack('>Q', db.nrdb)
    packed[2] = struct.pack('>%ds' % len(db.dbname), bytes(db.dbname, 'UTF-8'))
    packed[3] = struct.pack('>Q', db.nrtbl)
    packed[4] = ','.join(db.tblnames).encode('UTF-8')
    packed[5] = struct.pack('>%ds' % len(db.fn), bytes(db.fn, 'UTF-8'))
    self.pack_write_to_file(packed)

  def pack_tbl(self, tbl) -> None:
    packed: List[Union[bytes, None]] = [None] * 3
    packed[0] = struct.pack('>Q', tbl.nrtbls)
    packed[1] = struct.pack('>Q', tbl.nrtbl)
    packed[2] = ','.join(tbl.colnames).encode('UTF-8')
    self.pack_write_to_file(packed)

  def pack_row(self, col) -> None:
    packed: List[Union[List[Any], bytes, None]] = [None] * 3
    packed[0] = struct.pack('>Q', col.nrrows)
    packed[1] = struct.pack('>Q', col.nrrow)
    packed[2] = []
    if isinstance(packed[2], list):
      for d in col.data:
        if isinstance(d, str):
          packed[2].extend(struct.pack('>%ds' % len(d), bytes(d, 'UTF-8')))
        elif isinstance(d, int):
          packed[2].extend(struct.pack('>Q', d))
      packed[2] = bytes(packed[2])
    self.pack_write_to_file(packed)

  def add_db_to_file2(self, db) -> None:
    self.pack_db2(db)

  def pack_db2(self, db) -> None:
    dbs: Union[bytes, int, None] = None
    ff = open('.lib/db2.db', 'rb+')
    for _ in range(db.nrdbs):
      dbs = ff.read(8)
      print('loop dbs', dbs)
    if dbs:
      print('dbs', dbs)
      dbs = bytes(struct.unpack('>Q', dbs)[0])  # type: ignore
      print('dbs', bytes(int(dbs)))  # struct.unpack('>Q', dbs))
      dbs += bytes(1)
      print('dbs', dbs)
      db.nrdb = dbs
    else:
      dbs = 1
    packed: List[Union[bytes, None]] = [None] * 6
    packed[0] = struct.pack('>Q', dbs)
    packed[1] = struct.pack('>Q', dbs)
    # packed[2] = struct.pack('>%ds' % len(db.dbname), bytes(db.dbname, 'UTF-8'))
    # packed[3] = struct.pack('>Q', db.nrtbl)
    # packed[4] = ','.join(db.tblnames).encode('UTF-8')
    # packed[5] = struct.pack('>%ds' % len(db.fn), bytes(db.fn, 'UTF-8'))
    self.pack_write_to_file(packed)

  def add_table_to_db(self, tbl) -> None:
    self.pack_tbl(tbl)

  def add_row_to_table(self, col) -> None:
    self.pack_row(col)

  def delete_db_from_file(self) -> None:
    pass

  def delete_table_from_db(self) -> None:
    pass

  def delete_row_from_table(self) -> None:
    pass

  def modify_db(self) -> None:
    pass

  def modify_table(self) -> None:
    pass

  def modify_row(self) -> None:
    pass

if __name__ == '__main__':
  print('DB')
  r1 = Row(2, 0, [66, 55, 'stuff', 'm0reStUFf', 1234667])
  t1 = Table(3, 0, ['tb1', 'tb2', 'tb3', 'tb4'], r1)
  d1 = Db(6, 1, 'db1', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr', t1)
  d2 = Db(6, 2, 'db2', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr', t1)
  d3 = Db(6, 3, 'db3', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr', t1)
  d4 = Db(6, 4, 'db4', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr', t1)
  d5 = Db(6, 5, 'db5', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr', t1)
  d6 = Db('db6', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr', t1)
  print(d1, d2, d3, d4, d5, d6, t1)

  db = LotordbFile()
  db.create_db_file('.lib/db1.db')
  db.add_db_to_file(d1)
  db.add_db_to_file(d2)
  db.add_db_to_file(d3)
  db.add_db_to_file(d4)
  db.add_db_to_file(d5)
  db.add_db_to_file(d6)
  db.add_table_to_db(t1)
  db.add_row_to_table(r1)

  #db.read_header_from_file('.lib/db1.db')
  db.close_file()
  """
"""
  r1 = Row([66, 55, 'stuff', 'm0reStUFf', 1234667])
  t1 = Table(['tb1', 'tb2', 'tb3', 'tb4'], r1)
  d6 = Db('db6', ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr', t1)
  db1 = LotordbFile()
  db1.create_db_file('.lib/db2.db')
  """
"""
  #db1.add_db_to_file2(d6)
  pp = struct.pack('>Q', 1)# "1".encode('UTF-8'))
  db1.f.write(pp)
  db1.close_file()
  db1.f = open('.lib/db2.db', 'rb+')
  dat = db1.f.read(8)
  print("d", dat)
  dat = struct.unpack('>Q', dat)[0]
  print("d", dat)
  dat += 1
  pp = struct.pack('>Q', dat)
  db1.f.seek(0)
  db1.f.write(pp)
  db1.f.write(b'abc123123123')
  db1.close_file()
  """
"""
  db1.f = open('.lib/db2.db', 'rb+')
  dat = db1.f.read(8)
  print('d', dat)
  if dat:
    dat = (struct.unpack('>%ds' % 8, dat))
    print('d', dat)
    dat = bytes(int(dat[0]))
    dat += bytes(1)
  else:
    dat = bytes(1)
  pp = struct.pack('>%ds' % 8, str(dat).zfill(8).encode('UTF-8'))
  db1.f.seek(0)
  db1.f.write(pp)

  db1.f.seek(0)
  for i in range(int(dat)):
    db1.f.seek((i + 1) * 8)
    p = struct.pack('>%ds' % 8, str(i + 1).zfill(8).encode('UTF-8'))
    db1.f.write(p)
    print(i + 1, p, len(str(i + 1)))
    # For Look for tables
  db1.close_file()
  """

""" 2nd plan
db header file structure
  header row1: number of databases, [db nr, number of tables]
  header row2: [table nr, numbers of collumns]
  header row2: database name, table names...
  header row3: tablename, collumns

db data file structure
  dbnr, tablenr, rownr, data
  (modified row, move to bottom of file? save rownr in header?)

"""
""" example2:
4, 0,5 1,2 2,7 3,3
0,4, 1,7, 2,2, 3,9, 4,88, 0,22, 1,44
db0, db0_tb0, db0_tb1, db0_tb2, db0_tb3, db0_tb4, db1, db1_tb0, db1_tb1, db3...
db0_tb0_c0, db0_tb0_c1, db1_tb0_c0, db1_tb0_c1
"""

""" 1st plan
db file structure:
  header row1: number of databases
  header row2: database names, commaseparated

  each db(separate files?):
    header row1: number of tables
    header row2: table names, commaseparated
      table header row1: number of collumns
      table header row2: names
      table header row3: types
        table data


data always compressed?
"""

""" example:
15
DB1,DB2,DB3,DB4...
DB1:4
DB1:db1_tb1,db1_tb2,db1_tb3
DB1_db1_tb1:19
DB1_db1_tb1:tb1_1,tb1_2,tb1_3...
DB1_db1_tb1:str,int,bool,str,str,bool,binary
DB1_db1_tb1_tb1_1:"stuff1",4,true,"bla","blah",...
DB1_db1_tb1_tb1_2:"stuff2",4,true,"bla","blah",...
DB1_db1_tb1_tb1_3:"stuff3",4,true,"bla","blah",...
"""
