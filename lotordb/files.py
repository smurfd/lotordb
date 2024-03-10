#!/usr/bin/env python3
import binascii, struct
from dataclasses import dataclass
from typing import List, Union, Any, BinaryIO


@dataclass
class Row:
  nrrows: int  # number of rows
  nrrow: int  # number for this row
  data: list[Any]  # data for a row


@dataclass
class Table:
  nrtbls: int  # number of tables
  nrtbl: int  # this tables nr
  colnames: list[str]  # column names
  r: Row


@dataclass
class Db:
  nrdbs: int  # total number of databases
  nrdb: int  # this database number
  dbname: str  # database name
  nrtbl: int  # number of tables in database
  tblnames: list[str]  # table names
  fn: str  # database filename
  tbl: Table


class LotordbFiler:
  def __init__(self) -> None:
    self.f: Union[None, BinaryIO] = None

  def open_file(self, filename, rwd) -> None:
    self.f = open(filename, rwd)

  def close_file(self) -> None:
    if self.f and not self.f.closed:
      self.f.close()

  def read_header_from_file(self) -> None:
    pass

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
    # r1 = Row(2, 0, [66, 55, 'stuff', 'm0reStUFf', 1234667])
    # t1 = Table(3, 0, ['tb1', 'tb2', 'tb3', 'tb4'], r1)
    self.pack_db(db)

  def pack_write_to_file(self, packed) -> None:
    if self.f:
      [self.f.write(p) for p in packed]

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
  d6 = Db(6, 6, 'db6', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr', t1)
  print(d1, d2, d3, d4, d5, d6, t1)

  db = LotordbFiler()
  db.create_db_file('.lib/db1.db')
  db.add_db_to_file(d1)
  db.add_db_to_file(d2)
  db.add_db_to_file(d3)
  db.add_db_to_file(d4)
  db.add_db_to_file(d5)
  db.add_db_to_file(d6)
  db.add_table_to_db(t1)
  db.add_row_to_table(r1)
  db.close_file()


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
