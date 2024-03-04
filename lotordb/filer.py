#!/usr/bin/env python3
import binascii, struct
from dataclasses import dataclass
from typing import List, Union


@dataclass
class Db:
  nrdbs: int
  nrdb: int
  dbname: str
  nrtbl: int
  tblnames: list[str]
  fn: str


class LotordbFiler:
  def __init__(self) -> None:
    pass

  def open_file(self, filename, rwd) -> str:
    return open(filename, rwd)

  def close_file(self, f) -> None:
    if not f.closed:
      f.close()

  def read_header_from_file(self) -> None:
    pass

  def read_dbheader_from_file(self) -> None:
    pass

  def read_table_header_from_file(self) -> None:
    pass

  def read_data_row_from_file(self) -> None:
    pass

  def create_db_file(self, filename) -> str:
    return self.open_file(filename, 'ab+')

  def modify_nr_from_file(self, nr, mnr) -> bytes:
    dbs = binascii.unhexlify(nr.rstrip())
    dbsint = int.from_bytes(dbs, 'big') + mnr
    return binascii.hexlify(dbsint.to_bytes(len(dbs), 'big'))

  def add_db_to_file(self, f, fn, db_name) -> None:
    d4 = Db(6, 4, 'db4', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr')
    self.pack_db(f, d4)

  """
  header row1: number of databases, [db nr, number of tables]
  header row2: [table nr, numbers of collumns]
  header row2: database name, table names...
  header row3: tablename, collumns"""

  def pack_db(self, f, db) -> None:
    p: List[Union[bytes, None]] = [None] * 6
    p[0] = struct.pack('>Q', db.nrdbs)
    p[1] = struct.pack('>Q', db.nrdb)
    p[2] = struct.pack('>%ds' % len(db.dbname), bytes(db.dbname, 'UTF-8'))
    p[3] = struct.pack('>Q', db.nrtbl)
    p[4] = ','.join(db.tblnames).encode('UTF-8')
    p[5] = struct.pack('>%ds' % len(db.fn), bytes(db.fn, 'UTF-8'))
    print('P=', p)
    for pp in p:
      f.write(pp)

  def add_db_to_file_(self, f, fn, db_name) -> None:
    self.close_file(f)
    f = open(fn, 'rb+')
    databases = f.readline()
    print(databases)
    if not databases:
      print('db empty, creating header')
      f.write(b'00\n')
      databases = b'00'
    f.seek(0)
    databases = self.modify_nr_from_file(databases, 1)
    f.write(databases + '\n'.encode())
    f.readline()
    f.readline()
    f.write((db_name + ',').encode())

  def add_table_to_db(self, f, db_name, tbl_name, tbl_columns, tbl_types) -> None:
    pass

  def add_row_to_table(self, f, db_name, tbl_name, row) -> None:
    pass

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
  d1 = Db(6, 1, 'db1', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr')
  d2 = Db(6, 2, 'db2', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr')
  d3 = Db(6, 3, 'db3', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr')
  d4 = Db(6, 4, 'db4', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr')
  d5 = Db(6, 5, 'db5', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr')
  d6 = Db(6, 6, 'db6', 3, ['tb1', 'tb2', 'tb3'], '.lib/db.dbhdr')
  print(d1, d2, d3, d4, d5, d6)
  # pack_db(d1)
  # exit()

  db = LotordbFiler()
  db_file = db.create_db_file('.lib/db1.db')
  db.add_db_to_file(db_file, '.lib/db1.db', 'db1')
  db.add_db_to_file(db_file, '.lib/db1.db', 'db2')
  db.add_db_to_file(db_file, '.lib/db1.db', 'db3')
  db.close_file(db_file)


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
