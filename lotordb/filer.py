#!/usr/bin/env python3
import binascii


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
    return self.open_file(filename, 'a+')

  def modify_nr_from_file(self, nr, mnr) -> bytes:
    dbs = binascii.unhexlify(nr.rstrip())
    dbsint = int.from_bytes(dbs, 'big') + mnr
    return binascii.hexlify(dbsint.to_bytes(len(dbs), 'big'))

  def add_db_to_file(self, f, fn, db_name) -> None:
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
  db = LotordbFiler()
  db_file = db.create_db_file('.lib/db1.db')
  db.add_db_to_file(db_file, '.lib/db1.db', 'db1')
  db.add_db_to_file(db_file, '.lib/db1.db', 'db2')
  db.add_db_to_file(db_file, '.lib/db1.db', 'db3')
  db.close_file(db_file)

"""

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
