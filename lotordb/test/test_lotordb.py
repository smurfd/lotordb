#!/usr/bin/env python3
from lotordb.server import Server
from lotordb.client import Client
from lotordb.tables import Tables, DbIndex, DbData
from lotordb.keys import Keys
from typing import List
import time


def test_lotordb_key() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  Server('127.0.0.1', 1337, test=True, dbtype='key')
  time.sleep(0.1)
  Client('127.0.0.1', 1337, dbtype='key').set_key(Keys(k='1122', v='abc', s='/tmp')).start()
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_table() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  Server('127.0.0.1', 1337, test=True, dbtype='db')
  time.sleep(0.1)
  data: List = [123] * 125
  index = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  ddata = DbData(1, 1, 1, 1, 1, 1, data)
  f = Tables('.lib/db1')
  a = f.init_index(*index)
  b = f.init_data(*ddata, a)[0]  # type: ignore
  f.set_index_data(a, b)
  Client('127.0.0.1', 1337, dbtype='db').set_tables(f).start()
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
