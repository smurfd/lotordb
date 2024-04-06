#!/usr/bin/env python3
from lotordb.server import Server
from lotordb.client import Client
from lotordb.files import Files
from lotordb.keys import Keys
from typing import List
import time


def test_lotordb_key() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  Server('127.0.0.1', 1337, test=True, dbtype='key')
  time.sleep(0.1)
  cli = Client('127.0.0.1', 1337, dbtype='key')
  cli.set_key(Keys(k='1122', v='abc', s='/tmp'))
  cli.start()
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_db() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  Server('127.0.0.1', 1337, test=True, dbtype='db')
  time.sleep(0.1)
  data: List = [123] * 125
  f = Files('.lib/db1')
  a = f.init_index(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  b = f.init_data(1, 1, 1, 1, 1, 1, data, a)[0]  # type: ignore
  cli = Client('127.0.0.1', 1337, dbtype='db')
  f.set_index_data(a, b)
  cli.set_files(f)
  cli.start()
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
