#!/usr/bin/env python3
from lotordb.bitrs.bitrs.bitrs import Bitrs
from lotordb.tables import Tables
from lotordb.vars import DbIndex, DbData
from lotordb.cipher import Cipher
from typing import List
import time, secrets


def test_without_bitrs():
  time.sleep(0.1)
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  context: List = [123] * 1337  # 100000025
  tables = Tables('.lib/db6')
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db6.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  tables.write_index2(ind, cipher)
  tables.write_data2(ind, dad, cipher)
  tables.read_index2(ind, cipher)
  tables.read_data2(ind, cipher)
  print('time {:.4f}'.format(time.perf_counter() - t))


def _with_bitrs():
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  context: List = [123] * 1337  # 100000025
  tables = Tables('.lib/db7')
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db7.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  tables.write_index2(ind, cipher)
  tables.write_data2(ind, dad, cipher)
  tables.read_index2(ind, cipher)
  return tables.read_data2(ind, cipher)


def test_with_bitrs():
  time.sleep(0.1)
  t = time.perf_counter()
  b = Bitrs(_with_bitrs)
  b.start()
  print('time {:.4f}'.format(time.perf_counter() - t))
  a = b.stop()
  print('time {:.4f}'.format(time.perf_counter() - t))
  print(a)


if __name__ == '__main__':
  test_without_bitrs()
  test_with_bitrs()
