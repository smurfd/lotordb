#!/usr/bin/env python3
from lotordb.bitrs.bitrs.bitrs import Bitrs
from lotordb.vars import DbIndex, DbData
from lotordb.tables import Tables
from typing import List
import time


def test_without_bitrs():
  time.sleep(0.1)
  t = time.perf_counter()
  context: List = [123] * 133731
  tables = Tables('.lib/db6')
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db6.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  i = tables.index_to_bytearray_encrypt(ind)
  d = tables.data_to_bytearray_encrypt(dad, ind)
  tables.write_index(i)
  tables.write_data(d)
  tables.read_index()
  tables.read_data()
  print('time {:.4f}'.format(time.perf_counter() - t))


def _with_bitrs():
  context: List = [123] * 133731
  tables = Tables('.lib/db7')
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db7.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  i = tables.index_to_bytearray_encrypt(ind)
  d = tables.data_to_bytearray_encrypt(dad, ind)
  tables.write_index(i)
  tables.write_data(d)
  tables.read_index()
  return tables.read_data()


def test_with_bitrs():
  time.sleep(0.1)
  t = time.perf_counter()
  b = Bitrs(_with_bitrs)
  b.start()
  print('time {:.4f}'.format(time.perf_counter() - t))
  b.stop()
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('bitrs')
  test_without_bitrs()
  test_with_bitrs()
