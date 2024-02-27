#!/usr/bin/env python3
from lotordb.lotordb import Lotordb
from lotordb.lotordb_server import LotordbServer
from lotordb.lotordb_client import LotordbClient
import time


def test_lotordb() -> None:
  t = time.perf_counter()
  Lotordb()
  LotordbServer('127.0.0.1', 1337)
  LotordbClient('127.0.0.1', 1337)
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
