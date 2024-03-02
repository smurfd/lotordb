#!/usr/bin/env python3
from lotordb.lotordb import Lotordb
from lotordb.lotordb_server import LotordbServer, LotordbServerRunnable
from lotordb.lotordb_client import LotordbClient
import time


def test_lotordb() -> None:
  t = time.perf_counter()
  Lotordb()
  LotordbServer()
  LotordbServerRunnable(test=True)
  client = LotordbClient('127.0.0.1', 1337)
  client.start()
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
