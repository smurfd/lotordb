#!/usr/bin/env python3
from lotordb.server import LotordbServer, LotordbServerRunnable
from lotordb.client import LotordbClient

# from lotordb.files import LotordbFile
import time


def test_lotordb() -> None:
  t = time.perf_counter()
  # LotordbFile()
  LotordbServer()
  LotordbServerRunnable(test=True)
  client = LotordbClient('127.0.0.1', 1337)
  client.start()
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
