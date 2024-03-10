#!/usr/bin/env python3
from lotordb.server import LotordbServerRunnable
from lotordb.client import LotordbClientRunnable
import time


def test_lotordb() -> None:
  t = time.perf_counter()
  LotordbServerRunnable(test=True)
  LotordbClientRunnable()
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
