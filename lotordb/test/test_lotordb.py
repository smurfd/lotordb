#!/usr/bin/env python3
from lotordb.server import ServerRunnable
from lotordb.client import ClientRunnable
import time


def test_lotordb() -> None:
  t = time.perf_counter()
  ServerRunnable(test=True)
  ClientRunnable()
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
