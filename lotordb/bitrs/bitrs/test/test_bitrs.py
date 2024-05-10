#!/usr/bin/env python3
from bitrs.bitrs import Bitrs
from typing import Any
import time


# dummy function
def logr(x, y) -> Any:
  ret = []
  for _ in range(100000):
    ret = x * y
  return ret


def test_bitrs() -> None:
  t = time.perf_counter()
  b = Bitrs(logr, 1337, 7331)
  for _ in range(10):
    b.start()
  print(b.stop())
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
