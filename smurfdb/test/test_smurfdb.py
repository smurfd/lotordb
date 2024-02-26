#!/usr/bin/env python3
from smurfdb.smurfdb import Smurfdb
import time


def test_smurfdb() -> None:
  t = time.perf_counter()
  Smurfdb()
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
