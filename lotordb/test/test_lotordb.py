#!/usr/bin/env python3
from lotordb.server import ServerRunnable
from lotordb.client import ClientRunnable
import time


def test_lotordb_key() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  ServerRunnable('127.0.0.1', 7335, test=True, dbtype='key')
  ClientRunnable('127.0.0.1', 7335, dbtype='key')
  print('time {:.4f}'.format(time.perf_counter() - t))


# def test_lotordb_db() -> None:
#  time.sleep(0.1)
#  t = time.perf_counter()
#  ServerRunnable('127.0.0.1', 7331, test=True, dbtype='db')
#  ClientRunnable('127.0.0.1', 7331, dbtype='db')
#  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
