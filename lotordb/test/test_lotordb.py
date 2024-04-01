#!/usr/bin/env python3
from lotordb.server import ServerRunnable
from lotordb.client import ClientRunnable
import time


def test_lotordb_key() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  ServerRunnable('127.0.0.1', 1337, test=True, dbtype='key')
  time.sleep(0.1)
  ClientRunnable('127.0.0.1', 1337, dbtype='key')
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_db() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  ServerRunnable('127.0.0.1', 1337, test=True, dbtype='db')
  time.sleep(0.1)
  ClientRunnable('127.0.0.1', 1337, dbtype='db')
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
