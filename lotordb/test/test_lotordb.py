#!/usr/bin/env python3
from lotordb.tables import Tables, DbIndex, DbData
from lotordb.server import Server
from lotordb.client import Client
from lotordb.cipher import Cipher
from lotordb.keys import Keys
from lotordb.hash import Hash
from typing import List
import time, hashlib


def test_lotordb_key() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  Server('127.0.0.1', 1337, test=True, dbtype='key')
  time.sleep(0.1)
  Client('127.0.0.1', 1337, dbtype='key').set_key(Keys(k='1122', v='abc', s='/tmp')).start()
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_table() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  Server('127.0.0.1', 1337, test=True, dbtype='table')
  time.sleep(0.1)
  context: List = [123] * 125
  dindex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
  ddata = DbData(1, 1, 1, 1, 1, 1, context)
  table = Tables('.lib/db1')
  index = table.init_index(dindex)
  data = table.init_data(ddata, index)[0]  # type: ignore
  table.set_index_data(index, data)
  Client('127.0.0.1', 1337, dbtype='table').set_tables(table).start()
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_hash():
  t = time.perf_counter()
  has = Hash('smurfd').get()
  assert has == hashlib.sha3_512('smurfd'.encode('UTF-8')).hexdigest()
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_cbc():
  t = time.perf_counter()
  cipher = Cipher()
  plain = [i for i in range(ord('a'), ord('q'))]
  key = [i for i in range(0x20)]
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = cipher.encrypt_cbc(plain, key, [0xFF for _ in range(16)])
  ina = cipher.decrypt_cbc(out, key, [0xFF for _ in range(16)])
  assert plain == ina
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_cfb():
  t = time.perf_counter()
  cipher = Cipher()
  plain = [i for i in range(ord('a'), ord('q'))]
  key = [i for i in range(0x20)]
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = cipher.encrypt_cfb(plain, key, [0xFF for _ in range(16)])
  ina = cipher.decrypt_cfb(out, key, [0xFF for _ in range(16)])
  assert plain == ina
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_bytes():
  t = time.perf_counter()
  cipher = Cipher()
  plain = 'sometextiwanttoX'.encode('utf-8')
  key = [i for i in range(0x20)]
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = cipher.encrypt_cbc(plain, key, [0xFF for _ in range(16)])
  ina = cipher.decrypt_cbc(out, key, [0xFF for _ in range(16)])
  print(plain)
  print(ina)
  assert plain == ina
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_string():
  t = time.perf_counter()
  cipher = Cipher()
  plain = 'sometextiwanttoX'
  key = [i for i in range(0x20)]
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = cipher.encrypt_cbc(plain, key, [0xFF for _ in range(16)])
  ina = cipher.decrypt_cbc(out, key, [0xFF for _ in range(16)])
  if isinstance(ina, str):
    assert plain == ina.decode('UTF-8')
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
