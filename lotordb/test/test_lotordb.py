#!/usr/bin/env python3
from lotordb.server import Server, Handler
from lotordb.vars import DbIndex, DbData
from lotordb.tables import Tables
from lotordb.client import Client
from lotordb.cipher import Cipher
from lotordb.hash import Hash
from typing import List
import time, hashlib, secrets


def test_lotordb_hash():
  t = time.perf_counter()
  has = Hash('smurfd').get()
  assert has == hashlib.sha3_512('smurfd'.encode('UTF-8')).hexdigest()
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_cbc():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = [i for i in range(ord('a'), ord('q'))] * 100
  ina, out = [0] * 16, [0] * 16
  out = cipher.encrypt_cbc(plain)
  ina = cipher.decrypt_cbc(out)
  assert plain == ina
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_cfb():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = [i for i in range(ord('a'), ord('q'))] * 100
  ina, out = [0] * 16, [0] * 16
  out = cipher.encrypt_cfb(plain)
  ina = cipher.decrypt_cfb(out)
  assert plain == ina
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_bytes():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = 'sometextiwanttoX'.encode('utf-8') * 100
  ina, out = [0] * 16, [0] * 16
  out = cipher.encrypt_cbc(plain)
  ina = cipher.decrypt_cbc(out)
  assert plain == bytes(ina)
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_string():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = 'sometextiwanttoX' * 100
  ina, out = [0] * 16, [0] * 16
  out = cipher.encrypt_cbc(plain)
  ina = cipher.decrypt_cbc(out)
  if isinstance(ina, str):
    assert plain == ina.decode('UTF-8')
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_pad():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = [i for i in range(ord('b'))] * 100
  ina, out = [0] * 16, [0] * 16
  out = cipher.encrypt_cbc(plain)  # type: ignore
  ina = cipher.decrypt_cbc(out)  # type: ignore
  assert plain == ina
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_key_client_server():
  t = time.perf_counter()
  Server.Listener('localhost', 7335, Handler.HandlerKey, test=True)
  Client().client_key('localhost', 7335)
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_table_client_server():
  t = time.perf_counter()
  Server.Listener('localhost', 7336, Handler.HandlerTable, test=True)
  Client().client_table('localhost', 7336)
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_table_read_write():
  t = time.perf_counter()
  tables = Tables('.lib/db37')
  context: List = [1234] * 123456
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db10.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  tables.write_index(tables.index_to_bytearray_encrypt(ind))
  tables.write_data(tables.data_to_bytearray_encrypt_segment(dad, ind))
  tables.read_index()
  tables.read_data()
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_table_encrypt_decrypt():
  t = time.perf_counter()
  tables = Tables('.lib/db38')
  context: List = [1234] * 123456
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db10.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  tables.decrypt_bytearray_to_index(tables.index_to_bytearray_encrypt(ind))
  tables.decrypt_bytearray_to_data_segmented(tables.data_to_bytearray_encrypt_segment(dad, ind))
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
