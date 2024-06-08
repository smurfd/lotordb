#!/usr/bin/env python3
from lotordb.tables import Tables
from lotordb.vars import DbIndex, DbData
from lotordb.server import Server
from lotordb.client import Client
from lotordb.cipher import Cipher
from lotordb.keys import Keys
from lotordb.hash import Hash
from typing import List
import time, hashlib, secrets


def test_lotordb_key() -> None:
  time.sleep(0.1)
  t = time.perf_counter()
  Server('127.0.0.1', 1337, test=True, dbtype='key')
  time.sleep(0.1)
  Client('127.0.0.1', 1337, dbtype='key').set_key(Keys(k='1122', v='abc', s='/tmp')).start()
  print('time {:.4f}'.format(time.perf_counter() - t))


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


def test_lotordb_new_encrypt_decrypt_write_read():
  tables = Tables('.lib/db9')
  Server('127.0.0.1', 1337, test=True, dbtype='tablesecure').set_tables(tables)
  context: List = [123] * 123456
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db9.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  i = tables.index_to_bytearray_encrypt(ind)
  d = tables.data_to_bytearray_encrypt(dad, ind)
  tables.write_index(i)
  tables.write_data(d)
  bi = tables.decrypt_bytearray_to_index(i)
  bd = tables.decrypt_bytearray_to_data(d)
  ri = tables.read_index()
  rd = tables.read_data()
  rbi = tables.decrypt_bytearray_to_index(ri)
  rbd = tables.decrypt_bytearray_to_data(rd)
  tables.set_index_data(i, d)
  Client('127.0.0.1', 1337, dbtype='tablesecure').set_tables(tables).start()
  assert bi == rbi
  assert bd == rbd


def test_lotordb_new_encrypt_decrypt_write_read_segmented():
  tables = Tables('.lib/db10')
  Server('127.0.0.1', 1338, test=True, dbtype='tablesecure').set_tables(tables)
  context: List = [1234] * 123456
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db10.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  i = tables.index_to_bytearray_encrypt(ind)
  d = tables.data_to_bytearray_encrypt_segment(dad, ind)
  tables.write_index(i)
  tables.write_data(d)
  bi = tables.decrypt_bytearray_to_index(i)
  bd = tables.decrypt_bytearray_to_data_segmented(d)
  ri = tables.read_index()
  rd = tables.read_data()
  rbi = tables.decrypt_bytearray_to_index(ri)
  rbd = tables.decrypt_bytearray_to_data_segmented(rd)
  tables.set_index_data(i, d)
  Client('127.0.0.1', 1338, dbtype='tablesecure').set_tables(tables).start()
  assert bi == rbi
  assert bd == rbd


def test_lotordb_newprototype():
  Server().server_key_test()
  Client().client_key_test()

  Server().server_table_test()
  Client().client_table_test()


if __name__ == '__main__':
  print('OK')
