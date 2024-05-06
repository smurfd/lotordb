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


def test_lotordb_table_list():
  time.sleep(0.1)
  t = time.perf_counter()
  context: List = [123] * 1234  # 100000025
  tables = Tables('.lib/db2')
  ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db2.dbindex')
  dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
  index: DbIndex = tables.init_index(ind)
  data = tables.init_data(dad, index)  # 500mb
  if isinstance(index, DbIndex):
    tables.get_index(index)
    tables.write_index(index)
    if isinstance(data, list):
      tables.write_data(index, data)
      index2 = tables.read_index()
      data2 = tables.read_data(index)
      if isinstance(index2, DbIndex):
        tables.get_data(index2, data2)
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_hash():
  t = time.perf_counter()
  has = Hash('smurfd').get()
  assert has == hashlib.sha3_512('smurfd'.encode('UTF-8')).hexdigest()
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_cbc():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = [i for i in range(ord('a'), ord('q'))]
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = cipher.encrypt_cbc(plain)
  ina = cipher.decrypt_cbc(out)
  assert plain == ina
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_cfb():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = [i for i in range(ord('a'), ord('q'))]
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = cipher.encrypt_cfb(plain)
  ina = cipher.decrypt_cfb(out)
  assert plain == ina
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_bytes():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = 'sometextiwanttoX'.encode('utf-8')
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = cipher.encrypt_cbc(plain)
  ina = cipher.decrypt_cbc(out)
  assert plain == bytearray(ina)
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_string():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = 'sometextiwanttoX'
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = cipher.encrypt_cbc(plain)
  ina = cipher.decrypt_cbc(out)
  if isinstance(ina, str):
    assert plain == ina.decode('UTF-8')
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_pad():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  plain = [i for i in range(ord('b'))]
  ina, out = [0] * 16, [0] * 16
  plain *= 100  # big "text" to encrypt / decrypt
  out = cipher.encrypt_cbc(plain)  # type: ignore
  ina = cipher.decrypt_cbc(out)  # type: ignore
  assert plain == ina
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_list():
  t = time.perf_counter()
  index, data = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex'), DbData(1, 1, 1, 1, 1, 1, [123] * 1234)
  var: List = [index.index, index.dbindex, index.database, index.table, index.row, index.col, index.segments, index.seek]
  index_bytearr = bytearray(c for c in var)
  index_bytearr.extend(map(ord, index.file.ljust(255, ' ')))  # type: ignore
  cip = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  index_encrypted = cip.encrypt_index(index_bytearr)
  segmented_data = cip.segment_data(index, data)
  index_decr = cip.decrypt_index(index_encrypted)
  encrypted_data = cip.encrypt_list_data(segmented_data)
  data_list = cip.decrypt_list_data(encrypted_data)
  decr_data = cip.get_decrypted_data(data_list)
  assert decr_data[0].data == [123] * 506
  assert decr_data[1].data == [123] * 506
  assert decr_data[2].data == [123] * (1234 - 506 - 506) + [0] * (506 - (1234 - 506 - 506))
  assert index_decr == DbIndex(*[1, 1, 1, 1, 1, 1, 1, 0], '.lib/db1.dbindex'.ljust(255, ' '))
  print('time {:.4f}'.format(time.perf_counter() - t))


def test_lotordb_cipher_read_write():
  t = time.perf_counter()
  cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
  dindex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db3.dbindex')
  data = DbData(1, 1, 1, 1, 1, 1, [123] * 1234)
  table = Tables('.lib/db3')
  table.write_index2(dindex, cipher)
  table.write_index2(dindex, cipher)
  table.write_data2(dindex, data, cipher)
  i = table.read_index2(cipher)
  table.read_data2(i, cipher)
  print('time {:.4f}'.format(time.perf_counter() - t))


if __name__ == '__main__':
  print('OK')
