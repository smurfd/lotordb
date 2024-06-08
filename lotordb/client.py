#!/usr/bin/env python3
import threading, socket, ssl, sys
from typing import Union, Self, List, Any
from lotordb.tables import Tables, DbIndex, DbData
from lotordb.keys import Keys


class Cli:
  def client_key(self):
    for i in range(5):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.load_verify_locations('.lib/selfsigned.cert')
      ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      ssl_sock.connect(('localhost', 7331))
      k = Keys(k='1122', v='abc', s='/tmp')
      k.set_sock(ssl_sock).send_key(k.get_key_value_store())
      ssl_sock.close()

  def client_table(self):
    for i in range(5):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.load_verify_locations('.lib/selfsigned.cert')
      ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      ssl_sock.connect(('localhost', 7332))

      table = Tables()
      context: List = [123] * 123
      ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db9.dbindex')
      dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
      i = table.index_to_bytearray_encrypt(ind)
      d = table.data_to_bytearray_encrypt(dad, ind)
      table.send(ssl_sock, i, d)
      ssl_sock.close()

  def client_key_test(self):
    for i in range(5):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.load_verify_locations('.lib/selfsigned.cert')
      ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      ssl_sock.connect(('localhost', 7333))
      k = Keys(k='1122', v='abctest', s='/tmp')
      k.set_sock(ssl_sock).send_key(k.get_key_value_store())
      ssl_sock.close()

  def client_table_test(self):
    for i in range(5):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.load_verify_locations('.lib/selfsigned.cert')
      ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      ssl_sock.connect(('localhost', 7334))

      table = Tables()
      table.set_sock(ssl_sock)
      context: List = [123] * 123
      ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db9.dbindex')
      dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
      i = table.index_to_bytearray_encrypt(ind)
      d = table.data_to_bytearray_encrypt(dad, ind)
      table.send(ssl_sock, i, d)
      ssl_sock.close()


class Client(threading.Thread):
  def __init__(self, dbhost: str, dbport: int, dbmaster: bool = True, dbnode: int = 0, dbtype: Union[bool, str] = False) -> None:
    threading.Thread.__init__(self, group=None)
    self.client = Union[None, Client]
    self.event = threading.Event()
    self.host: str = dbhost
    self.port: int = dbport
    self.sock: Union[socket.socket, Any] = None
    self.type: Union[bool, str] = dbtype
    self.key: Union[None, Keys] = None
    self.tables: Union[None, Tables] = None
    self.thread = threading.Thread()

  def run(self) -> None:
    try:
      self.thread.start()
      self.connect()
      if self.type == 'key' and self.key:  # key value client
        self.key.set_sock(self.sock).send_key(self.key.get_key_value_store())
      elif self.type == 'tablesecure' and self.tables:
        self.tables.set_sock(self.sock)
        self.tables.send_encrypted_index(self.tables.index)
        self.tables.send_encrypted_data(self.tables.data)
      self.close()
      self.thread.join(timeout=0.1)
    except Exception as e:
      print('Could not connect to server', e)

  def connect(self):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('.lib/selfsigned.cert')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    self.sock = context.wrap_socket(sock, server_hostname=socket.gethostbyaddr(self.host)[0])  # Get hostname from ip
    self.sock.connect((self.host, self.port))
    return self.sock

  def close(self) -> None:
    self.sock.close() if self.sock else None

  def send(self, data: bytes) -> None:
    self.sock.send(data) if self.sock else None

  def receive(self, data: int) -> None:
    self.sock.recv(data) if self.sock else None

  def set_key(self, key: Union[None, Keys]) -> Self:
    self.key = key
    return self

  def set_tables(self, tables: Union[None, Tables]) -> Self:
    self.tables = tables
    return self


if __name__ == '__main__':
  print('Client')
  context: List = [123] * 123456
  if sys.argv[1] == 'tablesecure':
    tables = Tables()
    ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db10.dbindex')
    dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
    i = tables.index_to_bytearray_encrypt(ind)
    d = tables.data_to_bytearray_encrypt(dad, ind)
    tables.set_index_data(i, d)
    Client('127.0.0.1', 1337, dbtype='tablesecure').set_tables(tables).start()
  elif sys.argv[1] == 'key':
    Client('127.0.0.1', 1337, dbtype='key').set_key(Keys(k='1122', v='abc', s='/tmp')).start()
