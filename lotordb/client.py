#!/usr/bin/env python3
import threading, socket, ssl, sys
from typing import Union, Self, List, Any
from lotordb.tables import Tables, DbIndex, DbData
from lotordb.keys import Keys


class Client(threading.Thread):
  class Connection:
    def __init__(self, host, port):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.load_verify_locations('.lib/selfsigned.cert')
      self.ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      self.ssl_sock.connect((host, port))

    def get_socket(self):
      return self.ssl_sock

  def __init__(self, dbhost: str = 'localhost', dbport: int = 1337, dbmaster: bool = True, dbnode: int = 0, dbtype: Union[bool, str] = False) -> None:
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

  def client_key(self):
    sock = Client.Connection('localhost', 7331).get_socket()
    k = Keys(k='1122', v='abc', s='/tmp')
    k.set_sock(sock).send_key(k.get_key_value_store())
    sock.close()

  def client_table(self):
    sock = Client.Connection('localhost', 7332).get_socket()
    table = Tables()
    context: List = [123] * 123
    ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db9.dbindex')
    dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
    table.send(sock, table.index_to_bytearray_encrypt(ind), table.data_to_bytearray_encrypt(dad, ind))
    sock.close()

  def client_key_test(self):
    sock = Client.Connection('localhost', 7333).get_socket()
    k = Keys(k='1123', v='abctest', s='/tmp')
    k.set_sock(sock).send_key(k.get_key_value_store())
    sock.close()

  def client_table_test(self):
    sock = Client.Connection('localhost', 7334).get_socket()
    table = Tables()
    table.set_sock(sock)
    context: List = [123] * 123
    ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db9.dbindex')
    dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
    table.send(sock, table.index_to_bytearray_encrypt(ind), table.data_to_bytearray_encrypt(dad, ind))
    sock.close()


if __name__ == '__main__':
  print('Client')
  if sys.argv[1] == 'table':
    Client().client_table()
  elif sys.argv[1] == 'key':
    Client().client_key()
