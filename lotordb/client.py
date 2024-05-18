#!/usr/bin/env python3
import threading, socket, ssl
from lotordb.keys import Keys
from lotordb.tables import Tables, DbIndex, DbData
from typing import Union, Self, List, Any
import sys


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
        self.key.send_key(self.sock, self.key.get_key_value_store())
      elif self.type == 'table' and self.tables and self.sock and self.tables.index and self.tables.data:  # database client
        self.tables.set_ssl_socket(self.sock)
        self.tables.send_index(self.tables.index)
        self.tables.send_data(self.tables.data)
      elif self.type == 'tablesecure' and self.tables:
        self.tables.set_ssl_socket(self.sock)
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
  if sys.argv[1] and sys.argv[1] == 'table':
    context: List = [123] * 125
    dindex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
    ddata = DbData(1, 1, 1, 1, 1, 1, context)
    table = Tables('.lib/db1')
    index = table.init_index(dindex)
    data = table.init_data(ddata, index)[0]  # type: ignore
    table.set_index_data(index, data)
    Client('127.0.0.1', 1337, dbtype='table').set_tables(table).start()
  else:
    Client('127.0.0.1', 1337, dbtype='key').set_key(Keys(k='1122', v='abc', s='/tmp')).start()
