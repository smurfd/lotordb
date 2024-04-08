#!/usr/bin/env python3
import threading, socket, ssl
from lotordb.keys import Keys
from lotordb.tables import Tables, DbIndex, DbData
from typing import Union, Self, List
import sys


class Client(threading.Thread):
  def __init__(self, dbhost: str, dbport: int, dbmaster: bool = True, dbnode: int = 0, dbtype: Union[bool, str] = False) -> None:
    threading.Thread.__init__(self, group=None)
    self.client = Union[None, Client]
    self.event = threading.Event()
    self.host = dbhost
    self.port = dbport
    self.sock = None
    self.type = dbtype
    self.key: Union[None, Keys] = None
    self.tables: Union[None, Tables] = None
    self.thread = threading.Thread()

  def run(self) -> None:
    try:
      self.thread.start()
      self.connect()
      if self.type == 'key' and self.key:  # key value client
        self.key.send_key(self.sock, self.key.get_key())
      elif self.type == 'table' and self.tables and self.sock:  # database client
        self.tables.send_index(self.sock, self.tables.index)
        self.tables.send_data(self.sock, self.tables.data)
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
    if self.sock:
      self.sock.close()

  def send(self, data: bytes) -> None:
    if self.sock:
      self.sock.send(data)

  def receive(self, data: bytes) -> None:
    if self.sock:
      self.sock.recv(data)

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
