#!/usr/bin/env python3
import threading, signal, socket, ssl, sys
from lotordb.tables import Tables
from lotordb.keys import Keys
from typing import Union, Any, Self


class Server(threading.Thread):
  class ServiceExit(Exception):
    pass

  def __init__(self, dbhost: str, dbport: int, dbmaster: bool = True, dbnode: int = 0, test: bool = False, dbtype: Union[bool, str] = False) -> None:
    signal.signal(signal.SIGTERM, self.service_shutdown)
    signal.signal(signal.SIGINT, self.service_shutdown)
    threading.Thread.__init__(self)
    self.host: str = dbhost
    self.port: int = dbport
    self.sock: Union[socket.socket, Any] = None
    self.ssl_sock: Union[socket.socket, Any] = None
    self.context: Union[ssl.SSLContext, Any] = None
    self.event = threading.Event()
    self.test: bool = test
    self.type: Union[bool, str] = dbtype
    self.tables: Union[None, Tables] = None
    self.thread = threading.Thread()
    try:
      self.thread.start()
      self.start()
    except self.ServiceExit:
      self.event.set()
      self.thread.join()
      self.close()

  def __exit__(self, exc_type, exc_value, traceback) -> None:
    self.close()

  def close(self) -> None:
    self.ssl_sock.close()

  def run(self) -> None:
    self.init_server_socket()
    if self.type == 'key' and self.test:  # key value server, hack so you can run server in tests
      self.listen()
      Keys().set_sock(self.ssl_sock).recv_key(4096)
      self.close()
    elif self.type == 'key':  # key value server
      while not self.event.is_set():
        self.listen()
        try:
          k, v, s, h = Keys().set_sock(self.ssl_sock).recv_key()
          print('serv', k, v, s, h)
          if k and v and s:
            kvs = Keys(k, v, s)
            kvs.write_key() if h.decode('UTF-8') == kvs.get_key_value_store()[3] else print('Will not write key, hash does not match!')
        finally:
          self.close()
    elif self.type == 'tablesecure' and self.test and self.tables:  # database server, hack so you can run server in tests
      self.listen()
      self.tables.set_ssl_socket(self.ssl_sock)
      index = self.tables.recv_encrypted_index()
      data = self.tables.recv_encrypted_data()
      self.tables.write_index(index)
      self.tables.write_data(data)
      self.close()
    elif self.type == 'tablesecure' and self.tables:  # database server
      while not self.event.is_set():
        self.listen()
        try:
          self.tables.set_ssl_socket(self.ssl_sock)
          index = self.tables.recv_encrypted_index()
          data = self.tables.recv_encrypted_data()
          self.tables.write_index(index)
          self.tables.write_data(data)
          self.tables.close_file()
        finally:
          self.close()

  def init_server_socket(self) -> None:
    self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    self.context.load_cert_chain('.lib/selfsigned.cert', '.lib/selfsigned.key')
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    self.sock.bind((self.host, self.port))
    self.sock.listen(10)

  def listen(self) -> None:
    s, _ = self.sock.accept()
    self.ssl_sock = self.context.wrap_socket(s, server_side=True)

  def recv(self) -> bytes:
    return self.ssl_sock.recv(4096)

  def service_shutdown(self, signum, frame) -> None:
    raise self.ServiceExit

  def set_tables(self, tables: Union[None, Tables]) -> Self:
    self.tables = tables
    return self


if __name__ == '__main__':
  print('Server')
  tables = Tables('.lib/db10')
  if sys.argv[1] == 'tablesecure':
    Server('127.0.0.1', 1337, dbtype='tablesecure').set_tables(tables)
  elif sys.argv[1] == 'key':
    Server('127.0.0.1', 1337, dbtype='key')
