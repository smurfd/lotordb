#!/usr/bin/env python3
import threading, signal, socket, ssl
from lotordb.vars import DbIndex, DbData
from lotordb.cipher import Cipher
from lotordb.tables import Tables
from lotordb.keys import Keys
from typing import Union, Any
import sys, secrets


# TODO: Set self.tables instead of using Tables()
# TODO: Check if received index/data is bytes, then dont encode
# TODO: write_data2, already_encoded param, to just write data to disk
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
      self.recv()
      self.close()
    elif self.type == 'key':  # key value server
      while not self.event.is_set():
        self.listen()
        try:
          k, v, s, h = Keys().recv_key(self.ssl_sock)
          print('serv', k, v, s, h)
          if k and v and s:
            kvs = Keys(k, v, s)
            kvs.write_key() if h.decode('UTF-8') == kvs.get_key_value_store()[3] else print('Will not write key, hash does not match!')
        finally:
          self.close()
    elif self.type == 'table' and self.test:  # database server, hack so you can run server in tests
      self.listen()
      cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
      table = Tables('.lib/db1')
      table.set_ssl_socket(self.ssl_sock)
      index = table.recv_index()
      data = table.recv_data()
      ind = DbIndex(*(int.from_bytes(index[i]) for i in range(8)), index[8].decode('UTF-8'))  # type: ignore
      dat = DbData(*(int.from_bytes(data[i]) for i in range(6)), data[6])  # type: ignore
      table.write_index2(ind, cipher)
      table.write_data2(ind, dat, cipher)
      table.close_file()
      self.close()
    elif self.type == 'table':  # database server
      cipher = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
      while not self.event.is_set():
        self.listen()
        try:
          table = Tables('.lib/db1')
          table.set_ssl_socket(self.ssl_sock)
          index = table.recv_index()
          data = table.recv_data()
          ind = DbIndex(*(int.from_bytes(index[i]) for i in range(8)), index[8].decode('UTF-8'))  # type: ignore
          dat = DbData(*(int.from_bytes(data[i]) for i in range(6)), data[6])  # type: ignore
          table.write_index2(ind, cipher)
          table.write_data2(ind, dat, cipher)
          table.close_file()
        finally:
          self.close()
    elif self.type == 'tablesecure' and self.test:  # database server, hack so you can run server in tests
      table = Tables('.lib/db8')
      self.listen()
      table.set_ssl_socket(self.ssl_sock)
      index = table.recv_encrypted_index()
      data = table.recv_encrypted_data()
      table.write_index3(index)
      table.write_data3(data)
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


if __name__ == '__main__':
  print('Server')
  Server('127.0.0.1', 1337, dbtype='table') if sys.argv[1] and sys.argv[1] == 'table' else Server('127.0.0.1', 1337, dbtype='key')
