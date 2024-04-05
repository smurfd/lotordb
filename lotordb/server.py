#!/usr/bin/env python3
import threading, signal, socket, ssl
from lotordb.keys import Keys
from lotordb.files import Files
from typing import Union, Any


class ServerRunnable(threading.Thread):
  class ServiceExit(Exception):
    pass

  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0, test=False, dbtype=False) -> None:
    signal.signal(signal.SIGTERM, self.service_shutdown)
    signal.signal(signal.SIGINT, self.service_shutdown)
    threading.Thread.__init__(self)
    self.host = dbhost
    self.port = dbport
    self.sock: Union[socket.socket, Any] = None
    self.ssl_sock: Union[socket.socket, Any] = None
    self.context: Union[ssl.SSLContext, Any] = None
    self.event = threading.Event()
    self.test = test
    self.type = dbtype
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
            if h.decode('UTF-8') == kvs.get_key()[3]:  # Check that the serverside hash is the same as received hash from client
              kvs.write_key()
            else:
              print('Will not write key, hash does not match!')
        finally:
          self.close()
    elif self.type == 'db' and self.test:  # database server, hack so you can run server in tests
      self.listen()
      f = Files('.lib/db1')
      index = f.recv_index(self.ssl_sock)
      data = f.recv_data(self.ssl_sock)
      fi = f.init_index(*index)
      fd = f.init_data(*data, fi)  # type: ignore
      f.write_index(fi)
      f.write_data(fi, [fd])
      self.close()
    elif self.type == 'db':  # database server
      pass

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
  ServerRunnable('127.0.0.1', 1337, dbtype='key')
