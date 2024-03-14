#!/usr/bin/env python3
import threading, signal, socket, ssl
from lotordb.keys import Keys


class ServerRunnable(threading.Thread):
  class ServiceExit(Exception):
    pass

  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0, test=False, dbtype=False) -> None:
    signal.signal(signal.SIGTERM, self.service_shutdown)
    signal.signal(signal.SIGINT, self.service_shutdown)
    threading.Thread.__init__(self)
    self.host = dbhost
    self.port = dbport
    self.sock = None
    self.ssl_sock = None
    self.context = None
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

  def __exit__(self, exc_type, exc_value, traceback):
    self.close()

  def close(self):
    self.sock.close()

  def run(self):
    self.init_server_socket()
    if self.type == 'key' and self.test:  # key value server, hack so you can run server in tests
      self.listen()
      self.recv()
      self.ssl_sock.close()
    elif self.type == 'key':  # key value server
      while not self.event.is_set():
        self.listen()
        try:
          k = self.recv()
          v = self.recv()
          s = self.recv()
          print('serv', k, v, s)
          if k and v and s:
            kvs = Keys()
            kvs.set_key(k, v)
            kvs.set_store(s)
            print('kvs', kvs.get_key())
            kvs.write_key()
        finally:
          self.ssl_sock.close()
    elif self.type == 'db' and self.test:  # database server, hack so you can run server in tests
      pass
    elif self.type == 'db':  # database server
      pass
    elif self.test:  # hack so you can run server in tests
      self.listen()
      self.recv()
    else:
      while not self.event.is_set():
        self.listen()
        try:
          self.recv()
        finally:
          self.ssl_sock.close()

  def init_server_socket(self):
    self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    self.context.load_cert_chain('.lib/selfsigned.cert', '.lib/selfsigned.key')
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    self.sock.bind((self.host, self.port))
    self.sock.listen(10)

  def listen(self):
    s, _ = self.sock.accept()
    self.ssl_sock = self.context.wrap_socket(s, server_side=True)

  def recv(self):
    if self.ssl_sock:
      r = self.ssl_sock.recv(2048)
      print(r)
      return r

  def service_shutdown(self, signum, frame):
    raise self.ServiceExit


if __name__ == '__main__':
  print('Server')
  ServerRunnable('127.0.0.1', 1337, dbtype='key')
