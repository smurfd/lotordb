#!/usr/bin/env python3
import threading, signal, socket, ssl


class LotordbServerListener(threading.Thread):
  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0, test=False, dbtype=False):
    threading.Thread.__init__(self)
    self.host = dbhost
    self.port = dbport
    self.sock = None
    self.ssl_sock = None
    self.context = None
    self.event = threading.Event()
    self.test = test
    self.type = dbtype

  def __exit__(self, exc_type, exc_value, traceback):
    self.close()

  def __enter__(self):
    return self

  def close(self):
    self.sock.close()

  def run(self):
    if self.type == 'key' and self.test:  # key value server, hack so you can run server in tests
      pass
    if self.type == 'key':  # key value server
      pass
    elif self.type == 'db' and self.test:  # database server, hack so you can run server in tests
      pass
    elif self.type == 'db':  # database server
      pass
    elif self.test:  # hack so you can run server in tests
      self.init()
      self.listen()
      self.recv()
    else:
      self.init()
      while not self.event.is_set():
        self.listen()
        try:
          self.recv()
          self.recv()
        finally:
          self.ssl_sock.close()

  def init(self):
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


class LotordbServerRunnable(threading.Thread):
  def __init__(self, test=False, dbtype=False) -> None:
    signal.signal(signal.SIGTERM, self.service_shutdown)
    signal.signal(signal.SIGINT, self.service_shutdown)
    self.test = test
    try:
      listen = LotordbServerListener('127.0.0.1', 1337, test=self.test, dbtype=dbtype)
      listen.start()
    except self.ServiceExit:
      listen.event.set()
      listen.join()
      listen.close()

  class ServiceExit(Exception):
    pass

  def service_shutdown(self, signum, frame):
    raise self.ServiceExit


if __name__ == '__main__':
  print('Server')
  LotordbServerRunnable()
