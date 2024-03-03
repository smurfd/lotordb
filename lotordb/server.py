#!/usr/bin/env python3
import threading, signal, socket, time, ssl


class LotordbServer(threading.Thread):
  def __init__(self) -> None:
    threading.Thread.__init__(self)
    self.event = threading.Event()

  def run(self) -> None:
    while not self.event.is_set():
      time.sleep(0.5)


class LotordbServerListener(threading.Thread):
  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0, test=False):
    threading.Thread.__init__(self)
    self.host = dbhost
    self.port = dbport
    self.sock = None
    self.event = threading.Event()
    self.test = test

  def __exit__(self, exc_type, exc_value, traceback):
    self.close()

  def __enter__(self):
    return self

  def close(self):
    self.sock.close()

  def run(self):
    if not self.test:
      while True:
        self.listen()
    else:
      self.listen()

  def listen(self):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('.lib/selfsigned.cert', '.lib/selfsigned.key')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
      sock.bind((self.host, self.port))
      sock.listen(5)
      conn, addr = context.wrap_socket(sock, server_side=True).accept()
      print(conn, addr)


class LotordbServerRunnable(threading.Thread):
  def __init__(self, test=False) -> None:
    signal.signal(signal.SIGTERM, self.service_shutdown)
    signal.signal(signal.SIGINT, self.service_shutdown)
    self.test = test
    try:
      listen = LotordbServerListener('127.0.0.1', 1337, test=self.test)
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
