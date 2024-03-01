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
    # TODO: while true, if not test
    self.listen()

  def listen(self):
    # self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # self.sock.bind((self.host, self.port))
    # self.sock.listen(10)

    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    #  sock.bind(('127.0.0.1', 8443))
    #  sock.listen(5)
    #  with context.wrap_socket(sock, server_side=True) as ssock:
    #    conn, addr = ssock.accept()
    """
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    self.sock.bind((self.host, self.port))
    self.sock.listen(10)
    print("listening")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    print("listening2")

    context.load_cert_chain('.lib/selfsigned.cert', '.lib/selfsigned.key')
    print("listening3")
    with context.wrap_socket(self.sock, server_side=True) as self.ssock:
      print("listening4")
      conn, addr = self.ssock.accept()
      print("listening5")
      print(conn, addr)
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('.lib/selfsigned.cert', '.lib/selfsigned.key')

    # context.load_cert_chain('.lib/selfsigned.cert', '.lib/selfsigned.key')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
      sock.bind((self.host, self.port))
      sock.listen(5)
      # conn, addr = sock.accept()
      # works
      # ssls = ssl.wrap_socket(conn, server_side=True, certfile=".lib/selfsigned.cert", keyfile=".lib/selfsigned.key")
      ssls = context.wrap_socket(sock, server_side=True)
      conn, addr = ssls.accept()
      print(conn, addr)
      # ssls = context.wrap_socket(conn, server_side=True)

      # ssock = context.wrap_socket(sock, server_side=True)
      # with context.wrap_socket(sock, server_side=True) as ssock:
      # conn, addr = ssock.accept()


class LotordbServerRunnable(threading.Thread):
  def __init__(self, test=False) -> None:
    signal.signal(signal.SIGTERM, self.service_shutdown)
    signal.signal(signal.SIGINT, self.service_shutdown)
    self.test = test
    # sr = LotordbServer()
    # sr.start()
    try:
      sl = LotordbServerListener('127.0.0.1', 1337, self.test)
      sl.start()
    except self.ServiceExit:
      sl.event.set()
      sl.join()
      sl.close()
    # sr.join()

  class ServiceExit(Exception):
    pass

  def service_shutdown(self, signum, frame):
    raise self.ServiceExit


if __name__ == '__main__':
  print('Server')
  LotordbServerRunnable()
