#!/usr/bin/env python3
import threading, socket, ssl


class LotordbClient(threading.Thread):
  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0) -> None:
    threading.Thread.__init__(self, group=None)
    self.event = threading.Event()
    self.host = dbhost
    self.port = dbport

  def run(self) -> None:
    self.connect()

  def connect(self):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('.lib/selfsigned.cert')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
      with context.wrap_socket(sock, server_hostname='localhost') as ssl_sock:
        ssl_sock.connect((self.host, self.port))
        print(ssl_sock.version())


class LotordbClientRunnable(threading.Thread):
  def __init__(self) -> None:
    threading.Thread.__init__(self, group=None)

  def run(self) -> None:
    try:
      client = LotordbClient('127.0.0.1', 1337)
      client.start()
      client.join()
    except Exception:
      print('Could not connect to server')


if __name__ == '__main__':
  print('Client')
  client = LotordbClientRunnable()
  client.start()
