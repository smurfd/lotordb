#!/usr/bin/env python3
import threading, socket, ssl
from typing import Union


class LotordbClient(threading.Thread):
  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0) -> None:
    threading.Thread.__init__(self, group=None)
    self.event = threading.Event()
    self.host = dbhost
    self.port = dbport
    self.sock = None

  def run(self):
    pass

  def connect(self):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('.lib/selfsigned.cert')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    ssl_sock = context.wrap_socket(sock, server_hostname='localhost')
    ssl_sock.connect((self.host, self.port))
    self.sock = ssl_sock
    print(ssl_sock.version())
    print(self.sock.version())

    ssl_sock.send(b'haii000000')
    return self.sock

  def send(self, data):
    self.sock.send(data)

  def receive(self, data):
    self.sock.recv(data)


class LotordbClientRunnable(threading.Thread):
  def __init__(self) -> None:
    threading.Thread.__init__(self, group=None)
    self.client = Union[None, LotordbClient]

  def run(self) -> None:
    try:
      self.client = LotordbClient('127.0.0.1', 1337)
      self.client.start()
      cli = self.client.connect()
      cli.send(b'byt')
      self.client.join()
      # self.client.close()
    except Exception:
      print('Could not connect to server')


if __name__ == '__main__':
  print('Client')
  client = LotordbClientRunnable()
  client.start()
