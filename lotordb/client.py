#!/usr/bin/env python3
import threading, socket, ssl
from lotordb.keys import Keys
from typing import Union


class ClientRunnable(threading.Thread):
  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0, dbtype=False) -> None:
    threading.Thread.__init__(self, group=None)
    self.client = Union[None, ClientRunnable]
    self.event = threading.Event()
    self.host = dbhost
    self.port = dbport
    self.sock = None
    self.type = dbtype
    self.thread = threading.Thread()
    self.start()

  def run(self) -> None:
    try:
      self.thread.start()
      self.connect()
      if self.type == 'key':  # key value client
        k = Keys(k='1122', v='abc', s='/tmp')
        print('sending', k.get_key())
        self.send(k.get_key()[0].encode('UTF-8'))
        self.send(k.get_key()[1].encode('UTF-8'))
        self.send(k.get_key()[2].encode('UTF-8'))
      elif self.type == 'db':  # database client
        pass
      self.thread.join()
    except Exception:
      print('Could not connect to server')

  def connect(self):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('.lib/selfsigned.cert')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    self.sock = context.wrap_socket(sock, server_hostname='localhost')
    self.sock.connect((self.host, self.port))
    return self.sock

  def send(self, data):
    self.sock.send(data)

  def receive(self, data):
    self.sock.recv(data)


if __name__ == '__main__':
  print('Client')
  ClientRunnable('127.0.0.1', 1337, dbtype='key')
