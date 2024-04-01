#!/usr/bin/env python3
import threading, socket, ssl
from lotordb.keys import Keys
from lotordb.files import Files
from typing import Union, List


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
        k.send_key(self.sock, k.get_key())
      elif self.type == 'db':  # database client
        data: List = [123] * 125
        f = Files('.lib/db1')
        a = f.init_index(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db1.dbindex')
        b = f.init_data(1, 1, 1, 1, 1, 1, data, a)[0]  # type: ignore
        f.send_index(self.sock, a)
        f.send_data(self.sock, b)
      self.close()
      self.thread.join(timeout=0.1)
    except Exception as e:
      print('Could not connect to server', e)

  def connect(self):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('.lib/selfsigned.cert')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    self.sock = context.wrap_socket(sock, server_hostname=socket.gethostbyaddr(self.host)[0])  # Get hostname from ip
    self.sock.connect((self.host, self.port))
    return self.sock

  def close(self):
    self.sock.close()

  def send(self, data):
    self.sock.send(data)

  def receive(self, data):
    self.sock.recv(data)


if __name__ == '__main__':
  print('Client')
  ClientRunnable('127.0.0.1', 1337, dbtype='key')
