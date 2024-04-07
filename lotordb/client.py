#!/usr/bin/env python3
import threading, socket, ssl
from lotordb.keys import Keys
from lotordb.tables import Tables
from typing import Union


class Client(threading.Thread):
  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0, dbtype=False) -> None:
    threading.Thread.__init__(self, group=None)
    self.client = Union[None, Client]
    self.event = threading.Event()
    self.host = dbhost
    self.port = dbport
    self.sock = None
    self.type = dbtype
    self.key: Union[None, Keys] = None
    self.files: Union[None, Tables] = None
    self.thread = threading.Thread()

  def run(self) -> None:
    try:
      self.thread.start()
      self.connect()
      if self.type == 'key' and self.key:  # key value client
        self.key.send_key(self.sock, self.key.get_key())
      elif self.type == 'db' and self.files:  # database client
        self.files.send_index(self.sock, self.files.index)
        self.files.send_data(self.sock, self.files.data)
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

  def set_key(self, key):
    self.key = key

  def set_files(self, files):
    self.files = files


if __name__ == '__main__':
  print('Client')
  cli = Client('127.0.0.1', 1337, dbtype='key')
  cli.set_key(Keys(k='1122', v='abc', s='/tmp'))
  cli.start()
