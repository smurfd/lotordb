#!/usr/bin/env python3
from dataclasses import dataclass, field
from lotordb.hash import Hash
from typing import Tuple
import os


@dataclass
class Key:
  key: str = field(default='', init=False)
  value: str = field(default='', init=False)
  store: str = field(default='/tmp', init=False)
  hash: str = field(default='', init=False)


class Keys:
  def __init__(self, k='', v='', s='') -> None:
    self.k = Key()
    if k and v and s:
      self.set_key(k, v)
      self.set_store(s)

  def set_key(self, k, v) -> None:
    self.k.key = k
    self.k.value = v
    self.k.hash = Hash(self.k.value).get()

  def get_key(self) -> Tuple:
    return self.k.key, self.k.value, self.k.store, self.k.hash

  def del_key(self) -> None:
    if os.path.exists(os.path.join(self.k.store, self.k.key)):
      os.remove(os.path.join(self.k.store, self.k.key))

  def set_store(self, s) -> None:
    self.k.store = s

  def write_key(self) -> bool:
    if not os.path.exists(self.k.store):
      os.makedirs(self.k.store)
    f = open(os.path.join(self.k.store, self.k.key), 'wb+')
    if isinstance(self.k.value, bytes):
      return f.write(self.k.value) > 0
    return f.write(self.k.value.encode('UTF-8')) > 0

  def read_key(self) -> Tuple:
    if os.path.exists(os.path.join(self.k.store, self.k.key)):
      f = open(os.path.join(self.k.store, self.k.key), 'rb+')
      return (True, f.read())
    return (False,)

  def send_key(self, sock, kvsh) -> None:
    sock.send(kvsh[0].encode('UTF-8'))
    sock.send(kvsh[1].encode('UTF-8'))
    sock.send(kvsh[2].encode('UTF-8'))
    sock.send(kvsh[3].encode('UTF-8'))

  def recv_key(self, sock, size=2048) -> Tuple:
    return (sock.recv(size), sock.recv(size), sock.recv(size), sock.recv(size))


if __name__ == '__main__':
  print('Keys')
