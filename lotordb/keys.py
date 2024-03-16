#!/usr/bin/env python3
from dataclasses import dataclass, field
from lotordb.hash import Hash
import os


@dataclass
class Key:
  key: str = field(default='', init=False)
  value: str = field(default='', init=False)
  store: str = field(default='/tmp', init=False)
  hash: str = field(default='', init=False)


class Keys:
  def __init__(self, k='', v='', s=''):
    self.k = Key()
    if k and v and s:
      self.set_key(k, v)
      self.set_store(s)

  def set_key(self, k, v):
    self.k.key = k
    self.k.value = v
    self.k.hash = Hash(self.k.value).get()

  def get_key(self):
    return self.k.key, self.k.value, self.k.store, self.k.hash

  def del_key(self):
    if os.path.exists(os.path.join(self.k.store, self.k.key)):
      os.remove(os.path.join(self.k.store, self.k.key))

  def set_store(self, s):
    self.k.store = s

  def write_key(self):
    if not os.path.exists(self.k.store):
      os.makedirs(self.k.store)
    f = open(os.path.join(self.k.store, self.k.key), 'wb+')
    return f.write(self.k.value) > 0

  def read_key(self):
    if os.path.exists(os.path.join(self.k.store, self.k.key)):
      f = open(os.path.join(self.k.store, self.k.key), 'rb+')
      return (True, f.read())
    return (False,)


if __name__ == '__main__':
  print('Keys')
