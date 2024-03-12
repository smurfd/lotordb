#!/usr/bin/env python3
from dataclasses import dataclass, field
import os


@dataclass
class Key:
  key: str = field(default='', init=False)
  value: str = field(default='', init=False)
  store: str = field(default='/tmp', init=False)


class LotordbKey:
  def __init__(self):
    self.k = Key()

  def set_key(self, k, v):
    self.k.key = k
    self.k.value = v

  def get_key(self):
    return self.k.key, self.k.value, self.k.store

  def del_key(self):
    if os.path.exists(os.path.join(self.k.store, self.k.key)):
      os.remove(os.path.join(self.k.store, self.k.key))

  def set_store(self, s):
    self.k.store = s

  def write_key(self):
    if not os.path.exists(self.k.store):
      os.makedirs(self.k.store)
    f = open(os.path.join(self.k.store, self.k.key), 'wb+')
    return f.write(self.k.value.encode('UTF-8')) > 0

  def read_key(self):
    if os.path.exists(os.path.join(self.k.store, self.k.key)):
      f = open(os.path.join(self.k.store, self.k.key), 'rb+')
      return (True, f.read())
    return (False,)


if __name__ == '__main__':
  lk = LotordbKey()
  lk.set_key('1111', 'aba')
  lk.set_store('/tmp/tmp2')
  print(lk.get_key())
  assert lk.write_key()
  print(lk.read_key())
  print(lk.read_key()[0])
  lk.del_key()
