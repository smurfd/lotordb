#!/usr/bin/env python3
import threading, hashlib


class Hash(threading.Thread):
  def __init__(self, s):
    threading.Thread.__init__(self, group=None)
    self.s = s
    self.h = None
    self.start()

  def __exit__(self, exc_type, exc_value, traceback):
    self.join()

  def run(self):
    print('hashing:', self.s)
    if isinstance(self.s, bytes):
      self.h = hashlib.sha3_512(self.s).hexdigest()
    else:
      self.h = hashlib.sha3_512(self.s.encode('UTF-8')).hexdigest()
    print('hashed:::', self.h)

  def get(self):
    self.join()
    return self.h


if __name__ == '__main__':
  print('Hash')
