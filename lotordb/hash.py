#!/usr/bin/env python3
import threading, hashlib
from typing import Union


class Hash(threading.Thread):
  def __init__(self, s) -> None:
    threading.Thread.__init__(self, group=None)
    self.s: Union[str, bytes] = s
    self.h: Union[str, None] = None
    self.start()

  def __exit__(self, exc_type, exc_value, traceback) -> None:
    self.join()

  def run(self) -> None:
    if isinstance(self.s, bytes):
      self.h = hashlib.sha3_512(self.s).hexdigest()
    else:
      self.h = hashlib.sha3_512(self.s.encode('UTF-8')).hexdigest()

  def get(self) -> str:
    self.join()
    if self.h:
      return self.h
    return ''


if __name__ == '__main__':
  print('Hash')
