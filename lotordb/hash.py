#!/usr/bin/env python3
import threading, hashlib
from typing import Union


class Hash(threading.Thread):
  def __init__(self, string: Union[str, bytes]) -> None:
    threading.Thread.__init__(self, group=None)
    self.stri: Union[str, bytes] = string
    self.hash: Union[str, None] = None
    self.start()

  def __exit__(self, exc_type, exc_value, traceback) -> None:
    self.join()

  def run(self) -> None:
    self.hash = hashlib.sha3_512(self.stri).hexdigest() if isinstance(self.stri, bytes) else hashlib.sha3_512(self.stri.encode('UTF-8')).hexdigest()

  def get(self) -> str:
    self.join()
    return self.hash if self.hash else ''


if __name__ == '__main__':
  print('Hash')
