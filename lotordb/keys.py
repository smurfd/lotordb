#!/usr/bin/env python3
from typing import Tuple, Any
from lotordb.hash import Hash
from lotordb.vars import Key
import os, pathlib


class Keys:  # Key Value Store
  def __init__(self, k: str = '', v: str = '', s: str = '') -> None:
    self.k = Key()
    if k and v and s:
      self.set_key_value_hash(k, v)
      self.set_store(s)

  def set_key_value_hash(self, k: str, v: str) -> None:
    self.k.key, self.k.value, self.k.hash = k, v, Hash(self.k.value).get()

  def get_key_value_store(self) -> Tuple:
    return self.k.key, self.k.value, self.k.store, self.k.hash

  def del_key(self) -> None:
    pathlib.Path(os.path.join(self.k.store, self.k.key)).unlink(missing_ok=True)

  def set_store(self, s: str) -> None:
    self.k.store = s

  def write_key(self) -> bool:
    os.makedirs(self.k.store, exist_ok=True)
    f = open(os.path.join(self.k.store, self.k.key), 'wb+')
    return f.write(self.k.value) > 0 if isinstance(self.k.value, bytes) else f.write(self.k.value.encode('UTF-8')) > 0  # type: ignore

  def read_key(self) -> Tuple:
    return (True, open(os.path.join(self.k.store, self.k.key), 'rb+').read()) if os.path.exists(os.path.join(self.k.store, self.k.key)) else (False,)

  def send_key(self, sock: Any, kvsh: Tuple) -> None:
    b = bytearray()
    [b.extend((i + '\n').encode('UTF-8')) for i in kvsh]  # type: ignore
    sock.send(b)

  def recv_key(self, sock: Any, size: int = 2048) -> Tuple:
    return tuple(sock.recv(4096).strip(b'\n').split(b'\n', 3))
