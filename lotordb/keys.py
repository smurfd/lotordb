#!/usr/bin/env python3
from typing import Tuple, Any, List, Self
from lotordb.hash import Hash
from lotordb.vars import Key
import os, pathlib, struct


class Keys:  # Key Value Store
  def __init__(self, k: str = '', v: str = '', s: str = '', sock=None) -> None:
    self.k = Key()
    self.sock: Any = sock
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

  def set_sock(self, sock) -> Self:
    self.sock = sock
    return self

  def send_key(self, kvsh: Tuple) -> None:
    b: List = []
    [b.extend(struct.pack('>%ds' % len((kvsh[i] + '\n')), (kvsh[i] + '\n').encode('UTF-8'))) for i in range(4)]  # type: ignore
    assert len(kvsh[3]) == 128  # assert hash is 128 length
    self.sock.send(bytes(b))

  def recv_key(self, size: int = 2048) -> Tuple:
    return tuple(self.sock.recv(4096).strip(b'\n').split(b'\n', 3))
