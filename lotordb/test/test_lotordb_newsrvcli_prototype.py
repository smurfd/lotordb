import ssl, socket, threading, struct, gzip, mmap, secrets, io
from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler
from typing import List, Union, BinaryIO, IO
from lotordb.vars import DbIndex, DbData, Vars
from lotordb.cipher import Cipher
from lotordb.keys import Keys


class Tables(threading.Thread):
  def __init__(self, fn='') -> None:
    self.fi: Union[None, BinaryIO, IO] = None
    self.fd: Union[None, BinaryIO, IO] = None
    self.fimm: Union[None, BinaryIO] = None
    self.fdmm: Union[None, BinaryIO] = None
    self.fn = (fn + '.dbindex', fn + '.dbdata')
    self.size: int = 4048
    self.index: Union[DbIndex, None] = None
    self.data: Union[DbData, None] = None
    self.cip = Cipher(key=[secrets.randbelow(256) for _ in range(0x20)], iv=[secrets.randbelow(256) for _ in range(16)])
    self.ssl_sock: Union[socket.socket, None] = None
    if fn:
      self.open_index_file(self.fn[0], 'ab+')
      self.open_data_file(self.fn[1], 'ab+')
    else:
      self.fi = io.BufferedRandom  # type: ignore
      self.fd = io.BufferedRandom  # type: ignore

  def __exit__(self) -> None:
    self.close_file()
    self.join(timeout=0.1)

  def set_sock(self, sslsock):
    self.ssl_sock = sslsock
    return self

  def set_index_data(self, index: DbIndex, data: DbData):
    self.index = index
    self.data = data

  def close_file(self) -> None:
    self.fi.close() if self.fi and not self.fi.closed else None
    self.fd.close() if self.fd and not self.fd.closed else None

  def open_index_file(self, filename: str, rwd: str) -> None:
    self.fi = open(filename, rwd)

  def open_data_file(self, filename: str, rwd: str) -> None:
    self.fd = open(filename, rwd)

  def read_index(self):
    self.open_index_file(self.fn[0], 'rb+')
    self.fimm = mmap.mmap(self.fi.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return self.fimm.read() if self.fimm else b''

  def read_data(self):
    self.open_data_file(self.fn[1], 'rb+')
    self.fdmm = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)  # type: ignore
    return self.fdmm.read() if self.fimm else b''

  def write_index(self, index):
    self.open_index_file(self.fn[0], 'ab+') if self.fi.closed else None
    self.fi.write(index), len(index) if self.fi else b''

  def write_data(self, data):
    self.open_data_file(self.fn[1], 'ab+') if self.fd.closed else None
    self.fd.write(data) if self.fd else b''

  def index_to_bytearray_encrypt(self, index):
    b: List = []
    var: List = [index.index, index.dbindex, index.database, index.table, index.row, index.col, index.segments, index.seek]
    packed: List[Union[bytes, None]] = [None] * 8
    packed[:7] = [struct.pack('>Q', c) for c in var]
    packed[8] = struct.pack('>255s', bytes(index.file.ljust(255, ' '), 'UTF-8'))
    [b.extend(i) for i in packed]
    return self.encrypt(bytes(b))

  def data_to_bytearray_encrypt(self, data, index):
    b: List = []
    if isinstance(data, DbData) and data and data.data:
      pvr: List = [struct.pack('>Q', c) for c in [data.index, data.database, data.table, data.relative, data.row, data.col]]
      gzd: List = gzip.compress(struct.pack('>%dQ' % len(data.data), *data.data), compresslevel=3)
      gzl: int = len(gzd)
      gzlsize: int = gzl // self.size
      if isinstance(index.seek, bytes) and self.fd:
        index.seek = struct.pack('>Q', self.fd.tell()) if not struct.unpack('>Q', index.seek) else 0
        self.fd.seek(struct.unpack('>Q', index.seek)[0], 0)
      # Calculate diff between length of gz data, if not divisable with self.size, add 1 to zlen
      zlen: int = (gzlsize) if not (gzl - ((gzlsize) * self.size) > 0) else (gzlsize) + 1
      [b.extend(pvr[i]) for i in range(6)]
      [b.extend(gzd[i * self.size : (i + 1) * self.size]) for i in range(zlen)]
      return self.encrypt(bytes(b))

  def data_to_bytearray_encrypt_segment(self, data, index):
    b: List = []
    dad: DbData = DbData(1, 1, 1, 1, 1, 1, [])
    for i in range(0, len(data.data), Vars.SEGM):
      dad.data = data.data[i : i + Vars.SEGM]
      b.extend(self.data_to_bytearray_encrypt(dad, index))
    return bytes(b)

  def encrypt(self, p):
    iv, rk, out = self.cip.get_iv_rk()
    pad, p = self.cip.pad_data(p)
    for i in range(0, len(p), 16):
      out[i:] = self.cip.encrypt_block(self.cip.xor(iv, p[i:], 16), rk)
      iv = out[i:]
    return self.cip.get_encrypt(self.cip.key, p, out, pad)

  # def send_encrypted_index(self, index):
  #  print("snd sslsock", self.ssl_sock)
  #  print("snd sslsock len", self.ssl_sock.send(struct.pack('>Q', len(index)))) if self.ssl_sock else b''
  #  print("snd sslsock ind", self.ssl_sock.send(index)) if self.ssl_sock else b''

  def recv_encrypted_index(self):
    size = self.ssl_sock.recv(8) if self.ssl_sock else ()
    return self.ssl_sock.recv(int.from_bytes(size)) if self.ssl_sock else ()

  # def send_encrypted_data(self, data):
  #  self.ssl_sock.send(struct.pack('>Q', len(data))) if self.ssl_sock else b''
  #  self.ssl_sock.send(data) if self.ssl_sock else b''

  def recv_encrypted_data(self):
    size = self.ssl_sock.recv(8) if self.ssl_sock else ()
    return self.ssl_sock.recv(int.from_bytes(size)) if self.ssl_sock else ()

  def send(self, ssl_sock, enc_i, enc_d):
    snd: bytes = bytearray()
    snd.extend(struct.pack('>Q', len(enc_i)))
    snd.extend(enc_i)
    snd.extend(struct.pack('>Q', len(enc_d)))
    snd.extend(enc_d)
    ssl_sock.send(snd)

  def decrypt_index(self, index_packed):
    iv, rk, out = self.cip.get_iv_rk()
    ina, s, pp = self.cip.get_decrypt(self.cip.key, index_packed)
    for i in range(0, len(ina), 16):
      out[i:] = self.cip.xor(iv, self.cip.decrypt_block(ina[i:], rk), 16)
      iv = ina[i:]
    out = out[: len(out) - pp if isinstance(pp, int) else int.from_bytes(pp, 'big')]
    ret = ''.join(map(str, (chr(i) for i in out))).encode('UTF-8') if s else out
    return DbIndex(*(int.from_bytes(ret[i : i + 8]) for i in range(0, 64, 8)), ''.join(chr(y) for y in ret[64:]))

  def decrypt_data(self, data_packed):
    iv, rk, out = self.cip.get_iv_rk()
    ina, s, pp = self.cip.get_decrypt(self.cip.key, data_packed)
    if s or pp:
      pass  # TODO: string or padded, needed now?
    for i in range(0, len(ina), 16):
      out[i:] = self.cip.xor(iv, self.cip.decrypt_block(ina[i:], rk), 16)
      iv = ina[i:]
    outdata = gzip.decompress(bytes([i for i in out[48 : len(out)]]))
    return DbData(*(int.from_bytes(out[i : i + 8]) for i in range(0, 48, 8)), outdata)

  def decrypt_bytearray_to_index(self, indexba):
    return self.decrypt_index(indexba)

  def decrypt_bytearray_to_data_segmented(self, data):
    dad: DbData = DbData(1, 1, 1, 1, 1, 1, [])
    dret: DbData = DbData(1, 1, 1, 1, 1, 1, [])
    for i in range(0, len(data), Vars.ZSIZ):
      dad = self.decrypt_data(data[i : i + Vars.ZSIZ])
      dret.data.extend(dad.data)
    return dret

  def decrypt_bytearray_to_data(self, databa):
    return self.decrypt_data(databa)


class Hand:
  # Would we need different handlings for Test server, we create copies of these and use in Srv class
  class HandlerKey(StreamRequestHandler):
    def handle(self):
      print('key handler')
      try:
        k, v, s, h = Keys().set_sock(self.connection).recv_key()
        print('serv', k, v, s, h)
        if k and v and s:
          kvs = Keys(k, v, s)
          kvs.write_key() if h.decode('UTF-8') == kvs.get_key_value_store()[3] else print('Will not write key, hash does not match!')
      except ValueError:
        print('Value error')
      finally:
        pass

  class HandlerTable(StreamRequestHandler):
    def handle(self):
      print('table handler')
      self.table = Tables('.lib/db34')
      self.table.set_sock(self.connection)
      enc_i = self.table.recv_encrypted_index()
      enc_d = self.table.recv_encrypted_data()
      self.table.write_index(enc_i)
      self.table.write_data(enc_d)


class Cli:
  def client_key(self):
    for i in range(5):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.load_verify_locations('.lib/selfsigned.cert')
      ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      ssl_sock.connect(('localhost', 7331))
      k = Keys(k='1122', v='abc', s='/tmp')
      k.set_sock(ssl_sock).send_key(k.get_key_value_store())
      ssl_sock.close()

  def client_table(self):
    for i in range(5):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.load_verify_locations('.lib/selfsigned.cert')
      ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      ssl_sock.connect(('localhost', 7332))

      table = Tables()
      context: List = [123] * 123
      ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db9.dbindex')
      dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
      i = table.index_to_bytearray_encrypt(ind)
      d = table.data_to_bytearray_encrypt(dad, ind)
      table.send(ssl_sock, i, d)
      ssl_sock.close()

  def client_key_test(self):
    for i in range(5):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.load_verify_locations('.lib/selfsigned.cert')
      ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      ssl_sock.connect(('localhost', 7333))
      k = Keys(k='1122', v='abctest', s='/tmp')
      k.set_sock(ssl_sock).send_key(k.get_key_value_store())
      ssl_sock.close()

  def client_table_test(self):
    for i in range(5):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.load_verify_locations('.lib/selfsigned.cert')
      ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      ssl_sock.connect(('localhost', 7334))

      table = Tables()
      table.set_sock(ssl_sock)
      context: List = [123] * 123
      ind: DbIndex = DbIndex(1, 1, 1, 1, 1, 1, 1, 0, '.lib/db9.dbindex')
      dad: DbData = DbData(1, 1, 1, 1, 1, 1, context)
      i = table.index_to_bytearray_encrypt(ind)
      d = table.data_to_bytearray_encrypt(dad, ind)
      table.send(ssl_sock, i, d)
      ssl_sock.close()


class Srv:
  class TCPServerSSL(TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
      TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
      TCPServer.allow_reuse_address = True

    def get_request(self):
      newsocket, fromaddr = self.socket.accept()
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
      ctx.load_cert_chain('.lib/selfsigned.cert', '.lib/selfsigned.key')
      return ctx.wrap_socket(sock=newsocket, server_side=True), fromaddr

  class ThreadingTCPServerSSL(ThreadingMixIn, TCPServerSSL):
    pass

  def server_key(self):
    key_server = Srv.ThreadingTCPServerSSL(('localhost', 7331), Hand.HandlerKey)
    key_server_thread = threading.Thread(target=key_server.serve_forever)
    # key_server_thread.daemon = True
    key_server_thread.block_on_close = False
    key_server_thread.start()
    return key_server, key_server_thread

  def server_table(self):
    table_server = Srv.ThreadingTCPServerSSL(('localhost', 7332), Hand.HandlerTable)
    table_server_thread = threading.Thread(target=table_server.serve_forever)
    # table_server_thread.daemon = True
    table_server_thread.block_on_close = False
    table_server_thread.start()
    return table_server, table_server_thread

  def server_key_test(self):
    key_server = Srv.ThreadingTCPServerSSL(('localhost', 7333), Hand.HandlerKey)
    key_server_thread = threading.Thread(target=key_server.serve_forever)
    key_server_thread.daemon = True
    key_server_thread.block_on_close = False
    key_server_thread.start()
    return key_server, key_server_thread

  def server_table_test(self):
    table_server = Srv.ThreadingTCPServerSSL(('localhost', 7334), Hand.HandlerTable)
    table_server_thread = threading.Thread(target=table_server.serve_forever)
    table_server_thread.daemon = True
    table_server_thread.block_on_close = False
    table_server_thread.start()
    return table_server, table_server_thread

  def server_key_end(self, key_server, key_server_thread):
    key_server.shutdown()
    key_server.socket.close()
    key_server.server_close()
    key_server_thread.join()

  def server_table_end(self, table_server, table_server_thread):
    table_server.shutdown()
    table_server.socket.close()
    table_server.server_close()
    table_server_thread.join()


def test_lotordb_newprototype():
  # key_server, key_server_thread = Srv().server_key()
  # Cli().client_key()
  # Srv().server_key_end(key_server, key_server_thread)

  key_server, key_server_thread = Srv().server_key_test()
  Cli().client_key_test()
  Srv().server_key_end(key_server, key_server_thread)

  # table_server, table_server_thread = Srv().server_table()
  # Cli().client_table()
  # Srv().server_table_end(table_server, table_server_thread)

  table_server, table_server_thread = Srv().server_table_test()
  Cli().client_table_test()
  Srv().server_table_end(table_server, table_server_thread)


if __name__ == '__main__':
  test_lotordb_newprototype()
  print('OK')
