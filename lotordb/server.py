#!/usr/bin/env python3
import threading, signal, socket, ssl, sys
from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler
from typing_extensions import Self
from lotordb.tables import Tables
from typing import Union, Any
from lotordb.keys import Keys


class Handler:
  # Would we need different handlings for Test server, we create copies of these and use in Server class
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
      self.table.write_index(self.table.recv_encrypted_index())
      self.table.write_data(self.table.recv_encrypted_data())


class Server(threading.Thread):
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

  class ServiceExit(Exception):
    pass

  class Listener:
    def __init__(self, host, port, handler, test=False) -> None:
      self.server = Server.ThreadingTCPServerSSL((host, port), handler)
      self.server_thread = threading.Thread(target=self.server.serve_forever)
      self.server_thread.daemon = True if test else False
      self.server_thread.start()

    def __exit__(self) -> None:
      self.server.shutdown()
      self.server.socket.close()
      self.server.server_close()
      self.server_thread.join()

  def __init__(self, dbmaster: bool = True, dbnode: int = 0, test: bool = False, dbtype: Union[bool, str] = False) -> None:
    signal.signal(signal.SIGTERM, self.service_shutdown)
    signal.signal(signal.SIGINT, self.service_shutdown)
    threading.Thread.__init__(self)
    self.sock: Union[socket.socket, Any] = None
    self.ssl_sock: Union[socket.socket, Any] = None
    self.context: Union[ssl.SSLContext, Any] = None
    self.event = threading.Event()
    self.test: bool = test
    self.type: Union[bool, str] = dbtype
    self.tables: Union[None, Tables] = None
    self.thread = threading.Thread()
    try:
      self.thread.start()
      self.start()
    except self.ServiceExit:
      self.event.set()
      self.thread.join()
      self.close()

  def __exit__(self, exc_type, exc_value, traceback) -> None:
    self.close()

  def close(self) -> None:
    self.ssl_sock.close()

  def service_shutdown(self, signum, frame) -> None:
    raise self.ServiceExit

  def set_tables(self, tables: Union[None, Tables]) -> Self:
    self.tables = tables
    return self


if __name__ == '__main__':
  print('Server')
  if sys.argv[1] == 'table':
    Server.Listener('localhost', 7332, Handler.HandlerTable, test=False)
  elif sys.argv[1] == 'key':
    Server.Listener('localhost', 7331, Handler.HandlerKey, test=False)
