from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler
from lotordb.keys import Keys
import ssl, socket, threading


class Hand:
  class HandlerKey(StreamRequestHandler):
    def handle(self):
      # while not self.event.is_set():  # for actual server usage
      print('key handler')
      try:
        k, v, s, h = Keys().set_sock(self.connection).recv_key()
        print('serv', k, v, s, h)
        if k and v and s:
          kvs = Keys(k, v, s)
          kvs.write_key() if h.decode('UTF-8') == kvs.get_key_value_store()[3] else print('Will not write key, hash does not match!')
      finally:
        pass

  class HandlerTable(StreamRequestHandler):
    def handle(self):
      print('table handler')
      data = self.connection.recv(4096)
      self.wfile.write(data)

  class HandlerKeyTest(StreamRequestHandler):
    def handle(self):
      print('key handler test')
      try:
        k, v, s, h = Keys().set_sock(self.connection).recv_key()
        print('serv', k, v, s, h)
        if k and v and s:
          kvs = Keys(k, v, s)
          kvs.write_key() if h.decode('UTF-8') == kvs.get_key_value_store()[3] else print('Will not write key, hash does not match!')
      finally:
        pass
        # self.close()

  class HandlerTableTest(StreamRequestHandler):
    def handle(self):
      print('table handler test')
      data = self.connection.recv(4096)
      self.wfile.write(data)


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
      ssl_sock.send(b'elloH table')
      print(ssl_sock.recv(4096))
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
      ssl_sock.send(b'elloH table')
      print(ssl_sock.recv(4096))
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
    key_server_thread.daemon = True
    key_server_thread.block_on_close = False
    key_server_thread.start()
    return key_server, key_server_thread

  def server_table(self):
    table_server = Srv.ThreadingTCPServerSSL(('localhost', 7332), Hand.HandlerTable)
    table_server_thread = threading.Thread(target=table_server.serve_forever)
    table_server_thread.daemon = True
    table_server_thread.block_on_close = False
    table_server_thread.start()
    return table_server, table_server_thread

  def server_key_test(self):
    key_server = Srv.ThreadingTCPServerSSL(('localhost', 7333), Hand.HandlerKeyTest)
    key_server_thread = threading.Thread(target=key_server.serve_forever)
    key_server_thread.daemon = True
    key_server_thread.block_on_close = False
    key_server_thread.start()
    return key_server, key_server_thread

  def server_table_test(self):
    table_server = Srv.ThreadingTCPServerSSL(('localhost', 7334), Hand.HandlerTableTest)
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
  key_server, key_server_thread = Srv().server_key()
  Cli().client_key()
  Srv().server_key_end(key_server, key_server_thread)

  key_server, key_server_thread = Srv().server_key_test()
  Cli().client_key_test()
  Srv().server_key_end(key_server, key_server_thread)

  table_server, table_server_thread = Srv().server_table()
  Cli().client_table()
  Srv().server_table_end(table_server, table_server_thread)

  table_server, table_server_thread = Srv().server_table_test()
  Cli().client_table_test()
  Srv().server_table_end(table_server, table_server_thread)


if __name__ == '__main__':
  test_lotordb_newprototype()
  print('OK')
