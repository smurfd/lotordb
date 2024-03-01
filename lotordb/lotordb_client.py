#!/usr/bin/env python3
import threading, time, socket, ssl


class LotordbClient(threading.Thread):
  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0) -> None:
    threading.Thread.__init__(self, group=None)
    self.event = threading.Event()
    self.host = dbhost
    self.port = dbport

  def run(self) -> None:
    self.connect()

  def connect(self):
    """
    #self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    #self.sock.connect((self.host, self.port))
    ##self.ssls = ssl.wrap_socket(self.sock, ca_certs="lib/selfsigned.cert", cert_reqs=ssl.CERT_REQUIRED)
    ##self.ssls.connect((self.host, self.port))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    #context.load_verify_locations('.lib/selfsigned.key')#/opt/pkg/etc/openssl/certs/ca-certificates.crt')

    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    self.ssock = context.wrap_socket(self.sock, server_hostname=self.host)
    print(self.ssock.version())
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('.lib/selfsigned.cert')
    # context.load_verify_locations('path/to/cabundle.pem')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
      with context.wrap_socket(sock, server_hostname='localhost') as ssock:  # server_hostname='127.0.0.1') as ssock:
        ssock.connect((self.host, self.port))
        print(ssock.version())


class LotordbClientRunnable(threading.Thread):
  def __init__(self) -> None:
    threading.Thread.__init__(self, group=None)

  def run(self) -> None:
    try:
      cl = LotordbClient('127.0.0.1', 1337)
      cl.start()
      time.sleep(2)
      cl.join()
    except Exception:
      print('Could not connect to server')


if __name__ == '__main__':
  print('Client')
  c = LotordbClientRunnable()
  c.start()

"""
import socket
import ssl

hostname = 'www.python.org'
context = ssl.create_default_context()

with socket.create_connection((hostname, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssock.version())

Client socket example with custom context and IPv4:

hostname = 'www.python.org'
# PROTOCOL_TLS_CLIENT requires valid cert chain and hostname
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations('path/to/cabundle.pem')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssock.version())

Server socket example listening on localhost IPv4:

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/path/to/certchain.pem', '/path/to/private.key')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind(('127.0.0.1', 8443))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
"""
