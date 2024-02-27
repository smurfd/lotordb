#!/usr/bin/env python3
import threading


class LotordbServer(threading.Thread):
  def __init__(self, dbhost, dbport, dbmaster=True, dbnode=0) -> None:
    threading.Thread.__init__(self, group=None)


class LotordbServerRunnable(LotordbServer):
  def __init__(self) -> None:
    pass


if __name__ == '__main__':
  print('Server')
