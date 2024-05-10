#!/usr/bin/env python3
#                     ___
#   ,---,     ,--,   ,--.'|_ 2024
# ,---.'|   ,--.'|   |  | :,'   __  ,-. auth: smurfd
# |   | :   |  |,    :  : ' : ,' ,'/ /|  .--.--.
# :   : :   `--'_  .;__,'  /  '  | |' | /  /    '
# :     |,-.,' ,'| |  |   |   |  |   ,'|  :  /`./
# |   : '  |'  | | :__,'| :   '  :  /  |  :  ;_
# |   |  / :|  | :   '  : |__ |  | '    \  \    `.
# '   : |: |'  : |__ |  | '.'|;  : |     `----.   \
# |   | '/ :|  | '.'|;  :    ;|  , ;    /  /`--'  /
# |   :    |;  :    ;|  ,   /  ---'    '--'.     /
# /    \  / |  ,   /  ---`-'             `--'---'
# `-'----'   ---`-' processes to bits, for you
import multiprocessing
from typing import Any


class Bitrs(multiprocessing.Process):
  def __init__(self, func, *args, cpus=multiprocessing.cpu_count()) -> None:
    super().__init__()
    self.func = func
    self.prcs = multiprocessing.Pool(cpus)
    self.args = args

  def start(self) -> None:
    self.ret = self.prcs.apply_async(self.func, self.args)

  def stop(self) -> Any:
    self.prcs.close()
    self.prcs.join()
    return self.ret.get(timeout=1)
