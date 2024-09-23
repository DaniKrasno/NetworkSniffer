import threading
from datetime import datetime
import random
import time

global global_counter
global t

def counter_print():
  global global_counter
  global t
  t = threading.Timer(5.0, counter_print)
  print(f"{global_counter/5.0}[pps]")
  with threadLock:
        global_counter = 0
  t.start()

if __name__ == "__main__":   
    threadLock = threading.Lock()
    global_counter = 0
    global t
    counter_print()
    tic = datetime.now()
    while (datetime.now()-tic).total_seconds()<50:
        time.sleep(random.random())
        with threadLock:
            global_counter += 1
    t.cancel()