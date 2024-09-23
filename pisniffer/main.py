import pyshark
from pisniffer.dbtools import PacketHandler
import threading
import random
threadLock = threading.Lock()
# Database setup
DATABASE_URL = "postgresql+pg8000://pyclient:pyclient@localhost/packets"
from datetime import datetime

def counter_print():
  global global_counter
  global t
  t = threading.Timer(5.0, counter_print)
  print(f"{global_counter/5.0}[pps]")
  with threadLock:
        global_counter = 0
  t.start()

# Main function to capture packets and process them
def main(packet_handler:PacketHandler, interface):
    try:
        threadLock = threading.Lock()
        global_counter = 0 # the counter
        global t # the timer handle
        # Define the BPF filter
        bpf_filter = "not dst net 192.168.1.0/24 and tcp"
        capture = pyshark.LiveRingCapture(interface=interface,ring_file_size=1024,bpf_filter=bpf_filter)

        # Capture packets in a loop and handle each one
        counter_print()
        for packet in capture.sniff_continuously():
            packet_handler.add_tshark_packet(packet)
            with threadLock:
                global_counter += 1
    except Exception as ex:
        if t.is_alive:
            t.cancel()
        print(ex)

if __name__ == "__main__":    
    try:
        # Setup database
        ph = PacketHandler(DATABASE_URL)
        ph.create_db()
        # Start packet capturing on the specified interface
        INTERFACE = 'eth0'  # Change this to your network interface
        main(ph,INTERFACE)
    finally:
        #ph.drop_table()
        print('Done')

