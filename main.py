import pyshark
from dbtools import PacketHandler,Packet

# Database setup
DATABASE_URL = "postgresql+pg8000://pyclient:pyclient@localhost/packets"


# Main function to capture packets and process them
def main(packet_handler:PacketHandler, interface):
    # Define the BPF filter
    bpf_filter = "not dst net 192.168.1.0/24 and tcp"
    capture = pyshark.LiveRingCapture(interface=interface,ring_file_size=1024,bpf_filter=bpf_filter)

    # Capture packets in a loop and handle each one
    for packet in capture.sniff_continuously():
        packet_handler.add_tshark_packet(packet)

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

