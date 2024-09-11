import pyshark
import pandas as pd
from sqlalchemy import create_engine
import sqlite3
import json

# Database setup
DATABASE_URL = 'sqlite:///packets.db'
engine = create_engine(DATABASE_URL)

# Create a connection to the SQLite database
def create_db():
    with engine.connect() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT,
                destination TEXT,
                protocol TEXT,
                length INTEGER,
                data TEXT
            )
        ''')

# Function to serialize a packet to JSON
def serialize_packet(packet):
    packet_dict = {
        'timestamp': packet.sniff_time.isoformat(),
        'source': packet.ip.src if hasattr(packet, 'ip') else '',
        'destination': packet.ip.dst if hasattr(packet, 'ip') else '',
        'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else '',
        'length': int(packet.length),
        'data': packet.raw_mode_packet if hasattr(packet, 'raw_mode_packet') else ''
    }
    return json.dumps(packet_dict)

# Packet handler function
def packet_handler(packet):
    serialized_packet = serialize_packet(packet)
    packet_data = json.loads(serialized_packet)

    # Insert packet data into the database
    with engine.connect() as conn:
        conn.execute('''
            INSERT INTO packets (timestamp, source, destination, protocol, length, data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (packet_data['timestamp'], packet_data['source'], packet_data['destination'], packet_data['protocol'], packet_data['length'], packet_data['data']))

# Main function to capture packets and process them
def main(interface):
    capture = pyshark.LiveCapture(interface=interface)

    # Capture packets in a loop and handle each one
    for packet in capture.sniff_continuously():
        packet_handler(packet)

if __name__ == "__main__":
    # Setup database
    create_db()
    
    # Start packet capturing on the specified interface
    INTERFACE = 'eth0'  # Change this to your network interface
    main(INTERFACE)
