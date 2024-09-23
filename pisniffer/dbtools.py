import sqlalchemy as sa
from sqlalchemy.orm import declarative_base,Session,mapped_column,Mapped
import sqlite3
import json

Base = declarative_base()


class Packet(Base):
    __tablename__ = "test"
    id: Mapped[int] = mapped_column(sa.Integer,primary_key=True)
    timestamp: Mapped[str] = mapped_column(sa.TIMESTAMP)
    source: Mapped[str] = mapped_column(sa.TEXT)
    destination: Mapped[str] = mapped_column(sa.TEXT)
    protocol: Mapped[str] = mapped_column(sa.TEXT)
    data: Mapped[str] = mapped_column(sa.TEXT,nullable=True)
    length: Mapped[int] = mapped_column(sa.Integer)
    
    def __repr__(self):
        return "<User(timestamp='%s', source='%s', destination='%s')>" % (
            self.timestamp,
            self.source,
            self.destination,
        )

class PacketHandler:
    engine = None
    def __init__(self,connection_url) -> None:
       
        self.engine = sa.create_engine(connection_url, echo=True, echo_pool="debug")
        pass

    def add_packet(self,packet:Packet):
        with Session(self.engine) as session:
            session.add(packet)
            session.commit()
    
    def add_tshark_packet(self,tpacket):
        packet_dict = self.serialize_packet(tpacket)
        pac = Packet(timestamp=packet_dict['timestamp'],source=packet_dict['source'],destination=packet_dict['destination'],protocol=packet_dict['protocol'],data=packet_dict['data'],length=packet_dict['length'])
        self.add_packet(pac)
        
    @staticmethod
    def serialize_packet(packet):
        packet_dict = {
            'timestamp': packet.sniff_time.isoformat(),
            'source': packet.ip.src if hasattr(packet, 'ip') else '',
            'destination': packet.ip.dst if hasattr(packet, 'ip') else '',
            'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else '',
            'length': int(packet.length),
            'data': packet.raw_mode_packet if hasattr(packet, 'raw_mode_packet') else ''
        }
        return packet_dict
    
    def add_multiple_packets(self, packet_list:list):
        with Session(self.engine) as session:
            session.add_all(packet_list)
            session.commit()
    
    def create_db(self):
        Base.metadata.create_all(bind=self.engine)
        #metadata.create_all(bind=self.engine)
        
    def drop_table(self):
        Base.metadata.drop_all()
        #metadata.drop_all(Packet)

if __name__ == "__main__":
    try:
        from datetime import datetime
        DATABASE_URL = "postgresql+pg8000://pyclient:pyclient@localhost/packets"
        ph = PacketHandler(DATABASE_URL)
        ph.create_db()
        time_now = datetime.now().isoformat()
        pac = Packet(timestamp=time_now,source='192.168.1.1',destination='192.168.1.2',protocol = 'TCP',data='',length=0)
        ph.add_packet(packet=pac)
    finally:
        ph.drop_table()
    