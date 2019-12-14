import struct


class TLSHeader:
    def __init__(self, tcp_data):
        self.bytes_used = 5
        self.record_type,\
        self.protocol_version,\
        self.length = struct.unpack('! B H H', tcp_data[:self.bytes_used])


class TLSHandshakeHeader:
    def __init__(self, data):
        self.bytes_used = 6
        self.handshake_type = int.from_bytes(data[:1], "big")
        ## Should add other fields later
        # length
        # protocol version
