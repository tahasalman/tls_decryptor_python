import struct

CLIENT_RANDOM_LENGTH = 32
SERVER_RANDOM_LENGTH = 32

class EncryptedPacket:
    def __init__(self, packet_type, data):
        self.packet_type = packet_type
        self.data = data

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

class TLSParser:
    HANDSHAKE_TABLE = {}
    APPLICATION_DATA_TABLE = {}

    def __init__(self, tcp_data, tcp_length, src_ip, dest_ip, src_port, dest_port):
        self.tcp_data = tcp_data
        self.tcp_length = tcp_length
        self.remaining_length = tcp_length
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port

    def _update_length_and_data(self, data, parsed_length):
        data = data[parsed_length:]
        self.remaining_length -= parsed_length
        return data

    def _is_packet_empty(self):
        return self.tcp_length <=0

    def _get_key(self):
        if self.src_ip < self.dest_ip:
            return self.src_ip + self.src_port + self.dest_ip + self.dest_port
        else:
            return self.dest_ip + self.dest_port + self.src_ip + self.src_port

    def _create_handshake_entry(self):
        if self._get_key() not in TLSParser.HANDSHAKE_TABLE:
            TLSParser.HANDSHAKE_TABLE[self._get_key()] = \
                {
                    'client_random': '',
                    'server_random': '',
                    'encrypted_pre_master_secret': '',
                    'pre_master_secret': '',
                    'cipher_suite': '',
                    'master_secret': '',
                    'client_write_key': '',
                    'server_write_key': '',
                    'packets': b'',
                    'session_hash': ''
                }
        return

    def parse(self):
        # subtract length somewhere
        data = self.tcp_data
        tls_header = TLSHeader(self.tcp_data)

        print(f'Header Type: {tls_header.record_type}')
        print(f'Protocol Version: {tls_header.protocol_version}')
        print(f'Length: {tls_header.length}')

        data = self._update_length_and_data(data, tls_header.bytes_used)

        if tls_header.record_type == 20: # change cipher spec
            pass
        elif tls_header.record_type == 21: # alert
            pass
        elif tls_header.record_type == 22:  # handshake data
            self._create_handshake_entry()
            self.parse_handshake_data(data)
        elif tls_header.record_type == 23: # encrypted app data
            pass
        else:
            print("Something went wrong :(")
        return

    def parse_handshake_data(self, data):
        TLSParser.HANDSHAKE_TABLE[self._get_key()]['packets'] += data

        tls_handshake_header = TLSHandshakeHeader(data)
        data = self._update_length_and_data(data, tls_handshake_header.bytes_used)

        handshake_type = tls_handshake_header.handshake_type
        print(f'Handshake type: {handshake_type}')

        if handshake_type == 1:         # 0x01 client hello
            # extract client random
            client_random = data[:CLIENT_RANDOM_LENGTH]
            TLSParser.HANDSHAKE_TABLE[self._get_key()]['client_random'] = client_random
            data = self._update_length_and_data(data, CLIENT_RANDOM_LENGTH)

        elif handshake_type == 2:       # 0x02 server hello
            # extract server random
            server_random = data[:SERVER_RANDOM_LENGTH]
            TLSParser.HANDSHAKE_TABLE[self._get_key()]['server_random'] = server_random
            data = self._update_length_and_data(data, SERVER_RANDOM_LENGTH)

        elif handshake_type == 11:      # 0x0b server certificate
            pass

        elif handshake_type == 12:      # 0x0c server key exchange (does not occur in TLS RSA)
            pass

        elif handshake_type == 14:      # 0x0e server hello done
            pass

        elif handshake_type == 16:      # 0x10 client key exchange
            # extract encrypted pre-master secret
            data = self._update_length_and_data(data, 2)
            encrypted_pre_master_secret = data[:256]
            TLSParser.HANDSHAKE_TABLE[self._get_key()]['encrypted_pre_master_secret'] = encrypted_pre_master_secret
            data = self._update_length_and_data(data, 256)
        else:
            print("Something went wrong")

        return data