from packets import TLSHeader, TLSHandshakeHeader


class Parser:

    CLIENT_RANDOM_LENGTH = 32
    SERVER_RANDOM_LENGTH = 32
    SERVER_IP = '127.0.0.1'
    SERVER_PORT = '8443'

    def __init__(self, tcp_data, data_handler,
                 src_ip, dest_ip, src_port, dest_port):
        self.tcp_data = tcp_data
        self.tcp_length = len(tcp_data)
        self.data_handler = data_handler
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port

    def separate_packets(self):
        total_covered = 0
        packets = []
        data = self.tcp_data
        while total_covered < self.tcp_length:
            header = TLSHeader(data)
            covered = header.bytes_used + header.length
            packets.append(data[:covered])
            data = data[covered:]
            total_covered += covered
        return packets

    def parse(self):
        packets = self.separate_packets()
        args = (self.src_ip, self.dest_ip, self.src_port, self.dest_port)

        for packet in packets:
            tls_header = TLSHeader(packet)
            packet = packet[tls_header.bytes_used:]

            if tls_header.record_type == 23:    # encrypted application data
                if self.src_ip == Parser.SERVER_IP and self.src_port == Parser.SERVER_PORT: # need to add IP too later
                    packet_type = 'server'
                else:
                    packet_type = 'client'

                self.data_handler.add_to_app_data(packet_type, packet, *args)

            elif tls_header.record_type == 21:  # alert message ignore for now
                pass

            elif tls_header.record_type == 20:  # change cipher spec
                pass

            elif tls_header.record_type == 22: # handshake data
                self.data_handler.update_handshake_table('packets', packet, True, *args)
                self.parse_handshake_data(packet)

            else:
                print("I shouldn't be printing this!")

        return

    def parse_handshake_data(self, data):
        tls_handshake_header = TLSHandshakeHeader(data)
        handshake_type = tls_handshake_header.handshake_type
        args = (self.src_ip, self.dest_ip, self.src_port, self.dest_port)

        data = data[tls_handshake_header.bytes_used:]

        print("Handshake Type: " + str(handshake_type))

        if handshake_type == 1:         # 0x01 client hello
            # extract client random
            client_random = data[:Parser.CLIENT_RANDOM_LENGTH]
            self.data_handler.update_handshake_table('client_random', client_random, False, *args)

        elif handshake_type == 2:       # 0x02 server hello
            # extract server random
            server_random = data[:Parser.SERVER_RANDOM_LENGTH]
            self.data_handler.update_handshake_table('server_random', server_random, False, *args)

        elif handshake_type == 11:      # 0x0b server certificate
            pass

        elif handshake_type == 12:      # 0x0c server key exchange (does not occur in TLS RSA)
            pass

        elif handshake_type == 14:      # 0x0e server hello done
            pass

        elif handshake_type == 16:      # 0x10 client key exchange
            # extract encrypted pre-master secret
            data = data[:] # skip first 2 bytes as they contain length
            encrypted_pre_master_secret = data[:256]
            self.data_handler.update_handshake_table('enc_p_master_secret', encrypted_pre_master_secret, False, *args)
            self.data_handler.lock_field('packets', *args)
        else:
            print("Something went wrong. Handshake type: " + str(handshake_type))

        return data

