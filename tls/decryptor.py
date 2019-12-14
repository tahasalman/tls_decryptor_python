from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Decryptor:
    def __init__(self, data_handler, src_ip, dest_ip, src_port, dest_port):
        self.data_handler = data_handler
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port

    def start(self):
        output = []
        args = (self.src_ip, self.dest_ip, self.src_port, self.dest_port)

        packet_info = self.data_handler.get_next_from_app_data(*args)
        while packet_info:
            if packet_info['packet_type'] == 'client':
                key_name = 'client_write_key'
                iv_name = 'client_write_IV'
            else:
                key_name = 'server_write_key'
                iv_name = 'server_write_IV'

            key = self.data_handler.get_from_handshake_table(key_name, *args)
            iv = self.data_handler.get_from_handshake_table(iv_name, *args)

            cipher = Cipher(algorithm=algorithms.AES(key),
                            mode=modes.CBC(iv),
                            backend=default_backend())

            decryptor = cipher.decryptor()
            decrypted_packet = decryptor.update(packet_info['packet']) + decryptor.finalize()
            output.append(decrypted_packet[len(iv):])       # Skip the number of bytes used by IV
            packet_info = self.data_handler.get_next_from_app_data(*args)

        return output
