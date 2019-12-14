class DataHandler:
    def __init__(self):
        self.handshake_table = dict()
        self.app_data_table = dict()
        self.locked_tracker = dict()

    def lock_field(self, field_name, *args):
        key = DataHandler.get_key(*args)

        if key not in self.locked_tracker:
            self.locked_tracker[key] = set()
        self.locked_tracker[key].add(field_name)

    def update_handshake_table(self, field_name, field_value, append, *args):
        key = DataHandler.get_key(*args)
        if key in self.locked_tracker and field_name in self.locked_tracker[key]:
            return
        else:
            if key not in self.handshake_table:
                self.handshake_table[key] = \
                    {
                        'client_random': '',
                        'server_random': '',
                        'cipher_suite': '',
                        'enc_p_master_secret': '',
                        'p_master_secret': '',
                        'master_secret': '',
                        'client_write_mac': '',
                        'server_write_mac': '',
                        'client_write_key': '',
                        'server_write_key': '',
                        'client_write_IV': '',
                        'server_write_IV': '',
                        'packets': b'',
                        'session_hash': ''
                    }
            if append:
                self.handshake_table[key][field_name] += field_value
            else:
                self.handshake_table[key][field_name] = field_value

    def add_to_app_data(self, packet_type, packet, *args):
        key = DataHandler.get_key(*args)

        if key not in self.app_data_table:
            self.app_data_table[key] = []
        self.app_data_table[key].append(
            {'packet_type': packet_type,
            'packet': packet
            })

    def get_next_from_app_data(self, *args):
        result = None
        key = DataHandler.get_key(*args)
        if key in self.app_data_table and self.app_data_table[key]:
            result = self.app_data_table[key].pop(0)
        return result

    def get_from_handshake_table(self, field_name, *args):
        result = None
        key = DataHandler.get_key(*args)
        if key in self.handshake_table and field_name in self.handshake_table[key]:
            result = self.handshake_table[key][field_name]
        return result

    @staticmethod
    def get_key(src_ip, dest_ip, src_port, dest_port):
        if src_ip + src_port < dest_ip + dest_port:
            return src_ip + src_port + dest_ip + dest_port
        else:
            return dest_ip + dest_port + src_ip + src_port
