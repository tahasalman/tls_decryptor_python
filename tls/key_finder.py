from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def read_private_key(filename, password=None):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            data=key_file.read(),
            password=password,
            backend=default_backend()
        )
    return private_key


def read_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            data=key_file.read(),
            backend=default_backend()
        )
    return public_key


def _p_hash(hash_algorithm, secret, seed, output_length):
    result = bytearray()
    i = 1
    while len(result) < output_length:
        h = hmac.HMAC(secret, hash_algorithm, default_backend())
        h.update(_a(secret, hash_algorithm, i, seed))
        h.update(seed)
        result.extend(h.finalize())
        i += 1
    return bytes(result[:output_length])


def _a(secret, hash_algorithm, n, seed):
    if n == 0:
        return seed
    else:
        h = hmac.HMAC(secret, hash_algorithm, default_backend())
        h.update(_a(secret, hash_algorithm, n - 1, seed))
        return h.finalize()


def prf(secret, label, seed, hash_algorithm, output_length):
    return _p_hash(hash_algorithm, secret, label + seed, output_length)


class KeyFinder:
    def __init__(self, data_handler, private_key_file_path,
                 src_ip, dest_ip, src_port, dest_port,
                 mac_key_length, symmetric_key_length, iv_length):
        self.data_handler = data_handler
        self.private_key = read_private_key(private_key_file_path)
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.mac_key_length = mac_key_length
        self.symmetric_key_length = symmetric_key_length
        self.iv_length = iv_length

    def find(self):
        args = (self.src_ip, self.dest_ip, self.src_port, self.dest_port)

        client_random = self.data_handler.get_from_handshake_table(
            'client_random', *args)
        server_random = self.data_handler.get_from_handshake_table(
            'server_random', *args)
        enc_p_master_secret = self.data_handler.get_from_handshake_table(
            'enc_p_master_secret', *args)
        packets  =self.data_handler.get_from_handshake_table(
            'packets', *args)

        if not all((client_random, server_random, enc_p_master_secret, packets)):
            print("MISSING INFO ERROR ERROR HANDLE ME")
            return

        # Retrieve pre-master secret
        p_master_secret = self.private_key.decrypt(
            enc_p_master_secret,
            padding.PKCS1v15()
        )
        self.data_handler.update_handshake_table(
            'p_master_secret', p_master_secret, False, *args)

        # Calculate the session hash
        hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash.update(packets[:])
        session_hash = hash.finalize()
        self.data_handler.update_handshake_table(
            'session_hash', session_hash, False, *args)

        # Derive the master secret
        master_secret = prf(secret=p_master_secret,
                            label=b'extended master secret',
                            seed=session_hash,
                            hash_algorithm=hashes.SHA256(),
                            output_length=48)
        self.data_handler.update_handshake_table(
            'master_secret', master_secret, False, *args)

        # Derive all the remaining keys
        key_block_length = 2 * self.mac_key_length + 2 * self.symmetric_key_length + 2 * self.iv_length
        key_block = prf(secret=master_secret,
                        label=b'key expansion',
                        seed=server_random + client_random,
                        hash_algorithm=hashes.SHA256(),
                        output_length=key_block_length)

        client_write_mac = key_block[:self.mac_key_length]
        key_block = key_block[self.mac_key_length:]

        server_write_mac = key_block[:self.mac_key_length]
        key_block = key_block[self.mac_key_length:]

        client_write_key = key_block[:self.symmetric_key_length]
        key_block = key_block[self.symmetric_key_length:]

        server_write_key = key_block[:self.symmetric_key_length]
        key_block = key_block[self.symmetric_key_length:]

        client_write_IV = key_block[:self.iv_length]
        key_block = key_block[self.iv_length:]

        server_write_IV = key_block[:self.iv_length]

        self.data_handler.update_handshake_table(
            'client_write_mac', client_write_mac, False, *args)
        self.data_handler.update_handshake_table(
            'server_write_mac', server_write_mac, False, *args)
        self.data_handler.update_handshake_table(
            'client_write_key', client_write_key, False, *args)
        self.data_handler.update_handshake_table(
            'server_write_key', server_write_key, False, *args)
        self.data_handler.update_handshake_table(
            'client_write_IV', client_write_IV, False, *args)
        self.data_handler.update_handshake_table(
            'server_write_IV', server_write_IV, False, *args)
