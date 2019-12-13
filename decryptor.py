from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import config


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

def hmac_sha256_prf(secret, label, seed, length):
    seed = label + seed
    result = b''

    h = hmac.HMAC(secret, hashes.SHA256(), default_backend())
    a = seed
    while len(result) < length:
        # print(f'AAAAA: {a}')
        # print(f'SEEED: {seed}')
        h.update(a)
        a = h.copy().finalize()
        h.update(a + seed)
        p = h.copy().finalize()
        result += p
    return result


class TLSDecryptor:
    def __init__(self, client_random, server_random, enc_pre_master_secret,
                 mac_key_length, key_length, iv_length, private_key=None):
        self.client_random = client_random
        self.server_random = server_random
        self.mac_key_length = mac_key_length
        self.key_length = key_length
        self.iv_length = iv_length
        if private_key:
            self.private_key = private_key
        else:
            self.private_key = read_private_key(config.PRIVATE_KEY_FILE)
        self.pre_master_secret = self.private_key.decrypt(enc_pre_master_secret,
                                                          padding.PKCS1v15())
        self._derive_keys()

    def _derive_keys(self):
        '''
        Derives all all the keys and saves them as instance attributes
        Follows the steps specified in RFC 2546
        '''
        self.master_secret = hmac_sha256_prf(self.pre_master_secret,
                                        b'master secret',
                                        self.client_random + self.server_random,
                                        length = 48)[:48]                           # Master Secret is of length 48

        key_block = hmac_sha256_prf(self.master_secret,
                                    b'key expansion',
                                    self.server_random + self.client_random,
                                    (2*self.mac_key_length + 2*self.key_length + 2*self.iv_length))

        self.client_write_mac_key = key_block[:self.mac_key_length]
        key_block = key_block[self.mac_key_length:]
        self.server_write_mac_key = key_block[:self.mac_key_length]
        key_block = key_block[self.mac_key_length:]

        self.client_write_key = key_block[:self.key_length]
        key_block = key_block[self.key_length:]
        self.server_write_key = key_block[:self.key_length]
        key_block = key_block[self.key_length:]

        self.client_write_IV = key_block[:self.iv_length]
        key_block = key_block[self.iv_length:]
        self.server_write_IV = key_block[:self.iv_length]

        return

    def encrypt_client_data(self, data):
        cipher = Cipher(algorithm=algorithms.AES(self.client_write_key),
                        mode=modes.CBC(self.client_write_IV),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt_client_data(self, data):
        cipher = Cipher(algorithm=algorithms.AES(self.client_write_key),
                        mode=modes.CBC(self.client_write_IV),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def encrypt_server_data(self, data):
        cipher = Cipher(algorithm=algorithms.AES(self.server_write_key),
                        mode=modes.CBC(self.server_write_IV),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt_server_data(self, data):
        cipher = Cipher(algorithm=algorithms.AES(self.server_write_key),
                        mode=modes.CBC(self.server_write_IV),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()




