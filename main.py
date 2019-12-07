from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import config

from decryptor import TLS_Decryptor


def read_private_key(filename, password=None):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            data=key_file.read(),
            password=password,
            backend=default_backend()
        )
    return private_key

def read_public_key(filename, password=None):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            data=key_file.read(),
            backend=default_backend()
        )
    return public_key

def load_private_key():
    private_key = serialization.load_pem_private_key(
        data=bytes(config.PRIVATE_KEY, 'utf-8'),
        password=None,
        backend=default_backend()
    )
    return private_key

def load_public_key():
    public_key = serialization.load_pem_public_key(
        data=bytes(config.PUBLIC_KEY, 'utf-8'),
        backend=default_backend()
    )
    return public_key


def PRF(secret, label, seed, length=48):
    seed = label + seed
    result = b""

    h = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
    a = seed
    while len(result) < length:
        h.update(a)
        a = h.copy().finalize()
        h.update(a+seed)
        p = h.copy().finalize()
        result += p
    return result

    #
    # a0 = seed
    # a1 = hmac.new(secret, a0, hashlib.sha256)
    # a2 = hmac.new(secret, a1, hashlib.sha256)
    # p1 = hmac.new(secret, a1+seed, hashlib.sha256)
    # p2 = hmac.new(secret, a2+seed, hashlib.sha256)
    # return (p1 + p2[:16])

def test():
    private_key = read_private_key("keys/privkey.pem")
    public_key = read_public_key("keys/pubkey.pem")

    client_random = config.CLIENT_RANDOM
    server_random = config.SERVER_RANDOM


    premaster_secret = config.ENCRYPTED_PREMASTER_SECRET
    print(len(premaster_secret))

    premaster_secret = private_key.decrypt(
        premaster_secret,
        padding.PKCS1v15()
    )

    print(premaster_secret)
    print(len(premaster_secret))

    master_secret = PRF(premaster_secret,
                        b"master secret",
                        client_random + server_random)[:48]
    print(master_secret)
    print(len(master_secret))

    ## Generate key block to derive keys from
    MAC_KEY_LENGTH = 20
    SYMMETRIC_KEY_LENGTH = 16
    IV_LENGTH = 16

    key_block = PRF(master_secret,
                    b'key expansion',
                    server_random + client_random,
                    (2*MAC_KEY_LENGTH + 2*SYMMETRIC_KEY_LENGTH + 2*IV_LENGTH ))

    print(f'KEY BLOCK\n\n {key_block}')
    print(f'LENGTH: {len(key_block)}')
    client_write_mac = key_block[:MAC_KEY_LENGTH]
    key_block = key_block[MAC_KEY_LENGTH:]
    server_write_mac = key_block[:MAC_KEY_LENGTH]
    key_block = key_block[MAC_KEY_LENGTH:]
    client_write_key = key_block[:SYMMETRIC_KEY_LENGTH]
    key_block = key_block[SYMMETRIC_KEY_LENGTH:]
    server_write_key = key_block[:SYMMETRIC_KEY_LENGTH]
    key_block = key_block[SYMMETRIC_KEY_LENGTH:]
    client_write_IV = key_block[:IV_LENGTH]
    key_block = key_block[IV_LENGTH:]
    server_write_IV = key_block[:IV_LENGTH]

    print(client_write_key)
    print(len(client_write_key))
    print(len(server_write_IV))


    ## Now we do AES_128_CBC Decryption

    # Decrypt Client Data
    client_cipher = Cipher(algorithm=algorithms.AES(client_write_key),
                    mode=modes.CBC(client_write_IV),
                    backend=default_backend())
    client_decryptor = client_cipher.decryptor()
    client_decrypted_data = client_decryptor.update(config.CLIENT_ENCRYPTED_DATA) + client_decryptor.finalize()

    print(client_decrypted_data)
    print(client_decrypted_data.hex())
    print(len(client_decrypted_data))
    # Decrypt Server Data




def main():
    decryptor = TLS_Decryptor(
        client_random=config.CLIENT_RANDOM,
        server_random=config.SERVER_RANDOM,
        enc_pre_master_secret=config.ENCRYPTED_PREMASTER_SECRET,
        mac_key_length=20,
        key_length=16,
        iv_length=16
    )

    decrypted_client_data = decryptor.decrypt_client_data(config.CLIENT_ENCRYPTED_APP_DATA)
    print(decrypted_client_data.hex())
    print(len(decrypted_client_data))

if __name__ == "__main__":
    main()