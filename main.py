from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import config

from tls.parser import TLSParser
from decryptor import TLSDecryptor


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
    print("\nSEED:\n")
    print(seed)
    print(seed.hex())
    print(hexEscape(seed.hex()))
    print(len(seed))
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

def hexEscape(stream):
    output = ""
    escapeSeq = "\\x"

    for i in range(0, len(stream) - 2, 2):
        output += escapeSeq + stream[i:i+2]

    return output

def test():
    private_key = read_private_key("keys/privkey.pem")
    public_key = read_public_key("keys/pubkey.pem")

    client_random = config.CLIENT_RANDOM
    server_random = config.SERVER_RANDOM

    print("Encrypted PRE MASTER SECRET")
    premaster_secret = config.ENCRYPTED_PREMASTER_SECRET
    print(len(premaster_secret))

    premaster_secret = private_key.decrypt(
        premaster_secret,
        padding.PKCS1v15()
    )
    print("DECRYPTED PREMASTER SECRET")
    print(premaster_secret)
    print(premaster_secret.hex())
    print(hexEscape(premaster_secret.hex()))
    print(len(premaster_secret))

    master_secret = _p_hash(hashes.SHA256(), premaster_secret, config.EXTENDED_MASTER_SECRET_SEED, 48)
    print("MASTER SECRET")
    print(master_secret)
    print(master_secret.hex())
    print(hexEscape(master_secret.hex()))
    print(len(master_secret))

    ## Generate key block to derive keys from
    MAC_KEY_LENGTH = 20
    SYMMETRIC_KEY_LENGTH = 16
    IV_LENGTH = 16

    key_block = _p_hash(hashes.SHA256(), master_secret,
                    b'key expansion' + server_random + client_random,
                    (2*MAC_KEY_LENGTH + 2*SYMMETRIC_KEY_LENGTH + 2*IV_LENGTH ))

    print(f'KEY BLOCK\n\n {key_block}')
    print(f'IN HEX\n {key_block.hex()}')
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


    print("\nCLIENT WRITE KEY\n")
    print(client_write_key)
    print(client_write_key.hex())
    print(len(client_write_key))
    print(client_write_IV.hex())


    ## Now we do AES_128_CBC Decryption

    # Decrypt Client Data
    client_cipher = Cipher(algorithm=algorithms.AES(client_write_key),
                    mode=modes.CBC(client_write_IV),
                    backend=default_backend())
    client_decryptor = client_cipher.decryptor()
    client_decrypted_data = client_decryptor.update(config.CLIENT_ENCRYPTED_DATA) + client_decryptor.finalize()

    print("\nDECRYPTED DATA\n")

    print(client_decrypted_data)
    print(client_decrypted_data.hex())
    print(len(client_decrypted_data))
    print(client_decrypted_data[16:].hex())
    # Decrypt Server Data



def test_PRF(secret, length=48):
    seed = config.EXTENDED_MASTER_SECRET_SEED
    print("\nSEED:\n")
    print(seed)
    print(seed.hex())
    print(hexEscape(seed.hex()))
    print(len(seed))
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




def _p_hash(hash_algorithm, secret, seed, output_length):
    """
    A seed expansion function that uses a single hash function to expand a
    secret and seed into the number of bytes specified by output_length.
    """
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
    """
    a() is defined as:
        a(0) = seed
        a(i) = HMAC_hash(secret, A(i-1))
    """
    if n == 0:
        return seed
    else:
        h = hmac.HMAC(secret, hash_algorithm, default_backend())
        h.update(_a(secret, hash_algorithm, n - 1, seed))
        return h.finalize()


def prf(secret, label, seed, hash_algorithm, output_length):
    """
    A construction to expand secrets into blocks of data for the purposes of
    key generation or validation.
    This pseudo-random function (PRF) takes as input a secret, a seed, an
    identifying label and a hash algorithm and produces an output of length
    specified in output_length.
    :param secret: Secret key as ``bytes``.  The key should be randomly
        generated bytes and is recommended to be equal in length to the
        digest_size of the hash function chosen. You must keep the key secret.
    :type secret: :py:class:`bytes`
    :param label: An ASCII string.
    :type label: :py:class:`bytes`
    :param seed: The seed as ``bytes``.
    :type label: :py:class:`bytes`
    :param hash_algorithm: The hash algorithm to use with HMAC.
    :type hash_algorithm: a
        :py:class:`cryptography.hazmat.primitives.hashes.HashAlgorithm`
        provider.
    :param output_length: The number of bytes to expand the seed into.
    :type output_length: :py:class:`int`
    """
    return _p_hash(hash_algorithm, secret, label + seed, output_length)
def _p_hash(hash_algorithm, secret, seed, output_length):
    """
    A seed expansion function that uses a single hash function to expand a
    secret and seed into the number of bytes specified by output_length.
    """
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
    """
    a() is defined as:
        a(0) = seed
        a(i) = HMAC_hash(secret, A(i-1))
    """
    if n == 0:
        return seed
    else:
        h = hmac.HMAC(secret, hash_algorithm, default_backend())
        h.update(_a(secret, hash_algorithm, n - 1, seed))
        return h.finalize()


def prf(secret, label, seed, hash_algorithm, output_length):
    """
    A construction to expand secrets into blocks of data for the purposes of
    key generation or validation.
    This pseudo-random function (PRF) takes as input a secret, a seed, an
    identifying label and a hash algorithm and produces an output of length
    specified in output_length.
    :param secret: Secret key as ``bytes``.  The key should be randomly
        generated bytes and is recommended to be equal in length to the
        digest_size of the hash function chosen. You must keep the key secret.
    :type secret: :py:class:`bytes`
    :param label: An ASCII string.
    :type label: :py:class:`bytes`
    :param seed: The seed as ``bytes``.
    :type label: :py:class:`bytes`
    :param hash_algorithm: The hash algorithm to use with HMAC.
    :type hash_algorithm: a
        :py:class:`cryptography.hazmat.primitives.hashes.HashAlgorithm`
        provider.
    :param output_length: The number of bytes to expand the seed into.
    :type output_length: :py:class:`int`
    """
    return _p_hash(hash_algorithm, secret, label + seed, output_length)

def main():
    decryptor = TLSDecryptor(
        client_random=config.CLIENT_RANDOM,
        server_random=config.SERVER_RANDOM,
        enc_pre_master_secret=config.ENCRYPTED_PREMASTER_SECRET,
        mac_key_length=20,
        key_length=16,
        iv_length=16
    )

    decrypted_client_data = decryptor.decrypt_client_data(config.CLIENT_ENCRYPTED_DATA)

    print("Attempt at decrypting client data: ")
    print(decrypted_client_data.hex())
    print(f'Length: {len(decrypted_client_data)}\n\n')

    decrypted_server_data = decryptor.decrypt_server_data(config.SERVER_ENCRYPTED_DATA)
    print("Attempt at decrypting server data:")
    print(decrypted_server_data.hex())
    print(f'Length: {len(decrypted_server_data)}\n\n')

    # print("Commencing Tests:\n")
    #
    # random_data = b"Please encrypt me! I feel sad :("
    # print(f'This is our message: {random_data}')
    # encrypted_data = decryptor.encrypt_client_data(random_data)
    # print(f'This is our encrypted message: {encrypted_data}')
    # decrypted_data = decryptor.decrypt_client_data(encrypted_data)
    # print(f'This is our decrypted message: {decrypted_data}')

def main2():
    client_hello_packet = config.CLIENT_HELLO_PACKET
    client_key_exchange_packet = config.CLIENT_KEY_EXCHANGE_PACKET

    parser = TLSParser(client_hello_packet, 517, '127.1.0.1', '127.1.0.1', '53432', '8443')
    parser.parse()

    parser = TLSParser(client_key_exchange_packet, 517, '127.1.0.1', '127.1.0.1', '53432', '8443')
    parser.parse()

    print(TLSParser.HANDSHAKE_TABLE)

if __name__ == "__main__":
    test()