from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import config


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

def test():
    private_key = read_private_key("keys/privkey.pem")
    public_key = read_public_key("keys/pubkey.pem")

    print(private_key)
    print(public_key)


    premaster_secret = config.ENCRYPTED_PREMASTER_SECRET
    print(len(premaster_secret))

    plaintext = private_key.decrypt(
        premaster_secret,
        padding.PKCS1v15()
    )

    print(plaintext)
    print(len(plaintext))

def main():
    private_key = load_private_key()
    public_key = load_public_key()
    print(public_key)
    print(private_key)

if __name__ == "__main__":
    test()