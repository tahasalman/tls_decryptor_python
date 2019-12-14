from data_handler import DataHandler
from test_data.worker import get_packet
from parser import Parser
from key_finder import KeyFinder
from decryptor import Decryptor

MAC_KEY_LENGTH = 20
SYMMETRIC_KEY_LENGTH = 16
IV_LENGTH = 16


def main():
    SERVER_IP = '127.0.0.1'
    CLIENT_IP = '127.0.0.1'
    SERVER_PORT = '8443'
    CLIENT_PORT = '53432'

    data_handler = DataHandler()

    client_hello = get_packet('test_data/data/client_hello')
    server_hello = get_packet('test_data/data/server_hello')
    key_exchange = get_packet('test_data/data/client_key_exchange')
    client_encrypted_data1 = get_packet('test_data/data/client_encrypted_data1')
    server_encrypted_data1 = get_packet('test_data/data/server_encrypted_data1')


    print("Starting Parser: ")
    Parser(client_hello, data_handler,
           CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT).parse()
    Parser(server_hello, data_handler,
           SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT).parse()
    Parser(key_exchange, data_handler,
           CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT).parse()
    Parser(client_encrypted_data1, data_handler,
           CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT).parse()
    Parser(server_encrypted_data1, data_handler,
           SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT).parse()


    print("\nStarting Key Finder:")
    KeyFinder(data_handler, '../keys/privkey.pem',
              CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
              MAC_KEY_LENGTH, SYMMETRIC_KEY_LENGTH, IV_LENGTH).find()

    print("Handshake Table:\n")
    print(data_handler.handshake_table)

    print("Application Data:\n")
    print(data_handler.app_data_table)

    print("\nStarting Decryptor\n")
    decryptor = Decryptor(data_handler,
                          CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
    output = decryptor.start()

    for packet in output:
        print(f'packet {packet}\n')
    print(len(output))

if __name__ == "__main__":
    main()
