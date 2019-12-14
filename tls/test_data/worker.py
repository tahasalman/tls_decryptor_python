import os


def _hex_escape(stream):
    output = ""
    escapeSeq = "\\x"

    for i in range(0, len(stream) - 2, 2):
        output += escapeSeq + stream[i:i+2]

    return output


def get_packet(file_path):
    '''
    all files store packets in one line of hex stream
    '''
    output = None

    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as fp:
                output = bytes.fromhex(fp.read())
        except IOError:
            pass
    return output


def _test():
    print(get_packet('client_hello'))
    pass


if __name__ == "__main__":
    _test()