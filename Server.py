import signal
import socket
import struct
import sys


class Server:
    TLS_HANDSHAKE = 22  # 0x16

    def __init__(self, host='', port=443):
        self.host = host
        self.port = port
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as msg:
            print('ERROR with socket: ' + str(msg))

    def start_server(self):
        try:
            self.socket.bind((self.host, self.port))
        except socket.error as msg:
            print('ERROR with bind: ' + str(msg))

        self.accept_connections()

    def accept_connections(self):
        while True:
            print('Wait for connections')
            self.socket.listen(5)

            try:
                conn, addr = self.socket.accept()
            except socket.error as msg:
                print('ERROR with accept: ' + str(msg))

            print('RECV')

            data = conn.recv(2048)

            length = len(data)
            print('First Byte : ' + str(length))

            try:
                # string = data.decode('ISO-8859-1')
                string = struct.unpack(str(length) + 'c', data)  # repr(data)
                # first_token = string.split(' ')[0]
                # print('First token: ' + first_token)
                print('Request    : ' + string)
            except Exception as msg:
                print('ERROR with decode: ' + str(msg))

    def stop_server(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except socket.error as msg:
            print('ERROR with shutdown: ' + str(msg))

        try:
            self.socket.close()
        except socket.error as msg:
            print('ERROR with close: ' + str(msg))


def gracefull_shutdown(sig, dummy):
    server.stop_server()
    sys.exit(1)


signal.signal(signal.SIGINT, gracefull_shutdown)

server = Server('', 1337)
server.start_server()

server.stop_server()
