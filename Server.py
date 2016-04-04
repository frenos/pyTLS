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
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print('socket successfully')
        except socket.error as msg:
            print('ERROR with socket: ' + str(msg))

    def start_server(self):
        try:
            self.socket.bind((self.host, self.port))
            print('bind successfully')
        except socket.error as msg:
            print('ERROR with bind: ' + str(msg))

        try:
            self.socket.listen(5)
            print('listen successfully')
        except socket.error as msg:
            print('ERROR with listen' + str(msg))

        self.accept_connections()

    def accept_connections(self):
        while True:
            try:
                conn, addr = self.socket.accept()
            except socket.error as msg:
                print('ERROR with accept: ' + str(msg))

            print('receiving...')

            data = conn.recv(2048)

            self.dissect_message(data)

    def stop_server(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except socket.error as msg:
            print('ERROR with shutdown: ' + str(msg))

        try:
            self.socket.close()
        except socket.error as msg:
            print('ERROR with close: ' + str(msg))

    def dissect_message(self, data):
        print('message type\t: ' + struct.unpack('!B', data[0]))


def gracefull_shutdown(sig, dummy):
    server.stop_server()
    sys.exit(1)


signal.signal(signal.SIGINT, gracefull_shutdown)

server = Server('', 443)
server.start_server()

server.stop_server()
