import logging
import signal
import socket
import ssl
import struct
import sys
import time

import Parser


class Server:
    TLS_HANDSHAKE = 22  # 0x16
    TYPE_CLIENT_HELLO = 1  #

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    fileHandler = logging.FileHandler('server.log')
    fileHandler.setLevel(logging.DEBUG)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fileHandler.setFormatter(formatter)
    consoleHandler.setFormatter(formatter)

    # logger.addHandler(fileHandler)
    logger.addHandler(consoleHandler)

    parser = Parser.Parser()

    def __init__(self, host='', port=443):
        self.host = host
        self.port = port
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            Server.logger.debug('socket successfully')
        except socket.error as msg:
            Server.logger.error('socket: %s' % msg)

    def start_server(self):
        try:
            self.socket.bind((self.host, self.port))
            Server.logger.debug('bind successfully')
        except socket.error as msg:
            Server.logger.error('bind: %s' % msg)
            sys.exit(-1)

        try:
            self.socket.listen(5)
            Server.logger.debug('listen successfully')
        except socket.error as msg:
            Server.logger.error('listen: %s' % msg)

        self.accept_connections()

    def accept_connections(self):

        while True:
            try:
                conn, addr = self.socket.accept()
            except socket.error as msg:
                Server.logger.error('accept: %s' % msg)

            Server.logger.info('receiving...')

            data = conn.recv(2048)

            print(len(data))

            self.dissect_message(conn, data)

    def stop_server(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except socket.error as msg:
            Server.logger.error('shutdown: %s' % msg)

        try:
            self.socket.close()
        except socket.error as msg:
            Server.logger.error('close: %s' % msg)

    """ DISSECT EVERY MESSAGE HERE """

    def dissect_message(self, conn, data):
        Server.logger.debug('Try to dissect raw packet')

        header = self.parser.get_parsed_record_layer_header(data)

        if header['content_type'] == self.TLS_HANDSHAKE:
            self.dissect_handshake(conn, data)

    """ DISSECT HANDSAKE HERE """

    def dissect_handshake(self, conn, data):
        Server.logger.debug('Try to dissect handshake')

        ssl_data = self.parser.get_ssl_data(data)

        print(ssl_data)

        if ssl_data['handshake_type'] == self.TYPE_CLIENT_HELLO:
            print(' CLIENT HELLO')
            server_hello = self.pack_server_hello(ssl_data)
            conn.send(server_hello)
            print('DONE')

    def pack_server_hello(self, ssl_data):
        Server.logger.debug('pack server_hello here')

        buf = bytes()
        message_length = 0
        handshake_protocol_length = 0
        handshake_protocol_length_bytes = bytes()
        message_length_bytes = bytes()

        stack = []

        extension, extension_length = self.create_server_hello_extension(ssl_data)
        handshake_protocol_length += extension_length
        stack.append(extension)

        extension_length = struct.pack('!H', extension_length)
        handshake_protocol_length += 2
        stack.append(extension_length)

        compression_method = struct.pack('!B', 0)
        handshake_protocol_length += 1
        stack.append(compression_method)

        cipher_suites = struct.pack('!H', 49202)
        handshake_protocol_length += 2
        stack.append(cipher_suites)

        session_id_length = struct.pack('!B', 0)
        handshake_protocol_length += 1
        stack.append(session_id_length)

        random_bytes = ssl.RAND_bytes(28)
        handshake_protocol_length += 28
        stack.append(random_bytes)

        print(str(random_bytes))

        timestamp = struct.pack('!I', int(time.time()))
        handshake_protocol_length += 4
        stack.append(timestamp)

        max_tls_version = struct.pack('!H', 771)
        handshake_protocol_length += 2
        stack.append(max_tls_version)

        for i in (16, 8, 0):
            hexa = (handshake_protocol_length >> i) & 0xff

            handshake_protocol_length_bytes += struct.pack('!B', hexa)

        stack.append(handshake_protocol_length_bytes)
        message_length = handshake_protocol_length
        message_length += 3

        handshake_protocol = struct.pack('!B', 2)
        message_length += 1
        stack.append(handshake_protocol)

        message_length_bytes = struct.pack('!H', message_length)
        stack.append(message_length_bytes)

        min_tls_version = struct.pack('!H', 771)
        stack.append(min_tls_version)

        content_type = struct.pack('!B', 22)
        stack.append(content_type)

        while len(stack) != 0:
            buf += stack.pop()

        return buf

    def create_server_hello_extension(self, ssl_data):

        extension_buf = bytes()
        extension_length = 0

        server_name = 0
        server_name_data_length = 0
        extension_length += 4
        extension_buf += struct.pack('!HH', server_name, server_name_data_length)

        renegotiation_info = 65281
        renegotiation_info_data_length = 1
        renegotiation_info_extension_length = 0
        extension_length += (4 + renegotiation_info_data_length)
        extension_buf += struct.pack('!HHB', renegotiation_info, renegotiation_info_data_length,
                                     renegotiation_info_extension_length)

        ec_point_formats = 11
        ec_point_formats_data_length = 3
        ec_point_formats_length = 2
        ec_point_format_uncompress = 0
        ec_point_format_anisx962_compressed_prime = 1
        extension_length += (4 + ec_point_formats_data_length)
        extension_buf += struct.pack('!HHBBB', ec_point_formats, ec_point_formats_data_length,
                                     ec_point_formats_length, ec_point_format_uncompress,
                                     ec_point_format_anisx962_compressed_prime)

        session_ticket = 35
        session_ticket_data_length = 0
        extension_length += (4 + session_ticket_data_length)
        extension_buf += struct.pack('!HH', session_ticket, session_ticket_data_length)

        print('create extension')

        return extension_buf, extension_length


########################################################################################################################
########################################################################################################################

def gracefull_shutdown(sig, dummy):
    server.stop_server()
    sys.exit(1)


signal.signal(signal.SIGINT, gracefull_shutdown)

server = Server('', 1337)
server.start_server()

server.stop_server()
