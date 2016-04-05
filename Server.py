import logging
import signal
import socket
import struct
import sys


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

            self.dissect_message(data)

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

    def dissect_message(self, data):
        Server.logger.debug('Try to dissect raw packet: %s' % data)

        unpackedHeader = struct.unpack('!BHHB', data[:6])
        '''Messagelength ist 3Byte, Python braucht fuer unpack aber 4Byte
           daher hier 3Byte aus data + 1Byte extra padding am anfang
        '''

        if unpackedHeader[0] == self.TLS_HANDSHAKE:
            self.dissect_handshake_msg(unpackedHeader, data)

    """ DISSECT HANDSAKE HERE """

    def dissect_handshake_msg(self, unpackedHeader, data):
        Server.logger.debug('Try to dissect handshake')

        if unpackedHeader[3] == self.TYPE_CLIENT_HELLO:
            self.dissect_client_hello(unpackedHeader, data)

    """ DISSECT CLIENT_HELLO HERE """

    def dissect_client_hello(self, unpackedHeader, data):
        Server.logger.debug('Try to dissect client_hello')

        paddingByte = b'\x00'
        unpackedMessageLength = struct.unpack('!I', paddingByte + data[6:9])
        unpackedMessage = struct.unpack('!HI' + 'B' * 28 + 'BH', data[9:46])

        # concat randomBytes aus der Message
        randomBytes = bytearray()
        for i in range(2, 30):
            randomBytes.append(unpackedMessage[i])

        ciphersuitesLength = int(unpackedMessage[31])
        # get ciphersuites
        unpackedCiphers = struct.unpack('!' + 'H' * int(ciphersuitesLength / 2), data[46:46 + ciphersuitesLength])
        availableCipers = []
        for cipher in unpackedCiphers:
            availableCipers.append(hex(cipher))

        # get compressionLength

        myHello = {
            'contentType': hex(unpackedHeader[0]),
            'tlsVersion': hex(unpackedHeader[1]),
            'length': unpackedHeader[2],
            'handshakeType': unpackedHeader[3],
            'messageLength': unpackedMessageLength[0],
            'messageVersion': hex(unpackedMessage[0]),
            'randomTimestamp': unpackedMessage[1],
            'randomBytes': str(randomBytes),
            'SessionIDLength': unpackedMessage[30],
            'CiphersuitesLength': ciphersuitesLength,
            'Ciphersuites': availableCipers
        }

        Server.logger.debug('dissected ClientHello: %s' % myHello)


########################################################################################################################
########################################################################################################################

def gracefull_shutdown(sig, dummy):
    server.stop_server()
    sys.exit(1)


signal.signal(signal.SIGINT, gracefull_shutdown)

server = Server('', 1337)
server.start_server()

server.stop_server()
