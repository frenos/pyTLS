import struct


class Parser:
    HEADER_OFFSET = 0
    HEADER_LENGTH = 5

    def get_random_bytes(self, data):
        unpacked_random_bytes = struct.unpack('!' + (self.RANDOM_BYTE_LENGTH * 'B'),
                                              data[self.RANDOM_BYTE_OFFSET:self.RANDOM_BYTE_END])
        random_bytes = bytearray()
        for i in range(0, 28):
            random_bytes.append(unpacked_random_bytes[i])
        return random_bytes

    def get_session_id_length(self, data):
        unpacked_session_id_length = struct.unpack('!B', data[self.SESSION_ID_LENGTH_OFFSET:self.SESSION_ID_LENGTH_END])
        self.SESSION_ID_LENGTH = unpacked_session_id_length[0]
        self.update_offsets()
        return self.SESSION_ID_LENGTH

    def get_session_id(self, data):
        if self.SESSION_ID_LENGTH == 0:
            return None
        else:
            return struct.unpack('!I', data[self.SESSION_ID_LENGTH_OFFSET:self.SESSION_ID_END])[0]

    def get_cipher_suites_length(self, data):
        cipher_suites_length = struct.unpack('!H',
                                             data[self.CIPHER_SUITES_LENGTH_OFFSET:self.CIPHER_SUITES_LENGTH_END])[0]

        if (cipher_suites_length % 2) != 0:
            cipher_suites_length = 0

        self.CIPHER_SUITES_LENGTH = cipher_suites_length
        self.update_offsets()

        return cipher_suites_length

    def get_availble_ciphers(self, data):

        available_ciphers = []

        print(str(self.CIPHER_SUITES_LENGTH) + ' AND ' + str(self.CIPHER_SUITES_OFFSET) + ' END ' + str(
            self.CIPHER_SUITES_END))

        if self.CIPHER_SUITES_LENGTH != 0:
            unpacked_ciphers = struct.unpack('!' + 'H' * int(self.CIPHER_SUITES_LENGTH / 2),
                                             data[self.CIPHER_SUITES_OFFSET:self.CIPHER_SUITES_END])
            for cipher in unpacked_ciphers:
                available_ciphers.append(hex(cipher))

        return available_ciphers

    def get_parsed_record_layer_header(self, data):
        unpacked_header = struct.unpack('!BHH', data[self.HEADER_OFFSET:self.HEADER_LENGTH])
        header = {
            'content_type': unpacked_header[0],
            'min_tls_version': unpacked_header[1],
            'message_length': unpacked_header[2]
        }

        return header

    def get_ssl_data(self, data):
        offset = {
            'handshake_type': 5,
            'data_length': 6,
            'max_tls_version': 9,
            'time': 11,
            'random_bytes': 15,
            'session_id_length': 43
        }

        length = {
            'handshake_type': 1,
            'data_length': 3,
            'max_tls_version': 2,
            'time': 4,
            'random_bytes': 28,
            'session_id_length': 1,
            'cipher_suites_length': 2,
            'compression_method_length': 1,
            'extensions_length': 2
        }

        ssl_data = {}
        handshake_type = \
            struct.unpack('!B', data[offset['handshake_type']:offset['handshake_type'] + length['handshake_type']])[0]
        ssl_data['handshake_type'] = handshake_type

        data_length = \
            struct.unpack('!I', b'\x00' + data[offset['data_length']:offset['data_length'] + length['data_length']])[0]
        ssl_data['data_length'] = data_length

        max_tls_version = \
            struct.unpack('!H', data[offset['max_tls_version']:offset['max_tls_version'] + length['max_tls_version']])[
                0]
        ssl_data['max_tls_version'] = max_tls_version

        time = struct.unpack('!I', data[offset['time']:offset['time'] + length['time']])[0]
        ssl_data['time'] = time

        random_bytes = struct.unpack('!' + (length['random_bytes'] * 'B'),
                                     data[offset['random_bytes']:offset['random_bytes'] + length['random_bytes']])[0]
        ssl_data['random_bytes'] = random_bytes

        length['session_id'] = struct.unpack('!B',
                                             data[offset['session_id_length']:offset['session_id_length'] + length[
                                                 'session_id_length']])[0]
        ssl_data['session_id_length'] = length['session_id']

        if (length['session_id'] < 0) or (length['session_id'] > 255):
            raise Exception('session_id_length = %i' % int(length['session_id']))

        offset['session_id'] = offset['session_id_length'] + length['session_id_length']

        if length['session_id'] != 0:
            session_id = \
                struct.unpack('!' + (length['session_id'] * 'B'),
                              data[offset['session_id']:offset['session_id'] + length['session_id']])[0]
            ssl_data['session_id'] = session_id

        print('ssl_data: ' + str(ssl_data))

        offset['cipher_suites_length'] = offset['session_id'] + length['session_id']
        length['cipher_suites'] = \
            struct.unpack('!H', data[offset['cipher_suites_length']:offset['cipher_suites_length'] + length[
                'cipher_suites_length']])[0]
        ssl_data['cipher_suites_length'] = length['cipher_suites']

        if length['cipher_suites'] < 3:
            raise Exception('only one cipher_suite')

        if (length['cipher_suites'] % 2) != 0:
            raise Exception('cipher_suites_length mod 2 != 0')

        offset['cipher_suites'] = offset['cipher_suites_length'] + length['cipher_suites_length']

        # TODO AUSLAGERN

        available_ciphers = []
        unpacked_ciphers = struct.unpack('!' + 'H' * int(length['cipher_suites'] / 2),
                                         data[
                                         offset['cipher_suites']:offset['cipher_suites'] + length['cipher_suites']])

        for cipher in unpacked_ciphers:
            available_ciphers.append(hex(cipher))

        ssl_data['available_ciphers'] = available_ciphers

        # TODO BIS HIER

        offset['compression_method_length'] = offset['cipher_suites'] + length['cipher_suites']
        length['compression_method'] = \
            struct.unpack('!B', data[offset['compression_method_length']:offset['compression_method_length'] +
                                                                         length['compression_method_length']])[0]
        ssl_data['compression_method_length'] = length['compression_method_length']

        offset['compression_method'] = offset['compression_method_length'] + length['compression_method_length']
        compression_method = struct.unpack('!B', data[offset['compression_method']:offset['compression_method'] +
                                                                                   length['compression_method']])[0]
        ssl_data['compression_method'] = compression_method

        offset['extensions_length'] = offset['compression_method'] + length['compression_method']
        length['extensions'] = struct.unpack('!H', data[offset['extensions_length']:offset['extensions_length'] +
                                                                                    length['extensions_length']])[0]

        ssl_data['extensions_length'] = length['extensions']

        # TODO AUSLAGERN 2 Byte type; 2 Byte length; length Byte Extensiondata

        return ssl_data
