import struct


class Parser:
    CONTENT_TYPE_OFFSET = 0
    CONTENT_TYPE_LENGTH = 1
    CONTENT_TYPE_END = CONTENT_TYPE_OFFSET + CONTENT_TYPE_LENGTH

    MIN_TLS_VERSION_OFFSET = CONTENT_TYPE_END
    MIN_TLS_VERSION_LENGTH = 2
    MIN_TLS_VERSION_END = MIN_TLS_VERSION_OFFSET + MIN_TLS_VERSION_LENGTH

    MESSAGE_LENGTH_OFFSET = MIN_TLS_VERSION_END
    MESSAGE_LENGTH_LENGTH = 2
    MESSAGE_LENGTH_END = MESSAGE_LENGTH_OFFSET + MESSAGE_LENGTH_LENGTH

    HANDSHAKE_TYPE_OFFSET = MESSAGE_LENGTH_END
    HANDSHAKE_TYPE_LENGTH = 1
    HANDSHAKE_TYPE_END = HANDSHAKE_TYPE_OFFSET + HANDSHAKE_TYPE_LENGTH

    CLIENT_HELLO_LENGTH_OFFSET = HANDSHAKE_TYPE_END
    CLIENT_HELLO_LENGTH_LENGTH = 3
    CLIENT_HELLO_LENGTH_END = CLIENT_HELLO_LENGTH_OFFSET + CLIENT_HELLO_LENGTH_LENGTH

    MAX_TLS_VERSION_OFFSET = CLIENT_HELLO_LENGTH_END
    MAX_TLS_VERSION_LENGTH = 2
    MAX_TLS_VERSION_END = MAX_TLS_VERSION_OFFSET + MAX_TLS_VERSION_LENGTH

    RANDOM_TIME_OFFSET = MAX_TLS_VERSION_END
    RANDOM_TIME_LENGTH = 4
    RANDOM_TIME_END = RANDOM_TIME_OFFSET + RANDOM_TIME_LENGTH

    RANDOM_BYTE_OFFSET = RANDOM_TIME_END
    RANDOM_BYTE_LENGTH = 28
    RANDOM_BYTE_END = RANDOM_BYTE_OFFSET + RANDOM_BYTE_LENGTH

    SESSION_ID_LENGTH_OFFSET = RANDOM_BYTE_END
    SESSION_ID_LENGTH_LENGTH = 1
    SESSION_ID_LENGTH_END = SESSION_ID_LENGTH_OFFSET + SESSION_ID_LENGTH_LENGTH

    SESSION_ID_OFFSET = SESSION_ID_LENGTH_END
    SESSION_ID_LENGTH = 0
    SESSION_ID_END = SESSION_ID_OFFSET + SESSION_ID_LENGTH

    CIPHER_SUITES_LENGTH_OFFSET = SESSION_ID_END
    CIPHER_SUITES_LENGTH_LENGTH = 2
    CIPHER_SUITES_LENGTH_END = CIPHER_SUITES_LENGTH_OFFSET + CIPHER_SUITES_LENGTH_LENGTH

    def update_offsets(self):
        self.CONTENT_TYPE_OFFSET = 0
        self.CONTENT_TYPE_END = self.CONTENT_TYPE_OFFSET + self.CONTENT_TYPE_LENGTH

        self.MIN_TLS_VERSION_OFFSET = self.CONTENT_TYPE_END
        self.MIN_TLS_VERSION_END = self.MIN_TLS_VERSION_OFFSET + self.MIN_TLS_VERSION_LENGTH

        self.MESSAGE_LENGTH_OFFSET = self.MIN_TLS_VERSION_END
        self.MESSAGE_LENGTH_END = self.MESSAGE_LENGTH_OFFSET + self.MESSAGE_LENGTH_LENGTH

        self.HANDSHAKE_TYPE_OFFSET = self.MESSAGE_LENGTH_END
        self.HANDSHAKE_TYPE_END = self.HANDSHAKE_TYPE_OFFSET + self.HANDSHAKE_TYPE_LENGTH

        self.CLIENT_HELLO_LENGTH_OFFSET = self.HANDSHAKE_TYPE_END
        self.CLIENT_HELLO_LENGTH_END = self.CLIENT_HELLO_LENGTH_OFFSET + self.CLIENT_HELLO_LENGTH_LENGTH

        self.MAX_TLS_VERSION_OFFSET = self.CLIENT_HELLO_LENGTH_END
        self.MAX_TLS_VERSION_END = self.MAX_TLS_VERSION_OFFSET + self.MAX_TLS_VERSION_LENGTH

        self.RANDOM_TIME_OFFSET = self.MAX_TLS_VERSION_END
        self.RANDOM_TIME_END = self.RANDOM_TIME_OFFSET + self.RANDOM_TIME_LENGTH

        self.RANDOM_BYTE_OFFSET = self.RANDOM_TIME_END
        self.RANDOM_BYTE_END = self.RANDOM_BYTE_OFFSET + self.RANDOM_BYTE_LENGTH

        self.SESSION_ID_LENGTH_OFFSET = self.RANDOM_BYTE_END
        self.SESSION_ID_LENGTH_END = self.SESSION_ID_LENGTH_OFFSET + self.SESSION_ID_LENGTH_LENGTH

        self.SESSION_ID_OFFSET = self.SESSION_ID_LENGTH_END
        self.SESSION_ID_END = self.SESSION_ID_OFFSET + self.SESSION_ID_LENGTH

        self.CIPHER_SUITES_LENGTH_OFFSET = self.SESSION_ID_END
        self.CIPHER_SUITES_LENGTH_END = self.CIPHER_SUITES_LENGTH_OFFSET + self.CIPHER_SUITES_LENGTH_LENGTH

    def get_content_type(self, data):
        return struct.unpack('!B', data[self.CONTENT_TYPE_OFFSET:self.CONTENT_TYPE_END])[0]

    def get_min_tls_version(self, data):
        return struct.unpack('!H', data[self.MIN_TLS_VERSION_OFFSET:self.MIN_TLS_VERSION_END])[0]

    def get_message_length(self, data):
        return struct.unpack('!H', data[self.MESSAGE_LENGTH_OFFSET:self.MESSAGE_LENGTH_END])[0]

    def get_handshake_type(self, data):
        return struct.unpack('!B', data[self.HANDSHAKE_TYPE_OFFSET:self.HANDSHAKE_TYPE_END])[0]

    def get_client_hello_length(self, data):
        return struct.unpack('!I', b'\x00' + data[self.CLIENT_HELLO_LENGTH_OFFSET:self.CLIENT_HELLO_LENGTH_END])[0]

    def get_max_tls_version(self, data):
        return struct.unpack('!H', data[self.MAX_TLS_VERSION_OFFSET:self.MAX_TLS_VERSION_END])[0]

    def get_random_time(self, data):
        return struct.unpack('!I', data[self.RANDOM_TIME_OFFSET:self.RANDOM_TIME_END])[0]

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
        if self.SESSION_ID_LENGTH != 0:
            return struct.unpack('!I', data[self.SESSION_ID_LENGTH_OFFSET:self.SESSION_ID_END])[0]
        else:
            return None

    def get_cipher_suites_length(self, data):
        return struct.unpack('!H', data[self.CIPHER_SUITES_LENGTH_OFFSET:self.CIPHER_SUITES_LENGTH_END])[0]
