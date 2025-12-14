class RC4:

    def __init__(self, key: bytes):
        if not (1 <= len(key) <= 256):
            raise ValueError("RC4 key length must be between 1 and 256 bytes")
        self.S = None
        self.key = key
        self.i = 0
        self.j = 0

    def setup_keys(self) -> None:
        self.S = list(range(256))

        j = 0
        key_len = len(self.key)
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_len]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

        self.i = 0
        self.j = 0

    def _generate_keystream(self, length: int) -> bytes:
        if self.S is None:
            raise RuntimeError("Key not initialized. Call setup_keys() first.")

        keystream = []

        for _ in range(length):
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            K = self.S[(self.S[self.i] + self.S[self.j]) % 256]
            keystream.append(K)

        return bytes(keystream)

    def crypt(self, data: bytes) -> bytes:
        if self.S is None:
            raise RuntimeError("Key not initialized. Call setup_keys() first.")

        keystream = self._generate_keystream(len(data))
        return bytes(d ^ k for d, k in zip(data, keystream))

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.crypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.crypt(ciphertext)
