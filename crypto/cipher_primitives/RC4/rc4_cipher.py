class RC4:

    def __init__(self):
        self.S = None
        self.key = None

    def setup_keys(self, key: bytes) -> None:

        if not (1 <= len(key) <= 256):
            raise ValueError("RC4 key length must be between 1 and 256 bytes")

        self.key = key
        self.S = list(range(256))

        j = 0
        key_len = len(key)
        for i in range(256):
            j = (j + self.S[i] + key[i % key_len]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def _generate_keystream(self, length: int) -> bytes:
        if self.S is None:
            raise RuntimeError("Key not initialized. Call setup_keys() first.")

        S = self.S.copy()
        i = 0
        j = 0
        keystream = []

        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
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
