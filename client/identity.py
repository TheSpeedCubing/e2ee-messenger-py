from nacl.signing import SigningKey
from nacl.public import PrivateKey

class Identity:
    def __init__(self):
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

        self.dh_private = PrivateKey.generate()
        self.dh_public = self.dh_private.public_key

    def sign(self, data: bytes) -> bytes:
        return self.signing_key.sign(data).signature
