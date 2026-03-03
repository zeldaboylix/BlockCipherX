from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class RSAKeyPair:
    def __init__(self, key_size: int = 2048):
        # Generate RSA private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, message: bytes) -> bytes:
        # Encrypt message using public key
        return self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Decrypt message using private key
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def sign(self, message: bytes) -> bytes:
        # Sign message using private key
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        # Verify signature using public key
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
