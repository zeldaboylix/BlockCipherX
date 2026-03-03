from blockcipherx.aes import AESCipher
from blockcipherx.rsa import RSAKeyPair
from blockcipherx.hashing import hash_password, verify_password

# AES Example
aes = AESCipher()
iv, encrypted = aes.encrypt(b"Secret Message")
decrypted = aes.decrypt(iv, encrypted)

print("AES Decrypted:", decrypted)

# RSA Example
rsa = RSAKeyPair()
ciphertext = rsa.encrypt(b"Confidential Data")
plaintext = rsa.decrypt(ciphertext)

signature = rsa.sign(b"Data to sign")
verified = rsa.verify(b"Data to sign", signature)

print("RSA Verified:", verified)

# Hashing Example
salt, hashed = hash_password("StrongPassword123")
is_valid = verify_password("StrongPassword123", salt, hashed)

print("Password valid:", is_valid)
