from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

# Function to generate a random salt
def generate_salt():
    return os.urandom(16)

# Function to derive a key from a password
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt plaintext
def encrypt(plaintext, password):
    salt = generate_salt()
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Initialization vector

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    return base64.b64encode(salt + iv + ciphertext).decode()

# Function to decrypt ciphertext
def decrypt(ciphertext, password):
    decoded = base64.b64decode(ciphertext)
    salt = decoded[:16]
    iv = decoded[16:32]
    ciphertext = decoded[32:]
    print("decoded  =   {},salt  =  {},iv   =   {},ciphertext   =   {}".format(decoded,salt,iv,ciphertext))

    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()

# Example usage
if __name__ == "__main__":
    password = "mysecretpassword"
    plaintext = "Hello, AES encryption!"
    
    encrypted = encrypt(plaintext, password)
    print(f"Encrypted: {encrypted}")

    decrypted = decrypt(encrypted, password)
    print(f"Decrypted: {decrypted}")
