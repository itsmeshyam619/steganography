from PIL import Image
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

#image stegnography functions
def encode(image_path, secret_message, output_image_path):
    # Load the image
    image = Image.open(image_path)
    encoded_image = image.copy()
    
    # Convert the secret message to binary
    secret_message += '||'  # Delimiter to signify the end of the message
    binary_message = ''.join(format(ord(char), '08b') for char in secret_message)

    # Check if the image is large enough to hold the message
    if len(binary_message) > image.size[0] * image.size[1]:
        raise ValueError("The message is too long to be encoded in this image.")

    data_index = 0

    # Encode the message into the image
    for y in range(image.size[1]):
        for x in range(image.size[0]):
            pixel = list(encoded_image.getpixel((x, y)))

            for color in range(3):  # Loop through R, G, B channels
                if data_index < len(binary_message):
                    # Replace the least significant bit with the message bit
                    pixel[color] = (pixel[color] & ~1) | int(binary_message[data_index])
                    data_index += 1

            encoded_image.putpixel((x, y), tuple(pixel))
            if data_index >= len(binary_message):
                break
        if data_index >= len(binary_message):
            break

    # Save the encoded image
    encoded_image.save(output_image_path)
    print("Message encoded successfully!")













if __name__ == "__main__":

#encryption state    
    plaintext = input("Enter your secret message : ")
    password = "mysecretpassword"
    #plaintext = "Hello, AES encryption!"
    
    encrypted = encrypt(plaintext, password)
    print(f"\n Encrypted : {encrypted}")

    print("\n current file selected is \n \tC:/Users/naga/Pictures/Screenshot 2024-08-13 220101.png")

    encode("C:/Users/naga/Pictures/Screenshot 2024-08-13 220101.png", encrypted, "output_image.png")