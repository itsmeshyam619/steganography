from PIL import Image
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

def decode(image_path):
    # Load the image
    image = Image.open(image_path)
    binary_message = ""

    # Extract the message from the image
    for y in range(image.size[1]):
        for x in range(image.size[0]):
            pixel = image.getpixel((x, y))

            for color in range(3):  # Loop through R, G, B channels
                binary_message += str(pixel[color] & 1)

    # Convert binary to string
    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i + 8]
        if byte == '00000000':  # Stop decoding if we reach a null byte
            break
        message += chr(int(byte, 2))

    return message.rstrip('||')  # Remove the delimiter

def decrypt(ciphertext, password):
    decoded = base64.b64decode(ciphertext)
    salt = decoded[:16]
    iv = decoded[16:32]
    ciphertext = decoded[32:]
    #print("decoded  =   {},salt  =  {},iv   =   {},ciphertext   =   {}".format(decoded,salt,iv,ciphertext))

    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def get_file_path():
    while True:
        file_path = input("\n\nPlease enter the path to the file: ")
        
        # Check if the file exists
        if os.path.isfile(file_path):
            print("\n\n\t\t\tFile found!")
            return file_path
        else:
            print("\n\nFile not found. Please try again.")




if __name__ == "__main__":


    password = str(input("\n\nEnter password:"))

    file_path=get_file_path()
    decoded_message = decode(file_path)
    print("\n\nDecoded lsb message:",decoded_message)

    
    lsb_extraction=''

    print("\n \t ***********DECRYTION*********** \n\nDecoded message:",end=' ')
    for i in decoded_message:
        
        print(i,end='')
        if(i == "|"):
            break
        lsb_extraction+=i
    print("\n\nEncrypted message extraction : {}\n\n ".format(lsb_extraction))

    decrypted = decrypt(lsb_extraction,password)
    print(f"\n\n\tDecrypted: {decrypted}\n\n")
