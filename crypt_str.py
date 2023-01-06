# encrypt: python crypt_str.py encrypt "aaaaaaaaaaaaaaaa" "Hi my name is"
# this will result with: b'6BWEwHkXSJ4qk5HVD1oq5g=='
# decrypt: python crypt_str.py decrypt "aaaaaaaaaaaaaaaa" "6BWEwHkXSJ4qk5HVD1oq5g=="

import argparse
import base64
from Crypto.Cipher import AES

def encrypt(key, plaintext):
    # Pad the plaintext so that it is a multiple of 16 bytes
    padding = b' ' * (AES.block_size - len(plaintext) % AES.block_size)
    plaintext += padding

    # Create a cipher to encrypt the plaintext
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the plaintext and encode it in base64
    ciphertext = base64.b64encode(cipher.encrypt(plaintext))

    return ciphertext

def decrypt(key, ciphertext):
    # Decode the ciphertext from base64
    ciphertext = base64.b64decode(ciphertext)

    # Create a cipher to decrypt the ciphertext
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the ciphertext and remove the padding
    plaintext = cipher.decrypt(ciphertext).rstrip(b' ')

    return plaintext

if __name__ == '__main__':
    # Parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['encrypt', 'decrypt'])
    parser.add_argument('key', type=str)
    parser.add_argument('input', type=str)
    args = parser.parse_args()

    # Convert the key and input strings to bytes
    key = args.key.encode()
    input_str = args.input.encode()

    if args.action == 'encrypt':
        output = encrypt(key, input_str)
    elif args.action == 'decrypt':
        output = decrypt(key, input_str)

    print(output)
