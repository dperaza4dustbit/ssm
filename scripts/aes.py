#!/usr/bin/env python

import base64
import sys
from Crypto import Random
from Crypto.Cipher import AES


def encrypt(base64_key, text):

    key = base64.b64decode(base64_key)
    iv = Random.new().read(AES.block_size)

    cipher = AES.new(key, AES.MODE_CFB, iv)

    cipher_bytes = iv + cipher.encrypt(text)

    base64_cipher = base64.b64encode(cipher_bytes)
    return base64_cipher


def decrypt(base64_key, text):
    key = base64.b64decode(base64_key)
    cipher_bytes = base64.b64decode(text)
    iv = cipher_bytes[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    final_msg= cipher.decrypt(cipher_bytes[AES.block_size:])
    return final_msg


if __name__ == "__main__":

    msg_in = sys.argv[1]
    key = sys.argv[2]
    action = sys.argv[3]

    if action == "encrypt":
        ciphertext = encrypt(key, msg_in)
        print(ciphertext)

    elif action == "decrypt":
        plaintext = decrypt(key, msg_in)
        print(plaintext)