import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import time
import sys
import socket
import json
import binascii

def pad(message):
    n = AES.block_size - len(message) % AES.block_size
    if n == 0:
        n = AES.block_size
    for _ in range(n):
        message = message + n.to_bytes(1, byteorder='big')
    return message

def unpad(message):
    n = message[-1]
    if n < 1 or n > AES.block_size or message[-n:] != bytes([n]*n):
        raise Exception('invalid_padding')
    return message[:-n]

def encrypt(message, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message)
    return iv + cipher.encrypt(padded_message)

def decrypt(ciphertext, key):
    if len(ciphertext) % AES.block_size:
        raise Exception('invalid_length')
    if len(ciphertext) < 2 * AES.block_size:
        raise Exception('invalid_iv')
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[AES.block_size:]))

def hmac(message, mac_key):
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(message)
    return h.digest()

def verify(message, mac, mac_key):
    if mac != hmac(message, mac_key):
        # exaggerate time difference between checking padding and verifying mac
        time.sleep(0.02)
        raise Exception('invalid_mac')

def macThenEncrypt(message, key, mac_key):
    return encrypt(message + hmac(message, mac_key), key)

def decryptThenVerify(ciphertext, key, mac_key):
    plaintext = decrypt(ciphertext, key)
    message, mac = plaintext[:-SHA256.digest_size], plaintext[-SHA256.digest_size:]
    verify(message, mac, mac_key)
    return message

def main():
    enc_password = "mypwdiscool"
    enc_key = hashlib.sha256(enc_password.encode('utf-8')).digest()
    mac_password = "newmacpwdlol"
    mac_key = hashlib.sha256(mac_password.encode('utf-8')).digest()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("localhost", 8000))
    sock.listen(5)
    sock.settimeout(5)
    shutdown = False
    while not shutdown:
        while True:
            try:
                client_sock, address = sock.accept()
                break
            except socket.timeout:
                continue
        message_chunks = []
        while True:
            try:
                data = client_sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                break
            message_chunks.append(data)
        client_sock.close()
        message_bytes = b''.join(message_chunks)
        message_str = message_bytes.decode("utf-8")
        message_dict = json.loads(message_str)
        # shutdown case
        if "status" in message_dict.keys():
            print("oracle shutting down")
            shutdown = True
            continue
        ciphertext_hex = message_dict["ciphertext"]
        ciphertext = bytes.fromhex(ciphertext_hex)
        try:
            decryptThenVerify(ciphertext, enc_key, mac_key)
        except:
            response_msg = {
                "status": "error"
            }
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_sock.connect(("localhost", 8001))
            temp_sock.sendall(json.dumps(response_msg).encode('utf-8'))
            temp_sock.close()
            continue
        response_msg = {
            "status": "valid"
        }
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.connect(("localhost", 8001))
        temp_sock.sendall(json.dumps(response_msg).encode('utf-8'))
        temp_sock.close()
    sock.close()

if __name__ == '__main__':
    main()