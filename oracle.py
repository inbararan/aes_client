from Crypto.Cipher import AES

key = b"A 16-bytes key!!"

encrypter = AES.new(key, AES.MODE_ECB)

import socket

import base64
print(base64.b16encode(encrypter.encrypt("1234567890123456")))

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 7878  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    message = input("Write the message to server:\n")
    b = bytes(message, "utf-8")
    e = encrypter.encrypt(b)
    # print(f"Before_len: {len(b)}, after_len: {len(e)}")
    # print(f"Before: {list(b)}")
    # print(f"After: {list(e)}")
    s.sendall(e)
    data = s.recv(16)
    # print(f"encrypted response: {data}")
    print(encrypter.decrypt(data))
