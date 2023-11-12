import socket
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
import os


def client():
    host = socket.gethostname()
    port = 6969

    ##Gather RSA keys for local files 
    with open("client.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    
    with open("server_public.pem", "rb") as f:
        server_publickey = RSA.import_key(f.read())
    


    client_socket = socket.socket()
    client_socket.connect((host, port))


    message = input("->")


    while message.lower().strip() != 'byte':
        

        ##Hash the original message using SHA256
        ##Sign the Hash with CLIENT PRIVATE KEY to ensure Client signed it
        hash_value = SHA256.new(message.encode())
        signature = PKCS1_v1_5.new(private_key).sign(hash_value)
        print("\nMessage Signature: \n")
        print(signature)


        ##Encrypt the original message using the SERVER PUBLIC KEY
        ##This allows only the server to be able to decrypt
        cipher = PKCS1_OAEP.new(server_publickey)
        ciphertext = cipher.encrypt(message.encode())
        print("\nMessage Encryption: \n")
        print(ciphertext)
        

        ##Send the message signature and encryption to the server
        client_socket.send(signature)
        client_socket.send(ciphertext)


        data = client_socket.recv(1024).decode()
        print('\nRecieved from server: ' + data)

        message = input("->")

    client_socket.close()

if __name__ == '__main__':
    client()