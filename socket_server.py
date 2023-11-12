import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

def server():
    host = socket.gethostname()
    port = 6969

    
    ##Gather RSA Keys from local files.
    ##Server Private Key and Client Public Key
    with open("server.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

        
    with open("client_public.pem", "rb") as f:
        client_publickey = RSA.import_key(f.read())

    
    ##Gather CLIENT PRIVATE KEY to prove message cant be decrypt
    ##with any private key
    with open("client.pem", "rb") as f:
        client_privatekey = RSA.import_key(f.read())


    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen(1)
    conn, address = server_socket.accept()
    print("Connection from: " + str(address))

    while True:
        ##Recieve the first 256 bytes for the signature
        ##The rest of the message is the encryption
        signature = conn.recv(256)
        if not signature:
            break

        encryption = conn.recv(1024)
        if not encryption:
            break
        
        print("Client Signature :" + str(signature))
        print("Client Encryption : " + str(encryption))


        ##Create a cipher with SERVER PRIVATE KEY
        ##Decrypt the encrypted message with the cipher
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(encryption)

        print("\n Message : " + str(plaintext))

    

        ##Hash the decrypted message
        ##Use the CLIENT PUBLIC KEY to see if the Hash matches the signature
        digest = SHA256.new(plaintext)
        if PKCS1_v1_5.new(client_publickey).verify(digest, signature):
            data = "Signature Verified"
        else:
            data = "Mismatched Signature"

        
        conn.send(data.encode())

    conn.close()


if __name__ == '__main__':
    server()