import hashlib
import os
import socket
import threading
import rsa
class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.session_keys = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        self.public_key, self.private_key = rsa.main()

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            # send public key to the client

            c.send(f"{self.public_key[0]},{self.public_key[1]}".encode())


            client_public_key_raw = c.recv(1024).decode()
            client_public_key = tuple(map(int, client_public_key_raw.split(',')))

            session_key = os.urandom(32)
            self.session_keys[c] = session_key

            # encrypt the secret with the clients public key
            encrypted_session_key = rsa.encrypt(session_key.decode('latin1'), client_public_key)

            # send the encrypted secret to a client
            c.send(' '.join(map(str, encrypted_session_key)).encode())

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients: 
            session_key = self.session_keys[client]

            # encrypt the message
            msg_hash = hashlib.sha3_512(msg.encode()).hexdigest()
            encrypted_msg = rsa.encrypt(msg, session_key)

            client.send(f"{msg_hash}|{' '.join(map(str, encrypted_msg))}".encode())

    def handle_client(self, c: socket, addr): 
        session_key = self.session_keys[c]

        while True:
            data = c.recv(2048).decode()
            if not data:
                break

            received_hash, encrypted_msg_raw = data.split('|')
            encrypted_msg = list(map(int, encrypted_msg_raw.split()))

            decrypted_msg = rsa.decrypt(encrypted_msg, session_key)

            calculated_hash = hashlib.sha3_512(decrypted_msg.encode()).hexdigest()
            if calculated_hash != received_hash:
                print("Message integrity check failed!")
                continue

            for client in self.clients:
                if client != c:
                    self.broadcast(decrypted_msg)

if __name__ == "__main__":
    s = Server(9001)
    s.start()
