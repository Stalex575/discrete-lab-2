import socket
import threading
import rsa
class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
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

            # encrypt the secret with the clients public key

            client_public_key_raw = c.recv(1024).decode()

            # send the encrypted secret to a client 

            # ...

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients: 
            key = self.username_lookup[client]['public_key']
            encrypted_msg = rsa.encrypt(msg, key)
            encoded = ' '.join(map(str, encrypted_msg)).encode()

            client.send(msg.rsa.encode())

    def handle_client(self, c: socket, addr): 
        while True:
            msg = c.recv(1024)

            for client in self.clients:
                if client != c:
                    client.send(msg)

if __name__ == "__main__":
    s = Server(9001)
    s.start()
