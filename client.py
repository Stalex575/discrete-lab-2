import socket
import threading
import hashlib
import rsa

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.session_key = None

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs
        self.public_key, self.private_key = rsa.main()

        # exchange public keys
        server_public_key_raw = self.s.recv(1024).decode()
        server_public_key = tuple(map(int, server_public_key_raw.split(',')))
        self.s.send(f"{self.public_key[0]},{self.public_key[1]}".encode())

        # receive the encrypted secret key
        encrypted_session_key_raw = self.s.recv(1024).decode()
        encrypted_session_key = list(map(int, encrypted_session_key_raw.split()))

        self.session_key = rsa.decrypt(encrypted_session_key, self.private_key).encode('latin1')

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self): 
        while True:
            data = self.s.recv(2048).decode()

            received_hash, encrypted_msg = data.split('|')

            decrypted_msg = ''.join(chr(ord(c) ^ self.session_key[i % len(self.session_key)]) for i, c in enumerate(encrypted_msg))

            calculated_hash = hashlib.sha3_512(decrypted_msg.encode()).hexdigest()
            if calculated_hash != received_hash:
                print("[client]: Message integrity check failed!")
                continue

            print(f"[server]: {decrypted_msg}")

    def write_handler(self):
        while True:
            message = input()
            msg_hash = hashlib.sha3_512(message.encode()).hexdigest()
            encrypted_msg = ''.join(chr(ord(c) ^ self.session_key[i % len(self.session_key)]) for i, c in enumerate(message))
            self.s.send(f"{msg_hash}|{encrypted_msg}".encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
