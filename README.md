
### 0. lab 2: Pechenenko and Stadnik

### 1. RSA Encryption (`rsa.py`)
Custom RSA implementation including:
- Prime number generation
- Keypair generation (`generate_pair_of_keys`)
- Encryption (`encrypt`)
- Decryption (`decrypt`)
- Extended Euclidean algorithm for modular inverse

### 2. Secure Session Key Exchange
- When a client connects:
  - It receives the server’s **public key**
  - Sends its **own public key**
  - Receives a **randomly generated session key**, encrypted with its public key
  - Decrypts the session key using its **private key**


### 3. Message Encryption + Integrity
- Before sending, the message is:
  - Hashed with SHA3-512
  - XOR-encrypted using the session key
- On the receiver's side:
  - The message is decrypted
  - The hash is re-computed and verified

---

## Workload Distribution

| Name      | Role                               | Contribution                                              |
|-----------|------------------------------------|-----------------------------------------------------------|
| **Alex** | Server and Client logic, encryption | Implemented RSA exchange, session key setup, broadcasting |
| **Yaryna**  | RSA module                         | Wrote RSA key generation, encryption/decryption functions |


