import random
from math import gcd

def is_prime(n):
    """prime checker"""
    if n <= 1:
        return False
    for i in range(2, int(n ** 0.5)+1):
        if n % i == 0:
            return False
    return True

def euclid(a, b):
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = euclid(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y
    
def mod_inverse(e, phi):
    return euclid(e, phi)[1] % phi


def generate_pair_of_keys(p, q):
    """finding rair of keys"""
    n = p * q
    phi = (p-1)*(q-1)

    e = 65539
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = pow(e, -1, phi)
    return ((e, n), (d, n))

def encrypt(message, public_key):
    """encoding message"""
    e, n = public_key
    return [pow(ord(char), e, n) for char in message]

def decrypt(code, private_key):
    """decoding massage"""
    d, n = private_key
    return ''.join([chr(pow(char, d, n)) for char in code])

def main():
    length = 50
    half_bit_length = length // 2
    while True:
        p = random.randint(2**(half_bit_length-1), 2**half_bit_length-1)
        if is_prime(p):
            break
    while True:
        q = random.randint(2**(half_bit_length-1), 2**half_bit_length-1)
        if is_prime(q) and p != q:
            break

    return(generate_pair_of_keys(p, q))
    

