import random
from sympy import isprime, mod_inverse
import streamlit as st

# Utility functions
def generate_large_prime(nbits):
    while True:
        num = random.getrandbits(nbits)
        if isprime(num):
            return num


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# Extended Euclidean algorithm to find modular inverse
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1


# Generate RSA parameters (public and private keys)
def generate_rsa_parameters(keys):
    # Choose two distinct large prime numbers p and q
    p = generate_large_prime(keys // 2)
    q = generate_large_prime(keys // 2)

    return p, q


def generate_eular_totient(p, q):
    # Compute n = p * q (modulus)
    n = p * q

    # Compute Euler's totient function φ(n)
    phi = (p - 1) * (q - 1)
    return phi,n


def generate_keys(phi):
    # Choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    # Compute d, the modular multiplicative inverse of e (private key)
    d = mod_inverse(e, phi)

    # Public key: (e, n), Private key: (d, n)
    return e, d


# RSA encryption
def encrypt_rsa(message, e, n):
    ciphertext = [pow(ord(char), e, n) for char in message]
    for char in message:
        encrypted_char = pow(ord(char), e, n)
        st.write(f"Character: {char} -> Encrypted: {encrypted_char}")
    return ciphertext


# RSA decryption
def decrypt_rsa(ciphertext, d,n):
    plaintext = []
    for char in ciphertext:
        decrypted_value = pow(int(char), d, n)
        decrypted_char = chr(decrypted_value)  # Ensure char is an integer
        st.write(f"Ciphertext: {char} -> {decrypted_value} -> Decrypted: {decrypted_char}")
        plaintext.append(decrypted_char)
    return ''.join(plaintext)




# RSA signing
def sign(message, d,n):
    signature = [pow(char, d, n) for char in message]
    return signature


# RSA signature verification
def verify(signature, e,n):
    verified_message = [pow(char, e, n) for char in signature]
    return verified_message
