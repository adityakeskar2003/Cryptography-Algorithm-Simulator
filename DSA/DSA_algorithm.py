import hashlib
import random
from sympy import isprime, mod_inverse
import streamlit as st
from display import display_cryptographic_result
# Utility functions
def generate_large_prime(nbits):
    while True:
        # Generate a random number with the specified number of bits
        num = random.getrandbits(nbits)

        # Ensure the number is odd (since even numbers > 2 cannot be prime)
        num |= 1

        # Check for primality
        if isprime(num):
            return num


def hash_message(message):
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    elif isinstance(message, bytes):
        message_bytes = message
    else:
        raise ValueError("Message must be a string or bytes")

    hasher = hashlib.sha256()
    hasher.update(message_bytes)
    return hasher.hexdigest()


# Generate DSA parameters
def generate_dsa_parameters():
    q = generate_large_prime(5)
    while True:
        p = generate_large_prime(10)
        if (p - 1) % q == 0:
            break
    h = random.randint(2, p - 2)
    g = pow(h, (p - 1) // q, p)
    return p, q, g


# Generate DSA keys
def generate_dsa_keys(p, q, g):
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    return x, y


# Sign a message
def sign_message(message, p, q, g, private_key):
    H_m_str = hash_message(message)
    H_m = int(H_m_str, 16)  # Convert the hashed message to an integer
    k = random.randint(1, q - 1)
    display_cryptographic_result(k)
    r = pow(g, k, p) % q
    k_inv = mod_inverse(k, q)
    s = (k_inv * (H_m + private_key * r)) % q

    return H_m,k,k_inv,H_m_str, r, s


# Verify a signature
def verify_signature(message, p, q, g, public_key, r, s):
    H_m = int(hash_message(message), 16)
    w = mod_inverse(s, q)
    u1 = (H_m * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(public_key, u2, p)) % p) % q

    return w,u1,u2,v



def tampered(message, original_hash):
    new_hash = hash_message(message)
    return new_hash != original_hash


def valid(v, r):
    return v == r


def tamper_message(message, tamper_rate=0.1):
    message_list = list(message)
    tampered_indices = random.sample(range(len(message)), int(len(message) * tamper_rate))

    for index in tampered_indices:
        # Choose a random character that is different from the original character
        original_char = message_list[index]
        tampered_char = chr(random.randint(32, 126))
        while tampered_char == original_char:
            tampered_char = chr(random.randint(32, 126))

        message_list[index] = tampered_char

    return ''.join(message_list)