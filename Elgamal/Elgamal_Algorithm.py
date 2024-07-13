import random
import streamlit as st
from sympy import isprime, mod_inverse, gcd
from display import display_cryptographic_result

if 'encryption_steps' not in st.session_state:
    st.session_state.encryption_steps = []
if 'decryption_steps' not in st.session_state:
    st.session_state.decryption_steps = []

def generate_large_prime(nbits):
    while True:
        # Generate a random number with the specified number of bits
        num = random.getrandbits(nbits)

        # Ensure the number is odd (since even numbers > 2 cannot be prime)
        num |= 1

        # Check for primality
        if isprime(num):
            return num


def generate_keys():
    q = generate_large_prime(256)
    g = random.randint(2, q - 1)
    x = random.randint(2, q - 1)
    y = pow(g, x, q)
    return q, g, y, x


def encrypt_block(q, g, y, block):
    k = random.randint(2, q - 1)
    st.write(" ")
    st.session_state.encryption_steps.append(f"Value of k selected is {k}")

    # Convert block to numerical value
    block_int = int.from_bytes(block, byteorder='big')

    # Compute the ciphertext components
    c1 = pow(g, k, q)
    c2 = (block_int * pow(y, k, q)) % q
    st.session_state.encryption_steps.append(f'block : {block_int}')
    st.session_state.encryption_steps.append(f'c1 for {block_int}: {c1}')
    st.session_state.encryption_steps.append(f'c2 for {block_int}: {c2}')
    st.write(" ")
    return c1, c2


def encrypt(q, g, y, plaintext):
    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode('utf-8')

    # Split plaintext into blocks
    block_size = max((q.bit_length() // 8) - 1, 1)  # Ensure block size is greater than zero
    blocks = [plaintext_bytes[i:i + block_size] for i in range(0, len(plaintext_bytes), block_size)]

    ciphertext = [encrypt_block(q, g, y, block) for block in blocks]
    return st.session_state.encryption_steps,ciphertext


def decrypt_block(x, q, c1, c2):
    # Compute the shared secret
    st.session_state.decryption_steps.append(f"For: {c1}")
    s = pow(c1, x, q)
    st.session_state.decryption_steps.append(f"Calculated value of s is: {s}")

    # Compute the modular inverse of s
    s_inv = pow(s, q - 2, q)
    st.session_state.decryption_steps.append(f"Calculated value of s inverse is: {s_inv}")

    # Recover the block numerical value
    block_int = (c2 * s_inv) % q
    st.session_state.decryption_steps.append(f"Computed value of m is {block_int}")

    # Convert numerical value back to bytes
    block_bytes = block_int.to_bytes((block_int.bit_length() + 7) // 8, byteorder='big')
    st.session_state.decryption_steps.append(f"Computed value of m in  bytes is {block_bytes}")

    return block_bytes


def decrypt(x, q, ciphertext):
    plaintext_bytes = b''.join([decrypt_block(x, q, c1, c2) for c1, c2 in ciphertext])
    plaintext = plaintext_bytes.decode('utf-8')
    return st.session_state.decryption_steps,plaintext


def sign(message, x, p, g):
    st.write(" ")
    k = random.randrange(2, p - 1)

    while gcd(k, p - 1) != 1:
        k = random.randrange(2, p - 1)
    r = pow(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    m = int.from_bytes(message.encode('utf-8'), 'big')
    s = (k_inv * (m - x * r)) % (p - 1)
    return k,k_inv,r, s


def verify(message, r, s, p, g, y):
    m = int.from_bytes(message.encode('utf-8'), 'big')
    if r < 1 or r > p - 1:
        return False
    v1 = pow(y, r, p) * pow(r, s, p) % p
    v2 = pow(g, m, p)
    return v1, v2, v1 == v2
