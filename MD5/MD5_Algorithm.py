import struct
import math
import streamlit as st
from display import display_cryptographic_result
# Helper functions
def left_rotate(x, c):
    return ((x << c) & 0xFFFFFFFF) | (x >> (32 - c))

def F(X, Y, Z):
    return (X & Y) | (~X & Z)

def G(X, Y, Z):
    return (X & Z) | (Y & ~Z)

def H(X, Y, Z):
    return X ^ Y ^ Z

def I(X, Y, Z):
    return Y ^ (X | ~Z)

# Constants
T = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]
s = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4

# Initial hash values
A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

def md5(data):
    global A, B, C, D  # Declare A, B, C, D as global

    # Reset initial hash values
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    st.write("In the MD5 hashing algorithm, 'A', 'B', 'C', 'D' are the four state variables (or registers) that are used to maintain intermediate values during the hashing process.")
    st.write("These variables are initialized to specific values at the beginning of the hash computation and are updated through a series of transformations as the algorithm processes the input data.")
    st.write("A")
    display_cryptographic_result(A)
    st.write("B")
    display_cryptographic_result(B)
    st.write("C")
    display_cryptographic_result(C)
    st.write("D")
    display_cryptographic_result(D)

    st.header("Step 1: Padding")
    st.write("a. Append a '1' Bit : First, a single '1' bit (0x80 in hexadecimal) is appended to the original data. This bit indicates the start of the padding.")
    st.write("b. Append '0' Bits : Next, '0' bits are appended to the data until the total length in bits is 64 bits less than a multiple of 512. In other words, the length of the padded data should be congruent to 448 modulo 512. This ensures that there is exactly enough space to append the length of the original message in the final step.")
    st.write("c. Append the Length of the Original Data : Finally, the length of the original data (before padding) is appended as a 64-bit integer in little-endian format. This 64-bit value represents the number of bits in the original data.")
    # Ensure data is in bytes
    if isinstance(data, str):
        data = data.encode()

    # Pre-processing: padding
    original_len_in_bits = len(data) * 8
    data += b'\x80'
    while len(data) % 64 != 56:
        data += b'\x00'
    data += struct.pack('<Q', original_len_in_bits)
    st.write("Padded plaintext")
    display_cryptographic_result(data)

    # Process each 512-bit chunk
    st.write("We process each 512 bit chunk")
    chunks = [data[i:i + 64] for i in range(0, len(data), 64)]
    for chunk in chunks:
        display_cryptographic_result(chunk)
        st.write("At the beginning of processing each 512-bit chunk, the current values of 'A','B','C','D' into 'a','b','c','d'")
        a, b, c, d = A, B, C, D
        X = struct.unpack('<16I', chunk)
        st.write("Round 1 Transformations: 1 to 16 times")
        st.write("a = (b + left_rotate((a + F(b, c, d) + X[idx] + T[g]) & 0xFFFFFFFF, s[g])) & 0xFFFFFFFF")
        st.write("a, b, c, d = d, a, b, c")
        # Round 1
        for i in range(16):
            g = i
            idx = i
            a = (b + left_rotate((a + F(b, c, d) + X[idx] + T[g]) & 0xFFFFFFFF, s[g])) & 0xFFFFFFFF
            a, b, c, d = d, a, b, c

        st.write("a: ")
        display_cryptographic_result(a)
        st.write("b: ")
        display_cryptographic_result(b)
        st.write("c: ")
        display_cryptographic_result(c)
        st.write("d: ")
        display_cryptographic_result(d)
        st.write(" ")

        # Round 2
        st.write("Round 2 Transformations: 1 to 16 times")
        st.write("g = (5 * i + 1) % 16")
        st.write("idx = (1 * i + 1) % 16")
        st.write("a = (b + left_rotate((a + G(b, c, d) + X[idx] + T[g]) & 0xFFFFFFFF, s[g])) & 0xFFFFFFFF")
        st.write("a, b, c, d = d, a, b, c")
        for i in range(16):
            g = (5 * i + 1) % 16
            idx = (1 * i + 1) % 16
            a = (b + left_rotate((a + G(b, c, d) + X[idx] + T[g]) & 0xFFFFFFFF, s[g])) & 0xFFFFFFFF
            a, b, c, d = d, a, b, c

        st.write("a: ")
        display_cryptographic_result(a)
        st.write("b: ")
        display_cryptographic_result(b)
        st.write("c: ")
        display_cryptographic_result(c)
        st.write("d: ")
        display_cryptographic_result(d)
        st.write(" ")

        # Round 3
        st.write("Round 3 Transformations: 1 to 16 times")
        st.write(" g = (3 * i + 5) % 16")
        st.write("idx = (2 * i + 5) % 16")
        st.write("a = (b + left_rotate((a + H(b, c, d) + X[idx] + T[g]) & 0xFFFFFFFF, s[g])) & 0xFFFFFFFF")
        st.write("a, b, c, d = d, a, b, c")
        for i in range(16):
            g = (3 * i + 5) % 16
            idx = (2 * i + 5) % 16
            a = (b + left_rotate((a + H(b, c, d) + X[idx] + T[g]) & 0xFFFFFFFF, s[g])) & 0xFFFFFFFF
            a, b, c, d = d, a, b, c

        st.write("a: ")
        display_cryptographic_result(a)
        st.write("b: ")
        display_cryptographic_result(b)
        st.write("c: ")
        display_cryptographic_result(c)
        st.write("d: ")
        display_cryptographic_result(d)
        st.write(" ")

        # Round 4
        st.write("Round 4 Transformations: 1 to 16 times")
        st.write("g = (7 * i) % 16")
        st.write("idx = (3 * i) % 16")
        st.write(" a = (b + left_rotate((a + I(b, c, d) + X[idx] + T[g]) & 0xFFFFFFFF, s[g])) & 0xFFFFFFFF")
        st.write("a, b, c, d = d, a, b, c")
        for i in range(16):
            g = (7 * i) % 16
            idx = (3 * i) % 16
            a = (b + left_rotate((a + I(b, c, d) + X[idx] + T[g]) & 0xFFFFFFFF, s[g])) & 0xFFFFFFFF
            a, b, c, d = d, a, b, c

        st.write("a: ")
        display_cryptographic_result(a)
        st.write("b: ")
        display_cryptographic_result(b)
        st.write("c: ")
        display_cryptographic_result(c)
        st.write("d: ")
        display_cryptographic_result(d)
        st.write(" ")

        # Update hash values
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF
        st.write("Updating A,B,C and D")
        st.write("A")
        display_cryptographic_result(A)
        st.write("B")
        display_cryptographic_result(B)
        st.write("C")
        display_cryptographic_result(C)
        st.write("D")
        display_cryptographic_result(D)
    # Final hash
    st.write("Final Concatenation")
    hash_value = struct.pack('<4I', A, B, C, D)
    return hash_value.hex()

