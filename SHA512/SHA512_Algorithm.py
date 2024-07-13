import struct
import streamlit as st

from display import display_cryptographic_result

# Helper functions
def right_rotate(x, n):
    """Right rotate x by n bits."""
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def pad_message(message):
    # st.header("Step 1: Padding")
    # st.write(
    #     "a. Append a '1' Bit : First, a single '1' bit (0x80 in hexadecimal) is appended to the original data. This bit indicates the start of the padding.")
    # st.write(
    #     "b. Append '0' Bits : Add '0' bits until the length of the message (in bytes) is 120 bytes less than a multiple of 128. This padding ensures the total length (message + 1-bit + padding) is a multiple of 128 bytes, leaving space for the 8-byte length field.")
    # st.write(
    #     "c. Append the Length of the Original Data : Finally, the length of the original data (before padding) is appended as a 64-bit integer in big-endian format. This 64-bit value represents the number of bits in the original data.")
    #
    # """Pad the message to be a multiple of 1024 bits (128 bytes)."""
    original_length = len(message)
    append_bit = b'\x80'
    append_length = (120 - original_length % 128) % 128
    append_padding = b'\x00' * append_length
    length_bits = struct.pack(b'>Q', original_length * 8)

    return message + append_bit + append_padding + length_bits


def chunks(message, chunk_size):
    """Split the message into chunks of chunk_size bytes."""
    num_chunks = (len(message) + chunk_size - 1) // chunk_size
    padded_message = message.ljust(num_chunks * chunk_size, b'\x00')  # Ensure message is padded to full chunks
    return [padded_message[i * chunk_size:(i + 1) * chunk_size] for i in range(num_chunks)]


# Constants
K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]

# Initial hash values
H = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]


def sha512(message):
    # Initial hash values
    H = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]
    padded_message = pad_message(message)
    chunks_message = chunks(padded_message, 128)

    for chunk in chunks_message:
        words = [struct.unpack(b'>Q', chunk[i:i + 8])[0] for i in range(0, len(chunk), 8)]
        # display_cryptographic_result(words)

        for i in range(16, 80):
            # st.write(f"For i: {i} ")
            # st.write("s0 : s0 = right_rotate(words[i - 15], 1) ^ right_rotate(words[i - 15], 8) ^ (words[i - 15] >> 7)")
            s0 = right_rotate(words[i - 15], 1) ^ right_rotate(words[i - 15], 8) ^ (words[i - 15] >> 7)
            # display_cryptographic_result(s0)
            # st.write("s1 : s1 = right_rotate(words[i - 2], 19) ^ right_rotate(words[i - 2], 61) ^ (words[i - 2] >> 6)")
            s1 = right_rotate(words[i - 2], 19) ^ right_rotate(words[i - 2], 61) ^ (words[i - 2] >> 6)
            # display_cryptographic_result(s1)
            words.append((words[i - 16] + s0 + words[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF)

        # display_cryptographic_result(words)
        a, b, c, d, e, f, g, h = H
        # st.write("Initial working variables:")
        # display_cryptographic_result([a,b,c,d,e,f,g,h])

        for i in range(80):
            # st.write("s1 : s1 = right_rotate(e, 14) ^ right_rotate(e, 18) ^ right_rotate(e, 41)")
            s1 = right_rotate(e, 14) ^ right_rotate(e, 18) ^ right_rotate(e, 41)
            # display_cryptographic_result(s1)
            # st.write("ch : ch = (e & f) ^ (~e & g)")
            ch = (e & f) ^ (~e & g)
            # display_cryptographic_result(ch)
            # st.write("temp1 : h + s1 + ch + K[i] + words[i]")
            temp1 = h + s1 + ch + K[i] + words[i]
            # display_cryptographic_result(temp1)
            # st.write("s0 : s0 = right_rotate(a, 28) ^ right_rotate(a, 34) ^ right_rotate(a, 39)")
            s0 = right_rotate(a, 28) ^ right_rotate(a, 34) ^ right_rotate(a, 39)
            # display_cryptographic_result(s0)
            # st.write("maj :  maj = (a & b) ^ (a & c) ^ (b & c)")
            maj = (a & b) ^ (a & c) ^ (b & c)
            # display_cryptographic_result(maj)
            # st.write("temp 2 : temp 2 = s0 + maj ")
            temp2 = s0 + maj

            # st.write(" ")
            # st.write("Performing following operations:")
            # st.write("h = g, g = f, f = e, e = (d + temp1) & 0xFFFFFFFFFFFFFFFF,d = c,c = b, b = a,a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF")
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFFFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

            # st.write(f"Round {i}:")
            # st.write("variables:")
            # display_cryptographic_result([a,b,c,d,e,f,g,h])
            # st.write("")

        H[0] = (H[0] + a) & 0xFFFFFFFFFFFFFFFF
        H[1] = (H[1] + b) & 0xFFFFFFFFFFFFFFFF
        H[2] = (H[2] + c) & 0xFFFFFFFFFFFFFFFF
        H[3] = (H[3] + d) & 0xFFFFFFFFFFFFFFFF
        H[4] = (H[4] + e) & 0xFFFFFFFFFFFFFFFF
        H[5] = (H[5] + f) & 0xFFFFFFFFFFFFFFFF
        H[6] = (H[6] + g) & 0xFFFFFFFFFFFFFFFF
        H[7] = (H[7] + h) & 0xFFFFFFFFFFFFFFFF
        # st.write("Updated hash values:")
        # st.write("H[i] = H[i] + X[i] & 0xFFFFFFFF where X = [a,b,c,d,e,f,g,h]")
        # display_cryptographic_result(H)

    return struct.pack(b'>8Q', *H)
